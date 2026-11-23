pub mod http_upstream;
pub mod stdio_upstream;

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Path, Request, State},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use http::StatusCode;
use serde_json::Value;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::auth::{self, AuthStrategy};
use crate::config::{AuthConfig, AuthMethod, ExtraHeader, TransportType};
use crate::credential::CredentialProvider;
use crate::settings::{McpServerConfig, McpServerStore, Profile, ProfileStore};
use crate::storage::TokenStorage;
use crate::tool_cache::ToolCache;

/// Shared state for a single upstream.
pub struct UpstreamState {
    pub name: String,
    pub transport: TransportType,
    pub auth: Arc<dyn AuthStrategy>,
    pub http: Option<http_upstream::HttpUpstream>,
    pub stdio: Option<stdio_upstream::StdioUpstream>,
    /// Whether this upstream was loaded from the config file (not editable via UI).
    pub from_config: bool,
    /// Auth header name for display purposes.
    pub auth_header: String,
    /// Auth prefix for display purposes.
    pub auth_prefix: Option<String>,
    /// Additional headers configured for this upstream.
    pub extra_headers: Vec<ExtraHeader>,
    /// Credential reference for display purposes.
    pub credential_ref: Option<String>,
    /// Whether MCP request and response payloads should be logged.
    pub log_mcp_traffic: bool,
}

/// Shared application state.
pub struct AppState {
    pub upstreams: RwLock<HashMap<String, Arc<UpstreamState>>>,
    pub tool_cache: ToolCache,
    pub profile_store: ProfileStore,
    pub mcp_server_store: McpServerStore,
    pub credential_provider: Arc<dyn CredentialProvider>,
    pub token_storage: Arc<dyn TokenStorage>,
}

/// Build the axum router with path-prefix routing, settings API, and profile support.
pub fn build_router(
    upstreams: Vec<Arc<UpstreamState>>,
    tool_cache: ToolCache,
    profile_store: ProfileStore,
    mcp_server_store: McpServerStore,
    credential_provider: Arc<dyn CredentialProvider>,
    token_storage: Arc<dyn TokenStorage>,
) -> Router {
    let upstream_map: HashMap<String, Arc<UpstreamState>> =
        upstreams.into_iter().map(|u| (u.name.clone(), u)).collect();

    let state = Arc::new(AppState {
        upstreams: RwLock::new(upstream_map),
        tool_cache,
        profile_store,
        mcp_server_store,
        credential_provider,
        token_storage,
    });

    Router::new()
        // Web UI
        .route("/settings", get(settings_ui))
        // Settings API — upstreams list
        .route("/settings/upstreams", get(list_upstreams))
        // Settings API — tools cache
        .route("/settings/tools", get(list_cached_tools))
        .route(
            "/settings/tools/{upstream}/refresh",
            post(refresh_upstream_tools),
        )
        // Settings API — profiles
        .route(
            "/settings/profiles",
            get(list_profiles).post(create_profile),
        )
        .route(
            "/settings/profiles/{name}",
            get(get_profile).put(update_profile).delete(delete_profile),
        )
        // Settings API — MCP servers
        .route("/settings/servers", get(list_servers).post(create_server))
        .route(
            "/settings/servers/{name}",
            get(get_server).put(update_server).delete(delete_server),
        )
        // Everything else goes through the main router
        .fallback(root_handler)
        .with_state(state)
}

// ── Web UI ─────────────────────────────────────────────────────────

async fn settings_ui() -> impl IntoResponse {
    Html(include_str!("../web/settings.html"))
}

// ── Settings API: upstreams ────────────────────────────────────────

async fn list_upstreams(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let names: Vec<String> = state.upstreams.read().await.keys().cloned().collect();
    Json(names)
}

// ── Settings API: tools cache ──────────────────────────────────────

async fn list_cached_tools(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.tool_cache.get_all().await)
}

async fn refresh_upstream_tools(
    State(state): State<Arc<AppState>>,
    Path(upstream_name): Path<String>,
) -> impl IntoResponse {
    let upstream = match state.upstreams.read().await.get(&upstream_name) {
        Some(u) => u.clone(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                format!("upstream '{}' not found", upstream_name),
            )
                .into_response()
        }
    };

    match state.tool_cache.refresh_upstream(&upstream).await {
        Ok(()) => {
            let tools = state
                .tool_cache
                .get_tools(&upstream_name)
                .await
                .unwrap_or_default();
            Json(serde_json::json!({ "upstream": upstream_name, "tools": tools })).into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            format!("failed to fetch tools: {}", e),
        )
            .into_response(),
    }
}

// ── Settings API: profiles ─────────────────────────────────────────

async fn list_profiles(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.profile_store.list().await)
}

async fn get_profile(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    match state.profile_store.get(&name).await {
        Some(profile) => Json(profile).into_response(),
        None => (StatusCode::NOT_FOUND, "profile not found").into_response(),
    }
}

async fn create_profile(
    State(state): State<Arc<AppState>>,
    Json(profile): Json<Profile>,
) -> impl IntoResponse {
    if let Err(err_resp) = validate_route_name(&profile.name, "profile name") {
        return err_resp.into_response();
    }
    if state.upstreams.read().await.contains_key(&profile.name) {
        return (
            StatusCode::CONFLICT,
            "profile name conflicts with an upstream name",
        )
            .into_response();
    }

    if let Err(e) = state.profile_store.upsert(profile.clone()).await {
        error!(profile = %profile.name, error = %e, "failed to persist profile");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist profile",
        )
            .into_response();
    }
    info!(profile = %profile.name, "created profile");
    (StatusCode::CREATED, Json(profile)).into_response()
}

async fn update_profile(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(mut profile): Json<Profile>,
) -> impl IntoResponse {
    if let Err(err_resp) = validate_route_name(&name, "profile name") {
        return err_resp.into_response();
    }
    if state.upstreams.read().await.contains_key(&name) {
        return (
            StatusCode::CONFLICT,
            "profile name conflicts with an upstream name",
        )
            .into_response();
    }
    profile.name = name;
    if let Err(e) = state.profile_store.upsert(profile.clone()).await {
        error!(profile = %profile.name, error = %e, "failed to persist profile");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist profile",
        )
            .into_response();
    }
    Json(profile).into_response()
}

async fn delete_profile(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    match state.profile_store.delete(&name).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "profile not found").into_response(),
        Err(e) => {
            error!(profile = %name, error = %e, "failed to delete persisted profile");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to delete profile",
            )
                .into_response()
        }
    }
}

fn validate_route_name(name: &str, label: &str) -> Result<(), (StatusCode, String)> {
    if name == "settings" {
        return Err((
            StatusCode::CONFLICT,
            format!("{label} 'settings' is reserved"),
        ));
    }
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "{label} must be non-empty and contain only alphanumeric characters, hyphens, or underscores"
            ),
        ));
    }
    Ok(())
}

// ── Settings API: MCP servers ──────────────────────────────────────

#[derive(serde::Serialize)]
struct ServerInfo {
    name: String,
    url: String,
    auth_header: String,
    auth_prefix: Option<String>,
    log_mcp_traffic: bool,
    credential_ref: Option<String>,
    from_config: bool,
    transport: String,
}

async fn list_servers(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let upstreams = state.upstreams.read().await;
    let servers: Vec<ServerInfo> = upstreams
        .values()
        .map(|u| {
            let url = u
                .http
                .as_ref()
                .map(|h| h.url().to_string())
                .unwrap_or_default();
            let transport = match u.transport {
                TransportType::Http => "http",
                TransportType::Stdio => "stdio",
            };
            ServerInfo {
                name: u.name.clone(),
                url,
                auth_header: u.auth_header.clone(),
                auth_prefix: u.auth_prefix.clone(),
                log_mcp_traffic: u.log_mcp_traffic,
                credential_ref: u.credential_ref.clone(),
                from_config: u.from_config,
                transport: transport.to_string(),
            }
        })
        .collect();
    Json(servers)
}

async fn get_server(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    // Try dynamic store first
    if let Some(server) = state.mcp_server_store.get(&name).await {
        return Json(serde_json::json!(server)).into_response();
    }
    // Fall back to static upstream
    if let Some(u) = state.upstreams.read().await.get(&name) {
        if u.from_config {
            let url = u
                .http
                .as_ref()
                .map(|h| h.url().to_string())
                .unwrap_or_default();
            let transport = match u.transport {
                TransportType::Http => "http",
                TransportType::Stdio => "stdio",
            };
            return Json(serde_json::json!({
                "name": u.name,
                "url": url,
                "auth_header": u.auth_header,
                "auth_prefix": u.auth_prefix,
                "extra_headers": u.extra_headers,
                "log_mcp_traffic": u.log_mcp_traffic,
                "credential_ref": u.credential_ref,
                "from_config": true,
                "transport": transport,
            }))
            .into_response();
        }
    }
    (StatusCode::NOT_FOUND, "server not found").into_response()
}

async fn create_server(
    State(state): State<Arc<AppState>>,
    Json(server): Json<McpServerConfig>,
) -> impl IntoResponse {
    if let Err(err_resp) = validate_route_name(&server.name, "server name") {
        return err_resp.into_response();
    }
    if state.profile_store.get(&server.name).await.is_some() {
        return (
            StatusCode::CONFLICT,
            "name conflicts with an existing profile",
        )
            .into_response();
    }

    let upstream = match build_dynamic_upstream(
        &server,
        state.credential_provider.clone(),
        state.token_storage.clone(),
    ) {
        Ok(upstream) => upstream,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid server configuration: {}", e),
            )
                .into_response();
        }
    };

    {
        let mut upstreams = state.upstreams.write().await;
        if upstreams.contains_key(&server.name) {
            return (
                StatusCode::CONFLICT,
                "name conflicts with an existing upstream",
            )
                .into_response();
        }
        upstreams.insert(server.name.clone(), upstream.clone());
    }

    if let Err(e) = state.mcp_server_store.upsert(server.clone()).await {
        state.upstreams.write().await.remove(&server.name);
        error!(server = %server.name, error = %e, "failed to persist MCP server");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist MCP server",
        )
            .into_response();
    }

    info!(server = %server.name, "created MCP server");
    spawn_tool_cache_refresh(state.tool_cache.clone(), upstream);
    (StatusCode::CREATED, Json(server)).into_response()
}

async fn update_server(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(mut server): Json<McpServerConfig>,
) -> impl IntoResponse {
    if let Err(err_resp) = validate_route_name(&name, "server name") {
        return err_resp.into_response();
    }
    match state.upstreams.read().await.get(&name) {
        None => return (StatusCode::NOT_FOUND, "server not found").into_response(),
        Some(existing) if existing.from_config => {
            return (
                StatusCode::FORBIDDEN,
                "config-file upstreams cannot be modified via the settings API",
            )
                .into_response();
        }
        Some(_) => {}
    }

    server.name = name;
    let upstream = match build_dynamic_upstream(
        &server,
        state.credential_provider.clone(),
        state.token_storage.clone(),
    ) {
        Ok(upstream) => upstream,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid server configuration: {}", e),
            )
                .into_response();
        }
    };

    if let Err(e) = state.mcp_server_store.upsert(server.clone()).await {
        error!(server = %server.name, error = %e, "failed to persist updated MCP server");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist MCP server",
        )
            .into_response();
    }

    state
        .upstreams
        .write()
        .await
        .insert(server.name.clone(), upstream.clone());
    info!(server = %server.name, "updated MCP server");
    spawn_tool_cache_refresh(state.tool_cache.clone(), upstream);
    Json(server).into_response()
}

async fn delete_server(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    if let Some(existing) = state.upstreams.read().await.get(&name) {
        if existing.from_config {
            return (
                StatusCode::FORBIDDEN,
                "config-file upstreams cannot be deleted via the settings API",
            )
                .into_response();
        }
    }

    match state.mcp_server_store.delete(&name).await {
        Ok(true) => {
            state.upstreams.write().await.remove(&name);
            info!(server = %name, "deleted MCP server");
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "server not found").into_response(),
        Err(e) => {
            error!(server = %name, error = %e, "failed to delete persisted MCP server");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to delete MCP server",
            )
                .into_response()
        }
    }
}

fn spawn_tool_cache_refresh(tool_cache: ToolCache, upstream: Arc<UpstreamState>) {
    tokio::spawn(async move {
        if let Err(e) = tool_cache.refresh_upstream(&upstream).await {
            warn!(upstream = %upstream.name, error = %e, "failed to cache tools for server");
        }
    });
}

/// Create an UpstreamState from a dynamic McpServerConfig.
pub(crate) fn build_dynamic_upstream(
    server: &McpServerConfig,
    credential_provider: Arc<dyn CredentialProvider>,
    token_storage: Arc<dyn TokenStorage>,
) -> anyhow::Result<Arc<UpstreamState>> {
    let auth_config = AuthConfig {
        method: AuthMethod::Static,
        header: server.auth_header.clone(),
        prefix: server.auth_prefix.clone(),
        credential_ref: Some(server.credential_ref.clone()),
        oauth: None,
        extra_headers: server.extra_headers.clone(),
    };

    let auth_strategy = auth::create_auth_strategy(
        &auth_config,
        &server.name,
        None,
        credential_provider,
        token_storage,
    )?;

    let http = http_upstream::HttpUpstream::new(
        server.name.clone(),
        server.url.clone(),
        server.log_mcp_traffic,
    )?;

    Ok(Arc::new(UpstreamState {
        name: server.name.clone(),
        transport: TransportType::Http,
        auth: auth_strategy,
        http: Some(http),
        stdio: None,
        from_config: false,
        auth_header: server.auth_header.clone(),
        auth_prefix: server.auth_prefix.clone(),
        extra_headers: server.extra_headers.clone(),
        credential_ref: Some(server.credential_ref.clone()),
        log_mcp_traffic: server.log_mcp_traffic,
    }))
}

// ── Proxy routing ──────────────────────────────────────────────────

async fn root_handler(State(state): State<Arc<AppState>>, request: Request<Body>) -> Response {
    let path = request.uri().path().to_string();
    let query = request.uri().query().map(String::from);
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    if segments.is_empty() {
        return not_found().into_response();
    }
    if segments.iter().any(|s| is_dot_segment(s)) {
        return (StatusCode::BAD_REQUEST, "invalid path segment").into_response();
    }

    let first = segments[0];

    // Check if the first segment is a profile name
    if let Some(profile) = state.profile_store.get(first).await {
        if segments.len() < 2 {
            return (
                StatusCode::BAD_REQUEST,
                "profile prefix requires an upstream path segment",
            )
                .into_response();
        }
        let upstream_name = segments[1];
        if let Some(upstream) = state.upstreams.read().await.get(upstream_name) {
            let upstream = upstream.clone();
            let remaining = build_remaining_path(&segments[2..], &query);
            return proxy_with_filter(&state, upstream, request, &remaining, Some(profile)).await;
        }
        return not_found().into_response();
    }

    // Check if the first segment is an upstream name
    if let Some(upstream) = state.upstreams.read().await.get(first) {
        let upstream = upstream.clone();
        let remaining = build_remaining_path(&segments[1..], &query);
        return proxy_with_filter(&state, upstream, request, &remaining, None).await;
    }

    not_found().into_response()
}

fn build_remaining_path(segments: &[&str], query: &Option<String>) -> String {
    let path = if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    };
    match query {
        Some(q) => format!("{}?{}", path, q),
        None => path,
    }
}

fn is_dot_segment(segment: &str) -> bool {
    segment == "."
        || segment == ".."
        || segment.eq_ignore_ascii_case("%2e")
        || segment.eq_ignore_ascii_case("%2e%2e")
        || segment.eq_ignore_ascii_case(".%2e")
        || segment.eq_ignore_ascii_case("%2e.")
}

fn not_found() -> (StatusCode, &'static str) {
    (
        StatusCode::NOT_FOUND,
        "no upstream configured for this path prefix",
    )
}

async fn proxy_with_filter(
    state: &AppState,
    upstream: Arc<UpstreamState>,
    request: Request<Body>,
    remaining_path: &str,
    profile: Option<Profile>,
) -> Response {
    let method = request.method().clone();

    debug!(
        upstream = %upstream.name,
        method = %method,
        remaining_path = %remaining_path,
        profile = profile.as_ref().map(|p| p.name.as_str()),
        "routing request"
    );

    // Rewrite the URI to the remaining path
    let (mut parts, body) = request.into_parts();
    parts.uri = match remaining_path.parse() {
        Ok(uri) => uri,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid target path").into_response(),
    };

    // Read body for JSON-RPC inspection
    let body_bytes = match axum::body::to_bytes(body, 16 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("failed to read body: {}", e),
            )
                .into_response()
        }
    };

    let parsed_body = serde_json::from_slice::<Value>(&body_bytes).ok();

    // Profile-based tool filtering on single and batch tools/call requests
    if let Some(ref profile) = profile {
        let allowed = profile
            .allowed_tools
            .get(&upstream.name)
            .map(Vec::as_slice)
            .unwrap_or(&[]);

        if let Some(ref msg) = parsed_body {
            if let Some(err_resp) = enforce_profile_request(msg, allowed, &profile.name) {
                return err_resp;
            }
        }
    }

    let has_tools_list = parsed_body.as_ref().is_some_and(contains_tools_list);

    // Reconstruct request and forward to upstream
    let request = Request::from_parts(parts, Body::from(body_bytes));
    let response = do_proxy(&upstream, request).await;

    match response {
        Ok(mut resp) => {
            // Handle 401 from upstream
            if resp.status() == StatusCode::UNAUTHORIZED {
                warn!(upstream = %upstream.name, "upstream returned 401 — triggering auth refresh");
                if let Err(e) = upstream.auth.handle_unauthorized().await {
                    error!(error = %e, "failed to handle 401");
                }
            }

            // Cache tools from tools/list responses
            if has_tools_list {
                resp = cache_tools_from_response(state, &upstream.name, resp).await;
            }

            // Filter tools/list response when accessed through a profile
            if let Some(ref profile) = profile {
                if has_tools_list {
                    let allowed = profile
                        .allowed_tools
                        .get(&upstream.name)
                        .map(Vec::as_slice)
                        .unwrap_or(&[]);
                    resp = filter_tools_list_response(resp, allowed).await;
                }
            }

            resp
        }
        Err(e) => {
            error!(upstream = %upstream.name, error = %e, "proxy error");
            (
                StatusCode::BAD_GATEWAY,
                "proxy error: upstream request failed",
            )
                .into_response()
        }
    }
}

fn jsonrpc_items(msg: &Value) -> Vec<&Value> {
    match msg {
        Value::Array(items) => items.iter().collect(),
        Value::Object(_) => vec![msg],
        _ => Vec::new(),
    }
}

fn contains_tools_list(msg: &Value) -> bool {
    jsonrpc_items(msg)
        .into_iter()
        .any(|item| item.get("method").and_then(Value::as_str) == Some("tools/list"))
}

fn enforce_profile_request(
    msg: &Value,
    allowed_tools: &[String],
    profile_name: &str,
) -> Option<Response> {
    for item in jsonrpc_items(msg) {
        if item.get("method").and_then(Value::as_str) != Some("tools/call") {
            continue;
        }
        let Some(tool_name) = item
            .get("params")
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
        else {
            let error_resp = serde_json::json!({
                "jsonrpc": "2.0",
                "id": item.get("id"),
                "error": {
                    "code": -32602,
                    "message": "tools/call requires string params.name"
                }
            });
            return Some((StatusCode::OK, Json(error_resp)).into_response());
        };

        if !allowed_tools.iter().any(|allowed| allowed == tool_name) {
            let error_resp = serde_json::json!({
                "jsonrpc": "2.0",
                "id": item.get("id"),
                "error": {
                    "code": -32601,
                    "message": format!(
                        "tool '{}' is not allowed in profile '{}'",
                        tool_name, profile_name
                    )
                }
            });
            return Some((StatusCode::OK, Json(error_resp)).into_response());
        }
    }
    None
}

/// Intercept a tools/list JSON or SSE response and update the tool cache.
async fn cache_tools_from_response(
    state: &AppState,
    upstream_name: &str,
    response: Response,
) -> Response {
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let is_json = content_type.contains("application/json");
    let is_sse = content_type.contains("text/event-stream");

    if !is_json && !is_sse {
        return response;
    }

    let (parts, body) = response.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 16 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_GATEWAY,
                "failed to read upstream response body",
            )
                .into_response();
        }
    };

    let messages: Vec<Value> = if is_json {
        serde_json::from_slice::<Value>(&body_bytes)
            .ok()
            .into_iter()
            .collect()
    } else {
        sse_jsonrpc_messages(&body_bytes)
    };

    for msg in messages {
        for item in jsonrpc_items(&msg) {
            if let Some(tools) = item
                .get("result")
                .and_then(|r| r.get("tools"))
                .and_then(|t| t.as_array())
            {
                state
                    .tool_cache
                    .set_tools(upstream_name, tools.clone())
                    .await;
            }
        }
    }

    Response::from_parts(parts, Body::from(body_bytes))
}

/// Filter a tools/list JSON or SSE response to only include allowed tools.
async fn filter_tools_list_response(response: Response, allowed_tools: &[String]) -> Response {
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let is_json = content_type.contains("application/json");
    let is_sse = content_type.contains("text/event-stream");

    if !is_json && !is_sse {
        return response;
    }

    let (parts, body) = response.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 16 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_GATEWAY,
                "failed to read upstream response body",
            )
                .into_response();
        }
    };

    if is_json {
        if let Ok(mut msg) = serde_json::from_slice::<Value>(&body_bytes) {
            if filter_tools_in_message(&mut msg, allowed_tools) {
                if let Ok(filtered_bytes) = serde_json::to_vec(&msg) {
                    let mut parts = parts;
                    parts.headers.remove(http::header::CONTENT_LENGTH);
                    return Response::from_parts(parts, Body::from(filtered_bytes));
                }
            }
        }

        return Response::from_parts(parts, Body::from(body_bytes));
    }

    let text = String::from_utf8_lossy(&body_bytes).replace("\r\n", "\n");
    let mut changed = false;
    let events = text
        .split("\n\n")
        .map(|event| {
            let mut data_lines = Vec::new();
            let mut message = None;
            for line in event.lines() {
                if let Some(data) = line.strip_prefix("data:") {
                    data_lines.push(data.strip_prefix(' ').unwrap_or(data));
                }
            }
            if !data_lines.is_empty() {
                message = serde_json::from_str::<Value>(&data_lines.join("\n")).ok();
            }

            if let Some(mut message) = message {
                if filter_tools_in_message(&mut message, allowed_tools) {
                    if let Ok(data) = serde_json::to_string(&message) {
                        changed = true;
                        let mut data_written = false;
                        let lines: Vec<String> = event
                            .lines()
                            .filter_map(|line| {
                                if line.starts_with("data:") {
                                    if data_written {
                                        None
                                    } else {
                                        data_written = true;
                                        Some(format!("data: {data}"))
                                    }
                                } else {
                                    Some(line.to_string())
                                }
                            })
                            .collect();
                        return lines.join("\n");
                    }
                }
            }
            event.to_string()
        })
        .collect::<Vec<_>>();

    if changed {
        let mut parts = parts;
        parts.headers.remove(http::header::CONTENT_LENGTH);
        Response::from_parts(parts, Body::from(events.join("\n\n")))
    } else {
        Response::from_parts(parts, Body::from(body_bytes))
    }
}

fn filter_tools_in_message(msg: &mut Value, allowed_tools: &[String]) -> bool {
    if let Value::Array(items) = msg {
        let mut changed = false;
        for item in items {
            if filter_tools_in_message(item, allowed_tools) {
                changed = true;
            }
        }
        return changed;
    }

    if let Some(tools) = msg
        .get_mut("result")
        .and_then(|result| result.get_mut("tools"))
        .and_then(Value::as_array_mut)
    {
        let original_len = tools.len();
        tools.retain(|tool| {
            tool.get("name")
                .and_then(Value::as_str)
                .map(|name| allowed_tools.iter().any(|allowed| allowed == name))
                .unwrap_or(false)
        });
        tools.len() != original_len
    } else {
        false
    }
}

fn sse_jsonrpc_messages(body: &[u8]) -> Vec<Value> {
    let text = String::from_utf8_lossy(body).replace("\r\n", "\n");
    text.split("\n\n")
        .filter_map(|event| {
            let data = event
                .lines()
                .filter_map(|line| line.strip_prefix("data:"))
                .map(|line| line.strip_prefix(' ').unwrap_or(line))
                .collect::<Vec<_>>()
                .join("\n");
            if data.is_empty() {
                None
            } else {
                serde_json::from_str::<Value>(&data).ok()
            }
        })
        .collect()
}

async fn do_proxy(upstream: &UpstreamState, request: Request<Body>) -> anyhow::Result<Response> {
    // Get auth headers
    let auth_headers = upstream.auth.get_auth_headers().await?;

    match upstream.transport {
        TransportType::Http => {
            let http = upstream
                .http
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("HTTP upstream not configured"))?;
            http.forward(request, &auth_headers).await
        }
        TransportType::Stdio => {
            let stdio = upstream
                .stdio
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("stdio upstream not configured"))?;
            stdio.forward(request, &auth_headers).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_router, enforce_profile_request, filter_tools_in_message, is_dot_segment,
        UpstreamState,
    };
    use crate::auth::AuthStrategy;
    use crate::config::TransportType;
    use crate::credential::CredentialProvider;
    use crate::settings::{McpServerStore, Profile, ProfileStore};
    use crate::storage::TokenStorage;
    use crate::tool_cache::ToolCache;
    use async_trait::async_trait;
    use serde_json::json;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Arc;

    struct DummyAuth;
    #[async_trait]
    impl AuthStrategy for DummyAuth {
        async fn get_auth_headers(&self) -> anyhow::Result<Vec<(String, String)>> {
            Ok(vec![])
        }
        async fn handle_unauthorized(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    struct DummyCreds;
    #[async_trait]
    impl CredentialProvider for DummyCreds {
        async fn resolve(&self, _: &str) -> anyhow::Result<String> {
            Ok("secret".into())
        }
    }

    struct DummyStorage;
    #[async_trait]
    impl TokenStorage for DummyStorage {
        async fn get(&self, _: &str) -> anyhow::Result<Option<String>> {
            Ok(None)
        }
        async fn set(&self, _: &str, _: &str) -> anyhow::Result<()> {
            Ok(())
        }
        async fn delete(&self, _: &str) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mcp-auth-proxy-proxy-test-{name}-{:016x}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn enforces_profile_on_batch_requests_and_missing_tool_names() {
        let allowed = vec!["read_docs".to_string()];
        let batch = json!([
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "read_docs"}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "delete_all"}}
        ]);
        assert!(enforce_profile_request(&batch, &allowed, "readonly").is_some());

        let missing_name = json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {}});
        assert!(enforce_profile_request(&missing_name, &allowed, "readonly").is_some());

        let ok_batch = json!([
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "read_docs"}}
        ]);
        assert!(enforce_profile_request(&ok_batch, &allowed, "readonly").is_none());
    }

    #[test]
    fn filters_tools_in_batch_responses() {
        let mut batch_resp = json!([
            {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "a"}, {"name": "b"}]}}
        ]);
        assert!(filter_tools_in_message(&mut batch_resp, &["a".to_string()]));
        assert_eq!(batch_resp[0]["result"]["tools"], json!([{"name": "a"}]));
    }

    #[test]
    fn detects_dot_segments() {
        assert!(is_dot_segment(".."));
        assert!(is_dot_segment("%2E%2e"));
        assert!(!is_dot_segment("v1"));
    }

    #[tokio::test]
    async fn blocks_updating_config_upstreams_and_rejects_dot_paths() {
        let dir = temp_dir("router");
        let profile_store = ProfileStore::new(dir.join("profiles.json"));
        let server_store = McpServerStore::new(dir.join("servers.json"));
        profile_store
            .upsert(Profile {
                name: "readonly".into(),
                allowed_tools: HashMap::new(),
            })
            .await
            .unwrap();

        let upstream = Arc::new(UpstreamState {
            name: "cfg".into(),
            transport: TransportType::Http,
            auth: Arc::new(DummyAuth),
            http: Some(
                super::http_upstream::HttpUpstream::new(
                    "cfg".into(),
                    "https://example.com/mcp".into(),
                    false,
                )
                .unwrap(),
            ),
            stdio: None,
            from_config: true,
            auth_header: "Authorization".into(),
            auth_prefix: None,
            extra_headers: vec![],
            credential_ref: None,
            log_mcp_traffic: false,
        });

        let app = build_router(
            vec![upstream],
            ToolCache::new(),
            profile_store,
            server_store,
            Arc::new(DummyCreds),
            Arc::new(DummyStorage),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = reqwest::Client::new();
        let base = format!("http://{addr}");

        let put_cfg = client
            .put(format!("{base}/settings/servers/cfg"))
            .json(&json!({
                "name": "cfg",
                "url": "https://evil.example/steal",
                "credential_ref": "op://Private/x/y"
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(put_cfg.status(), reqwest::StatusCode::FORBIDDEN);

        let put_prof_conflict = client
            .put(format!("{base}/settings/profiles/cfg"))
            .json(&json!({"name": "cfg", "allowed_tools": {}}))
            .send()
            .await
            .unwrap();
        assert_eq!(put_prof_conflict.status(), reqwest::StatusCode::CONFLICT);

        let create_srv_conflict = client
            .post(format!("{base}/settings/servers"))
            .json(&json!({
                "name": "readonly",
                "url": "https://example.com/mcp",
                "credential_ref": "op://Private/x/y"
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(create_srv_conflict.status(), reqwest::StatusCode::CONFLICT);

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut raw = tokio::net::TcpStream::connect(addr).await.unwrap();
        raw.write_all(
            b"GET /cfg/%2e%2e/secret HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        let mut raw_resp = Vec::new();
        raw.read_to_end(&mut raw_resp).await.unwrap();
        let raw_resp_str = String::from_utf8_lossy(&raw_resp);
        assert!(
            raw_resp_str.starts_with("HTTP/1.1 400"),
            "expected 400 Bad Request, got: {raw_resp_str}"
        );

        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
