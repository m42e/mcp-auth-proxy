pub mod http_upstream;
pub mod stdio_upstream;

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    Json, Router,
    body::Body,
    extract::{Path, Request, State},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use http::StatusCode;
use serde_json::Value;
use tracing::{debug, error, info, warn};

use crate::auth::AuthStrategy;
use crate::config::TransportType;
use crate::settings::{Profile, ProfileStore};
use crate::tool_cache::ToolCache;

/// Shared state for a single upstream.
pub struct UpstreamState {
    pub name: String,
    pub transport: TransportType,
    pub auth: Arc<dyn AuthStrategy>,
    pub http: Option<http_upstream::HttpUpstream>,
    pub stdio: Option<stdio_upstream::StdioUpstream>,
}

/// Shared application state.
pub struct AppState {
    pub upstreams: HashMap<String, Arc<UpstreamState>>,
    pub tool_cache: ToolCache,
    pub profile_store: ProfileStore,
}

/// Build the axum router with path-prefix routing, settings API, and profile support.
pub fn build_router(
    upstreams: Vec<Arc<UpstreamState>>,
    tool_cache: ToolCache,
    profile_store: ProfileStore,
) -> Router {
    let upstream_map: HashMap<String, Arc<UpstreamState>> = upstreams
        .into_iter()
        .map(|u| (u.name.clone(), u))
        .collect();

    let state = Arc::new(AppState {
        upstreams: upstream_map,
        tool_cache,
        profile_store,
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
            get(get_profile)
                .put(update_profile)
                .delete(delete_profile),
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
    let names: Vec<String> = state.upstreams.keys().cloned().collect();
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
    let upstream = match state.upstreams.get(&upstream_name) {
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
    if state.upstreams.contains_key(&profile.name) {
        return (
            StatusCode::CONFLICT,
            "profile name conflicts with an upstream name",
        )
            .into_response();
    }
    if profile.name == "settings" {
        return (StatusCode::CONFLICT, "profile name 'settings' is reserved").into_response();
    }
    if profile.name.is_empty()
        || !profile
            .name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return (
            StatusCode::BAD_REQUEST,
            "profile name must be non-empty and contain only alphanumeric characters, hyphens, or underscores",
        )
            .into_response();
    }

    state.profile_store.upsert(profile.clone()).await;
    info!(profile = %profile.name, "created profile");
    (StatusCode::CREATED, Json(profile)).into_response()
}

async fn update_profile(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(mut profile): Json<Profile>,
) -> impl IntoResponse {
    profile.name = name;
    state.profile_store.upsert(profile.clone()).await;
    Json(profile).into_response()
}

async fn delete_profile(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    if state.profile_store.delete(&name).await {
        StatusCode::NO_CONTENT.into_response()
    } else {
        (StatusCode::NOT_FOUND, "profile not found").into_response()
    }
}

// ── Proxy routing ──────────────────────────────────────────────────

async fn root_handler(State(state): State<Arc<AppState>>, request: Request<Body>) -> Response {
    let path = request.uri().path().to_string();
    let query = request.uri().query().map(String::from);
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    if segments.is_empty() {
        return not_found().into_response();
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
        if let Some(upstream) = state.upstreams.get(upstream_name) {
            let remaining = build_remaining_path(&segments[2..], &query);
            return proxy_with_filter(&state, upstream.clone(), request, &remaining, Some(profile))
                .await;
        }
        return not_found().into_response();
    }

    // Check if the first segment is an upstream name
    if let Some(upstream) = state.upstreams.get(first) {
        let remaining = build_remaining_path(&segments[1..], &query);
        return proxy_with_filter(&state, upstream.clone(), request, &remaining, None).await;
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
    parts.uri = remaining_path
        .parse()
        .unwrap_or_else(|_| "/".parse().unwrap());

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

    let jsonrpc_method = serde_json::from_slice::<Value>(&body_bytes)
        .ok()
        .and_then(|msg| msg.get("method").and_then(|m| m.as_str()).map(String::from));

    // Profile-based tool filtering on tools/call requests
    if let Some(ref profile) = profile {
        let allowed = profile
            .allowed_tools
            .get(&upstream.name)
            .cloned()
            .unwrap_or_default();

        if jsonrpc_method.as_deref() == Some("tools/call") {
            if let Ok(msg) = serde_json::from_slice::<Value>(&body_bytes) {
                if let Some(tool_name) = msg
                    .get("params")
                    .and_then(|p| p.get("name"))
                    .and_then(|n| n.as_str())
                {
                    if !allowed.contains(&tool_name.to_string()) {
                        let error_resp = serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": msg.get("id"),
                            "error": {
                                "code": -32601,
                                "message": format!(
                                    "tool '{}' is not allowed in profile '{}'",
                                    tool_name, profile.name
                                )
                            }
                        });
                        return (StatusCode::OK, Json(error_resp)).into_response();
                    }
                }
            }
        }
    }

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
            if jsonrpc_method.as_deref() == Some("tools/list") {
                resp = cache_tools_from_response(state, &upstream.name, resp).await;
            }

            // Filter tools/list response when accessed through a profile
            if let Some(ref profile) = profile {
                if jsonrpc_method.as_deref() == Some("tools/list") {
                    let allowed = profile
                        .allowed_tools
                        .get(&upstream.name)
                        .cloned()
                        .unwrap_or_default();
                    resp = filter_tools_list_response(resp, &allowed).await;
                }
            }

            resp
        }
        Err(e) => {
            error!(upstream = %upstream.name, error = %e, "proxy error");
            (StatusCode::BAD_GATEWAY, format!("proxy error: {}", e)).into_response()
        }
    }
}

/// Intercept a tools/list JSON response and update the tool cache.
async fn cache_tools_from_response(
    state: &AppState,
    upstream_name: &str,
    response: Response,
) -> Response {
    let is_json = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.contains("application/json"))
        .unwrap_or(false);

    if !is_json {
        return response;
    }

    let (parts, body) = response.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 16 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return Response::from_parts(parts, Body::empty()),
    };

    if let Ok(msg) = serde_json::from_slice::<Value>(&body_bytes) {
        if let Some(tools) = msg
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

    Response::from_parts(parts, Body::from(body_bytes))
}

/// Filter a tools/list JSON response to only include allowed tools.
async fn filter_tools_list_response(response: Response, allowed_tools: &[String]) -> Response {
    let is_json = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.contains("application/json"))
        .unwrap_or(false);

    if !is_json {
        return response;
    }

    let (parts, body) = response.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 16 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return Response::from_parts(parts, Body::empty()),
    };

    if let Ok(mut msg) = serde_json::from_slice::<Value>(&body_bytes) {
        if let Some(tools) = msg
            .get_mut("result")
            .and_then(|r| r.get_mut("tools"))
            .and_then(|t| t.as_array_mut())
        {
            tools.retain(|tool| {
                tool.get("name")
                    .and_then(|n| n.as_str())
                    .map(|name| allowed_tools.contains(&name.to_string()))
                    .unwrap_or(false)
            });

            if let Ok(filtered_bytes) = serde_json::to_vec(&msg) {
                return Response::from_parts(parts, Body::from(filtered_bytes));
            }
        }
    }

    Response::from_parts(parts, Body::from(body_bytes))
}

async fn do_proxy(upstream: &UpstreamState, request: Request<Body>) -> anyhow::Result<Response> {
    // Get auth header
    let (header_name, header_value) = upstream.auth.get_auth_header().await?;

    match upstream.transport {
        TransportType::Http => {
            let http = upstream
                .http
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("HTTP upstream not configured"))?;
            http.forward(request, &header_name, &header_value).await
        }
        TransportType::Stdio => {
            let stdio = upstream
                .stdio
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("stdio upstream not configured"))?;
            stdio.forward(request, &header_name, &header_value).await
        }
    }
}
