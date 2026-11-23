use std::collections::HashSet;

use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::Request,
    response::{IntoResponse, Response},
};
use futures_util::StreamExt;
use http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use reqwest::Client;
use serde_json::Value;
use tracing::{debug, warn};

use crate::mcp_logging;
use crate::mcp_protocol::{
    latest_legacy_version, modern_request, supported_versions, LATEST_LEGACY_PROTOCOL_VERSION,
    MODERN_PROTOCOL_VERSION,
};

const MAX_HTTP_BODY_BYTES: usize = 16 * 1024 * 1024;
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// HTTP upstream transport — forwards requests to an HTTP MCP server.
pub struct HttpUpstream {
    client: Client,
    base_url: String,
    base_has_non_root_path: bool,
    upstream_name: String,
    log_mcp_traffic: bool,
}

impl HttpUpstream {
    pub fn new(upstream_name: String, base_url: String, log_mcp_traffic: bool) -> Result<Self> {
        let parsed = url::Url::parse(&base_url)
            .with_context(|| format!("invalid HTTP upstream URL: {base_url}"))?;
        if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
            anyhow::bail!("HTTP upstream URL must use http or https with a host");
        }
        let base_has_non_root_path = !parsed.path().is_empty() && parsed.path() != "/";

        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("failed to create HTTP client for upstream")?;

        // Normalize: strip trailing slash
        let base_url = base_url.trim_end_matches('/').to_string();

        Ok(Self {
            client,
            base_url,
            base_has_non_root_path,
            upstream_name,
            log_mcp_traffic,
        })
    }

    pub fn url(&self) -> &str {
        &self.base_url
    }

    pub async fn forward(
        &self,
        request: Request<Body>,
        auth_headers: &[(String, String)],
    ) -> Result<Response> {
        let method = request.method().clone();
        let path = request.uri().path();
        let query = request.uri().query();

        // Build upstream URL
        let upstream_url =
            build_upstream_url(&self.base_url, self.base_has_non_root_path, path, query);

        debug!(url = %upstream_url, method = %method, "forwarding to HTTP upstream");

        // Build upstream request
        let mut upstream_req = self.client.request(convert_method(&method)?, &upstream_url);

        // Strip hop-by-hop, client auth/cookie, and injected auth headers before forwarding.
        let headers = request.headers();
        let req_connection_headers = connection_nominated_headers(headers);
        for (name, value) in headers.iter() {
            let name_lower = name.as_str().to_ascii_lowercase();
            if should_strip_request_header(&name_lower, &req_connection_headers, auth_headers) {
                continue;
            }
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_str().as_bytes()),
                HeaderValue::from_bytes(value.as_bytes()),
            ) {
                upstream_req = upstream_req.header(name, value);
            }
        }

        // Inject auth headers (replace semantics — client headers with same names were stripped).
        for (name, value) in auth_headers {
            let header_name = HeaderName::from_bytes(name.as_bytes())
                .with_context(|| format!("invalid configured auth header name '{name}'"))?;
            let header_value = HeaderValue::from_str(value)
                .with_context(|| format!("invalid auth header value for '{name}'"))?;
            upstream_req = upstream_req.header(header_name, header_value);
        }

        // Forward body
        let body_bytes = match axum::body::to_bytes(request.into_body(), MAX_HTTP_BODY_BYTES).await
        {
            Ok(bytes) => bytes,
            Err(_) => {
                return Ok((
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body exceeds maximum allowed size",
                )
                    .into_response());
            }
        };

        if self.log_mcp_traffic {
            mcp_logging::log_request(&self.upstream_name, "http", &body_bytes);
        }

        if !body_bytes.is_empty() {
            upstream_req = upstream_req.body(body_bytes);
        }

        // Send request
        let upstream_resp = upstream_req
            .send()
            .await
            .context("failed to send request to upstream")?;

        // Convert response back
        let status = upstream_resp.status();
        let resp_headers = upstream_resp.headers().clone();

        // Check if this is a streaming response (SSE)
        let is_sse = resp_headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|ct| ct.contains("text/event-stream"))
            .unwrap_or(false);

        let mut response_builder = Response::builder().status(status.as_u16());

        // Forward response headers (strip hop-by-hop and Set-Cookie headers)
        let resp_connection_headers = connection_nominated_headers(&resp_headers);
        for (name, value) in resp_headers.iter() {
            let name_lower = name.as_str().to_ascii_lowercase();
            if should_strip_response_header(&name_lower, &resp_connection_headers) {
                continue;
            }
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_str().as_bytes()),
                HeaderValue::from_bytes(value.as_bytes()),
            ) {
                response_builder = response_builder.header(name, value);
            }
        }

        if is_sse {
            // Stream SSE responses
            debug!("streaming SSE response from upstream");
            if self.log_mcp_traffic {
                let content_type = resp_headers
                    .get(header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok());
                mcp_logging::log_streaming_response(
                    &self.upstream_name,
                    "http",
                    status.as_u16(),
                    content_type,
                );
            }
            let stream = upstream_resp
                .bytes_stream()
                .map(|result| result.map_err(|e| std::io::Error::other(e.to_string())));
            let body = Body::from_stream(stream);
            response_builder
                .body(body)
                .context("failed to build SSE response")
        } else {
            // Buffer non-streaming responses with size bound
            let body_bytes = read_bounded_body(upstream_resp, MAX_HTTP_BODY_BYTES).await?;
            if self.log_mcp_traffic {
                mcp_logging::log_response(
                    &self.upstream_name,
                    "http",
                    Some(status.as_u16()),
                    &body_bytes,
                );
            }
            let body = Body::from(body_bytes);
            response_builder
                .body(body)
                .context("failed to build upstream response")
        }
    }
}

fn build_upstream_url(
    base_url: &str,
    base_has_non_root_path: bool,
    path: &str,
    query: Option<&str>,
) -> String {
    let joined = if path == "/" && base_has_non_root_path {
        base_url.to_string()
    } else {
        format!("{base_url}{path}")
    };
    match query {
        Some(q) => format!("{joined}?{q}"),
        None => joined,
    }
}

fn connection_nominated_headers(headers: &HeaderMap) -> HashSet<String> {
    let mut nominated = HashSet::new();
    for value in headers.get_all(header::CONNECTION) {
        if let Ok(value_str) = value.to_str() {
            for token in value_str.split(',') {
                let token = token.trim().to_ascii_lowercase();
                if !token.is_empty() {
                    nominated.insert(token);
                }
            }
        }
    }
    nominated
}

fn should_strip_request_header(
    name_lower: &str,
    connection_headers: &HashSet<String>,
    auth_headers: &[(String, String)],
) -> bool {
    matches!(
        name_lower,
        "host" | "content-length" | "cookie" | "accept-encoding" | "authorization"
    ) || HOP_BY_HOP_HEADERS.contains(&name_lower)
        || connection_headers.contains(name_lower)
        || auth_headers
            .iter()
            .any(|(auth_name, _)| auth_name.eq_ignore_ascii_case(name_lower))
}

fn should_strip_response_header(name_lower: &str, connection_headers: &HashSet<String>) -> bool {
    name_lower == "set-cookie"
        || HOP_BY_HOP_HEADERS.contains(&name_lower)
        || connection_headers.contains(name_lower)
}

async fn read_bounded_body(mut resp: reqwest::Response, max_bytes: usize) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .context("failed to read upstream response body")?
    {
        if buf.len().saturating_add(chunk.len()) > max_bytes {
            anyhow::bail!("upstream response body exceeds {max_bytes} bytes");
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

fn convert_method(method: &Method) -> Result<reqwest::Method> {
    reqwest::Method::from_bytes(method.as_str().as_bytes())
        .with_context(|| format!("unsupported HTTP method: {method}"))
}

impl HttpUpstream {
    /// Fetch tools using the modern protocol first, then fall back to the legacy handshake.
    pub async fn fetch_tools(&self, auth_headers: &[(String, String)]) -> Result<Vec<Value>> {
        let discover = modern_request(
            "server/discover",
            serde_json::json!("discover-1"),
            MODERN_PROTOCOL_VERSION,
        );
        let reply = self
            .post_jsonrpc(&discover, auth_headers, Some(MODERN_PROTOCOL_VERSION), None)
            .await?;

        let response = parse_jsonrpc_response(&reply).ok();
        let method_not_found = response
            .as_ref()
            .and_then(|value| value.pointer("/error/code"))
            .and_then(Value::as_i64)
            == Some(-32601);
        if reply.status == reqwest::StatusCode::UNAUTHORIZED
            || reply.status == reqwest::StatusCode::FORBIDDEN
        {
            anyhow::bail!("MCP discovery failed with HTTP {}", reply.status);
        }

        if let Some(response) = response {
            if let Some(error) = response.get("error") {
                let error_code = error.get("code").and_then(Value::as_i64);
                if error_code == Some(-32022) {
                    let versions = supported_versions(&response);
                    if let Some(legacy_version) =
                        latest_legacy_version(versions.iter().map(String::as_str))
                    {
                        return self.fetch_legacy_tools(auth_headers, legacy_version).await;
                    }
                    anyhow::bail!(
                        "upstream does not support MCP protocol version {}; supported versions: {}",
                        MODERN_PROTOCOL_VERSION,
                        versions.join(", ")
                    );
                }

                if error_code.is_some_and(|code| (-32099..=-32020).contains(&code)) {
                    anyhow::bail!("MCP discovery failed: {error}");
                }

                if reply.status.is_success() && error_code != Some(-32601) {
                    anyhow::bail!("MCP discovery failed: {error}");
                }
            } else if reply.status.is_success() {
                let versions = supported_versions(&response);
                if versions.iter().any(|v| v == MODERN_PROTOCOL_VERSION) {
                    if response.pointer("/result/capabilities/tools").is_some() {
                        return self
                            .fetch_modern_tools(auth_headers, MODERN_PROTOCOL_VERSION)
                            .await;
                    }
                    return Ok(Vec::new());
                }

                if let Some(legacy_version) =
                    latest_legacy_version(versions.iter().map(String::as_str))
                {
                    return self.fetch_legacy_tools(auth_headers, legacy_version).await;
                }

                anyhow::bail!(
                    "MCP discovery returned no supported protocol version compatible with this proxy"
                );
            }
        }

        if !reply.status.is_client_error() && !(reply.status.is_success() && method_not_found) {
            anyhow::bail!(
                "MCP discovery failed with HTTP {}: {}",
                reply.status,
                String::from_utf8_lossy(&reply.body)
            );
        }

        // A legacy server generally rejects server/discover with 4xx or -32601. Per the
        // Streamable HTTP compatibility rules, retry using the initialize handshake.
        self.fetch_legacy_tools(auth_headers, LATEST_LEGACY_PROTOCOL_VERSION)
            .await
    }

    async fn fetch_modern_tools(
        &self,
        auth_headers: &[(String, String)],
        version: &str,
    ) -> Result<Vec<Value>> {
        let request = modern_request("tools/list", serde_json::json!("tools-1"), version);
        let reply = self
            .post_jsonrpc(&request, auth_headers, Some(version), None)
            .await?;
        let response = parse_jsonrpc_response(&reply).with_context(|| {
            format!(
                "failed to parse tools/list response (HTTP {})",
                reply.status
            )
        })?;
        ensure_success(&reply, &response, "tools/list")?;
        Ok(response
            .pointer("/result/tools")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }

    async fn fetch_legacy_tools(
        &self,
        auth_headers: &[(String, String)],
        version: &str,
    ) -> Result<Vec<Value>> {
        let init_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": 1,
            "params": {
                "protocolVersion": version,
                "capabilities": {},
                "clientInfo": {
                    "name": "mcp-auth-proxy",
                    "version": env!("CARGO_PKG_VERSION"),
                }
            }
        });
        let init_reply = self
            .post_jsonrpc(&init_body, auth_headers, None, None)
            .await?;
        let init_result = parse_jsonrpc_response(&init_reply).with_context(|| {
            format!(
                "failed to parse initialize response (HTTP {})",
                init_reply.status
            )
        })?;
        ensure_success(&init_reply, &init_result, "initialize")?;

        let session_id = init_reply.session_id.as_deref();
        debug!(session_id = ?session_id, version, "legacy MCP session initialized for tool discovery");

        let negotiated_version = init_result
            .pointer("/result/protocolVersion")
            .and_then(Value::as_str)
            .unwrap_or(version);
        let legacy_version_header =
            (negotiated_version >= "2025-06-18").then_some(negotiated_version);

        let notif_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });
        let notif_reply = self
            .post_jsonrpc(&notif_body, auth_headers, legacy_version_header, session_id)
            .await?;
        if !notif_reply.status.is_success() {
            warn!(status = %notif_reply.status, "initialized notification returned non-success status");
        }

        let tools_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 2,
        });
        let tools_reply = self
            .post_jsonrpc(&tools_body, auth_headers, legacy_version_header, session_id)
            .await?;
        let response = parse_jsonrpc_response(&tools_reply).with_context(|| {
            format!(
                "failed to parse tools/list response (HTTP {})",
                tools_reply.status
            )
        })?;
        ensure_success(&tools_reply, &response, "tools/list")?;
        Ok(response
            .pointer("/result/tools")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }

    async fn post_jsonrpc(
        &self,
        message: &Value,
        auth_headers: &[(String, String)],
        protocol_version: Option<&str>,
        session_id: Option<&str>,
    ) -> Result<HttpRpcReply> {
        let method = message
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();

        if self.log_mcp_traffic {
            let payload = serde_json::to_vec(message).context("failed to serialize MCP request")?;
            mcp_logging::log_request(&self.upstream_name, "http", &payload);
        }

        let mut request = self
            .client
            .post(&self.base_url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream");

        if let Some(version) = protocol_version {
            request = request.header("MCP-Protocol-Version", version);
            if message.pointer("/params/_meta").is_some() {
                request = request.header("Mcp-Method", method);
            }
        }
        if let Some(session_id) = session_id {
            request = request.header("Mcp-Session-Id", session_id);
        }
        for (name, value) in auth_headers {
            request = request.header(name.as_str(), value.as_str());
        }

        let response = request
            .json(message)
            .send()
            .await
            .context("failed to send MCP request")?;
        let status = response.status();
        let session_id = response
            .headers()
            .get("mcp-session-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = response
            .bytes()
            .await
            .context("failed to read MCP response")?
            .to_vec();

        if self.log_mcp_traffic {
            mcp_logging::log_response(&self.upstream_name, "http", Some(status.as_u16()), &body);
        }

        Ok(HttpRpcReply {
            status,
            session_id,
            content_type,
            body,
        })
    }
}

struct HttpRpcReply {
    status: reqwest::StatusCode,
    session_id: Option<String>,
    content_type: Option<String>,
    body: Vec<u8>,
}

fn parse_jsonrpc_response(reply: &HttpRpcReply) -> Result<Value> {
    let is_sse = reply
        .content_type
        .as_deref()
        .map(|content_type| content_type.contains("text/event-stream"))
        .unwrap_or(false);

    if !is_sse {
        return serde_json::from_slice(&reply.body).context("response body is not valid JSON");
    }

    let text = String::from_utf8_lossy(&reply.body);
    let mut data_lines = Vec::new();
    for line in text.lines().chain(std::iter::once("")) {
        if line.is_empty() {
            if !data_lines.is_empty() {
                let data = data_lines.join("\n");
                data_lines.clear();
                if let Ok(value) = serde_json::from_str::<Value>(&data) {
                    if value.get("id").is_some() || value.get("error").is_some() {
                        return Ok(value);
                    }
                }
            }
        } else if let Some(data) = line.strip_prefix("data:") {
            data_lines.push(data.strip_prefix(' ').unwrap_or(data).to_string());
        }
    }

    anyhow::bail!("SSE response did not contain a JSON-RPC response")
}

fn ensure_success(reply: &HttpRpcReply, response: &Value, method: &str) -> Result<()> {
    if !reply.status.is_success() || response.get("error").is_some() {
        let detail = response
            .get("error")
            .map(Value::to_string)
            .unwrap_or_else(|| String::from_utf8_lossy(&reply.body).into_owned());
        anyhow::bail!("{} failed with HTTP {}: {}", method, reply.status, detail);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        build_upstream_url, connection_nominated_headers, convert_method,
        should_strip_request_header, should_strip_response_header, HttpUpstream,
    };
    use http::{header, HeaderMap, HeaderValue, Method};

    #[test]
    fn builds_upstream_url_without_spurious_trailing_slash() {
        assert_eq!(
            build_upstream_url("https://mcp.context7.com/mcp", true, "/", None),
            "https://mcp.context7.com/mcp"
        );
        assert_eq!(
            build_upstream_url("https://mcp.context7.com/mcp", true, "/", Some("a=1")),
            "https://mcp.context7.com/mcp?a=1"
        );
        assert_eq!(
            build_upstream_url("https://mcp.context7.com/mcp", true, "/sse", None),
            "https://mcp.context7.com/mcp/sse"
        );
        assert_eq!(
            build_upstream_url("https://mcp.example.com", false, "/", None),
            "https://mcp.example.com/"
        );
    }

    #[test]
    fn strips_sensitive_and_hop_by_hop_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONNECTION, HeaderValue::from_static("x-hop, TE"));
        let conn = connection_nominated_headers(&headers);
        let auth = vec![("X-Custom-Auth".to_string(), "secret".to_string())];

        assert!(should_strip_request_header("authorization", &conn, &auth));
        assert!(should_strip_request_header("cookie", &conn, &auth));
        assert!(should_strip_request_header("accept-encoding", &conn, &auth));
        assert!(should_strip_request_header("x-custom-auth", &conn, &auth));
        assert!(should_strip_request_header("x-hop", &conn, &auth));
        assert!(!should_strip_request_header("mcp-session-id", &conn, &auth));

        assert!(should_strip_response_header("set-cookie", &conn));
        assert!(should_strip_response_header("transfer-encoding", &conn));
        assert!(should_strip_response_header("x-hop", &conn));
        assert!(!should_strip_response_header("content-type", &conn));
    }

    #[test]
    fn rejects_invalid_upstream_url_schemes() {
        assert!(HttpUpstream::new("bad".into(), "file:///etc/passwd".into(), false).is_err());
        assert!(
            HttpUpstream::new("ok".into(), "https://mcp.example.com/mcp".into(), false).is_ok()
        );
    }

    #[test]
    fn preserves_custom_http_methods() {
        let m = Method::from_bytes(b"PROPFIND").unwrap();
        assert_eq!(convert_method(&m).unwrap().as_str(), "PROPFIND");
    }
}
