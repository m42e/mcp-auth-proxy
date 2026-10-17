use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::Request,
    response::{IntoResponse, Response},
};
use futures_util::StreamExt;
use http::{header, HeaderName, HeaderValue, Method};
use reqwest::Client;
use serde_json::Value;
use tracing::{debug, warn};

use crate::mcp_logging;
use crate::mcp_protocol::{
    latest_legacy_version, modern_request, supported_versions, LATEST_LEGACY_PROTOCOL_VERSION,
    MODERN_PROTOCOL_VERSION,
};

/// HTTP upstream transport — forwards requests to an HTTP MCP server.
pub struct HttpUpstream {
    client: Client,
    base_url: String,
    upstream_name: String,
    log_mcp_traffic: bool,
}

impl HttpUpstream {
    pub fn new(upstream_name: String, base_url: String, log_mcp_traffic: bool) -> Result<Self> {
        let client = Client::builder()
            .build()
            .context("failed to create HTTP client for upstream")?;

        // Normalize: strip trailing slash
        let base_url = base_url.trim_end_matches('/').to_string();

        Ok(Self {
            client,
            base_url,
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
        let upstream_url = if let Some(q) = query {
            format!("{}{}?{}", self.base_url, path, q)
        } else {
            format!("{}{}", self.base_url, path)
        };

        debug!(url = %upstream_url, method = %method, "forwarding to HTTP upstream");

        // Build upstream request
        let mut upstream_req = self.client.request(convert_method(&method), &upstream_url);

        // Forward headers (except Host and Connection)
        let headers = request.headers();
        for (name, value) in headers.iter() {
            if name == header::HOST || name == header::CONNECTION {
                continue;
            }
            if let Ok(name) = reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()) {
                if let Ok(value) = reqwest::header::HeaderValue::from_bytes(value.as_bytes()) {
                    upstream_req = upstream_req.header(name, value);
                }
            }
        }

        // Inject auth headers
        for (name, value) in auth_headers {
            upstream_req = upstream_req.header(name.as_str(), value.as_str());
        }

        // Forward body
        let body_bytes = axum::body::to_bytes(request.into_body(), usize::MAX)
            .await
            .context("failed to read request body")?;

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
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|ct| ct.contains("text/event-stream"))
            .unwrap_or(false);

        let mut response_builder = Response::builder().status(status.as_u16());

        // Forward response headers
        for (name, value) in resp_headers.iter() {
            if name == reqwest::header::TRANSFER_ENCODING {
                continue;
            }
            if let Ok(name) = HeaderName::from_bytes(name.as_str().as_bytes()) {
                if let Ok(value) = HeaderValue::from_bytes(value.as_bytes()) {
                    response_builder = response_builder.header(name, value);
                }
            }
        }

        if is_sse {
            // Stream SSE responses
            debug!("streaming SSE response from upstream");
            if self.log_mcp_traffic {
                let content_type = resp_headers
                    .get(reqwest::header::CONTENT_TYPE)
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
            Ok(response_builder.body(body).unwrap().into_response())
        } else {
            // Buffer non-streaming responses
            let body_bytes = upstream_resp
                .bytes()
                .await
                .context("failed to read upstream response body")?;
            if self.log_mcp_traffic {
                mcp_logging::log_response(
                    &self.upstream_name,
                    "http",
                    Some(status.as_u16()),
                    body_bytes.as_ref(),
                );
            }
            let body = Body::from(body_bytes);
            Ok(response_builder.body(body).unwrap().into_response())
        }
    }
}

fn convert_method(method: &Method) -> reqwest::Method {
    match *method {
        Method::GET => reqwest::Method::GET,
        Method::POST => reqwest::Method::POST,
        Method::PUT => reqwest::Method::PUT,
        Method::DELETE => reqwest::Method::DELETE,
        Method::PATCH => reqwest::Method::PATCH,
        Method::HEAD => reqwest::Method::HEAD,
        Method::OPTIONS => reqwest::Method::OPTIONS,
        _ => reqwest::Method::GET,
    }
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
