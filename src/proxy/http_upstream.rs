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

/// HTTP upstream transport — forwards requests to an HTTP MCP server.
pub struct HttpUpstream {
    client: Client,
    base_url: String,
}

impl HttpUpstream {
    pub fn new(base_url: String) -> Result<Self> {
        let client = Client::builder()
            .build()
            .context("failed to create HTTP client for upstream")?;

        // Normalize: strip trailing slash
        let base_url = base_url.trim_end_matches('/').to_string();

        Ok(Self { client, base_url })
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
        let mut upstream_req = self.client.request(
            convert_method(&method),
            &upstream_url,
        );

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
            let stream = upstream_resp.bytes_stream().map(|result| {
                result.map_err(|e| {
                    std::io::Error::other(e.to_string())
                })
            });
            let body = Body::from_stream(stream);
            Ok(response_builder.body(body).unwrap().into_response())
        } else {
            // Buffer non-streaming responses
            let body_bytes = upstream_resp
                .bytes()
                .await
                .context("failed to read upstream response body")?;
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
    /// Fetch the list of tools from the upstream MCP server.
    ///
    /// This performs the full MCP session handshake:
    ///   1. initialize  → capture Mcp-Session-Id
    ///   2. notifications/initialized
    ///   3. tools/list  → extract tools
    pub async fn fetch_tools(
        &self,
        auth_headers: &[(String, String)],
    ) -> Result<Vec<Value>> {
        // Step 1: initialize
        let init_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": 1,
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {
                    "name": "mcp-auth-proxy",
                    "version": "0.1.0"
                }
            }
        });

        let mut init_req = self
            .client
            .post(&self.base_url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream");
        for (name, value) in auth_headers {
            init_req = init_req.header(name.as_str(), value.as_str());
        }
        let init_resp = init_req
            .json(&init_body)
            .send()
            .await
            .context("failed to send initialize request")?;

        let session_id = init_resp
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let init_result: Value = init_resp
            .json()
            .await
            .context("failed to parse initialize response")?;

        if init_result.get("error").is_some() {
            anyhow::bail!(
                "initialize failed: {}",
                init_result.get("error").unwrap()
            );
        }

        debug!(session_id = ?session_id, "MCP session initialized for tool discovery");

        // Step 2: notifications/initialized
        let notif_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });

        let mut notif_req = self
            .client
            .post(&self.base_url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream");
        for (name, value) in auth_headers {
            notif_req = notif_req.header(name.as_str(), value.as_str());
        }

        if let Some(ref sid) = session_id {
            notif_req = notif_req.header("Mcp-Session-Id", sid);
        }

        let notif_resp = notif_req
            .json(&notif_body)
            .send()
            .await
            .context("failed to send initialized notification")?;

        if !notif_resp.status().is_success() {
            warn!(
                status = %notif_resp.status(),
                "initialized notification returned non-success status"
            );
        }

        // Step 3: tools/list
        let tools_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 2
        });

        let mut tools_req = self
            .client
            .post(&self.base_url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream");
        for (name, value) in auth_headers {
            tools_req = tools_req.header(name.as_str(), value.as_str());
        }

        if let Some(ref sid) = session_id {
            tools_req = tools_req.header("Mcp-Session-Id", sid);
        }

        let tools_resp = tools_req
            .json(&tools_body)
            .send()
            .await
            .context("failed to send tools/list request")?;

        let body: Value = tools_resp
            .json()
            .await
            .context("failed to parse tools/list response")?;

        if body.get("error").is_some() {
            anyhow::bail!("tools/list failed: {}", body.get("error").unwrap());
        }

        let tools = body
            .get("result")
            .and_then(|r| r.get("tools"))
            .and_then(|t| t.as_array())
            .cloned()
            .unwrap_or_default();

        Ok(tools)
    }
}
