use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::Request,
    response::{IntoResponse, Response},
};
use futures_util::StreamExt;
use http::{header, HeaderName, HeaderValue, Method};
use reqwest::Client;
use tracing::debug;

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

    pub async fn forward(
        &self,
        request: Request<Body>,
        auth_header_name: &str,
        auth_header_value: &str,
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

        // Inject auth header
        upstream_req = upstream_req.header(auth_header_name, auth_header_value);

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
