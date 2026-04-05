pub mod http_upstream;
pub mod stdio_upstream;

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    response::{IntoResponse, Response},
};
use http::StatusCode;
use tracing::{debug, error, warn};

use crate::auth::AuthStrategy;
use crate::config::TransportType;

/// Shared state for a single upstream.
pub struct UpstreamState {
    pub name: String,
    pub transport: TransportType,
    pub auth: Arc<dyn AuthStrategy>,
    pub http: Option<http_upstream::HttpUpstream>,
    pub stdio: Option<stdio_upstream::StdioUpstream>,
}

/// Build the axum router with path-prefix routing for all upstreams.
pub fn build_router(upstreams: Vec<Arc<UpstreamState>>) -> Router {
    let mut router = Router::new();

    for upstream in upstreams {
        let prefix = upstream
            .name
            .clone();

        // Create a sub-router for this upstream that catches all methods and paths
        let upstream_router = Router::new()
            .fallback(proxy_handler)
            .with_state(upstream);

        router = router.nest(&format!("/{}", prefix), upstream_router);
    }

    // Root fallback
    router = router.fallback(not_found);

    router
}

async fn not_found() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        "no upstream configured for this path prefix",
    )
}

async fn proxy_handler(
    State(upstream): State<Arc<UpstreamState>>,
    request: Request<Body>,
) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();

    debug!(
        upstream = %upstream.name,
        method = %method,
        path = %uri,
        "proxying request"
    );

    match do_proxy(&upstream, request).await {
        Ok(response) => {
            // If upstream returned 401, notify auth strategy
            if response.status() == StatusCode::UNAUTHORIZED {
                warn!(upstream = %upstream.name, "upstream returned 401 — triggering auth refresh");
                if let Err(e) = upstream.auth.handle_unauthorized().await {
                    error!(error = %e, "failed to handle 401");
                }
            }
            response
        }
        Err(e) => {
            error!(
                upstream = %upstream.name,
                error = %e,
                "proxy error"
            );
            (StatusCode::BAD_GATEWAY, format!("proxy error: {}", e)).into_response()
        }
    }
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
