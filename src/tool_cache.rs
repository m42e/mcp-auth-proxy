use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;
use tokio::sync::RwLock;
use tracing::info;

use crate::config::TransportType;
use crate::proxy::UpstreamState;

/// Caches the list of tools exposed by each upstream MCP server.
#[derive(Clone)]
pub struct ToolCache {
    cache: Arc<RwLock<HashMap<String, Vec<Value>>>>,
}

impl ToolCache {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn set_tools(&self, upstream_name: &str, tools: Vec<Value>) {
        info!(upstream = %upstream_name, count = tools.len(), "cached tools");
        self.cache
            .write()
            .await
            .insert(upstream_name.to_string(), tools);
    }

    pub async fn get_tools(&self, upstream_name: &str) -> Option<Vec<Value>> {
        self.cache.read().await.get(upstream_name).cloned()
    }

    pub async fn get_all(&self) -> HashMap<String, Vec<Value>> {
        self.cache.read().await.clone()
    }

    /// Refresh the tool cache for a single upstream by sending a tools/list request.
    pub async fn refresh_upstream(&self, upstream: &UpstreamState) -> anyhow::Result<()> {
        let auth_headers = upstream.auth.get_auth_headers().await?;

        let tools = match upstream.transport {
            TransportType::Http => {
                let http = upstream
                    .http
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("HTTP upstream not configured"))?;
                http.fetch_tools(&auth_headers).await?
            }
            TransportType::Stdio => {
                let stdio = upstream
                    .stdio
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("stdio upstream not configured"))?;
                stdio.fetch_tools().await?
            }
        };

        self.set_tools(&upstream.name, tools).await;
        Ok(())
    }
}
