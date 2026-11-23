use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::warn;

use crate::config::{default_auth_header, ExtraHeader};
use crate::storage::write_private_atomic;

/// A profile that limits tool access under a URL prefix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    /// Upstream name → list of allowed tool names.
    /// Upstreams not listed here have no tools accessible through this profile.
    pub allowed_tools: HashMap<String, Vec<String>>,
}

/// Persistent store for profiles, backed by a JSON file.
#[derive(Clone)]
pub struct ProfileStore {
    profiles: Arc<RwLock<HashMap<String, Profile>>>,
    path: PathBuf,
}

impl ProfileStore {
    pub fn new(path: PathBuf) -> Self {
        let profiles = load_json_map::<Profile>(&path, |p| p.name.clone());
        Self {
            profiles: Arc::new(RwLock::new(profiles)),
            path,
        }
    }

    pub async fn list(&self) -> Vec<Profile> {
        self.profiles.read().await.values().cloned().collect()
    }

    pub async fn get(&self, name: &str) -> Option<Profile> {
        self.profiles.read().await.get(name).cloned()
    }

    pub async fn upsert(&self, profile: Profile) -> anyhow::Result<()> {
        let mut profiles = self.profiles.write().await;
        let mut next = profiles.clone();
        next.insert(profile.name.clone(), profile);
        persist_json(&self.path, &next).await?;
        *profiles = next;
        Ok(())
    }

    pub async fn delete(&self, name: &str) -> anyhow::Result<bool> {
        let mut profiles = self.profiles.write().await;
        if !profiles.contains_key(name) {
            return Ok(false);
        }
        let mut next = profiles.clone();
        next.remove(name);
        persist_json(&self.path, &next).await?;
        *profiles = next;
        Ok(true)
    }
}

/// Configuration for an MCP server added via the settings UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerConfig {
    pub name: String,
    pub url: String,
    #[serde(default = "default_auth_header")]
    pub auth_header: String,
    #[serde(default)]
    pub auth_prefix: Option<String>,
    #[serde(default)]
    pub log_mcp_traffic: bool,
    pub credential_ref: String,
    /// Additional headers to inject, each resolved via the credential provider
    #[serde(default)]
    pub extra_headers: Vec<ExtraHeader>,
}

/// Persistent store for dynamically added MCP server configurations, backed by a JSON file.
#[derive(Clone)]
pub struct McpServerStore {
    servers: Arc<RwLock<HashMap<String, McpServerConfig>>>,
    path: PathBuf,
}

impl McpServerStore {
    pub fn new(path: PathBuf) -> Self {
        let servers = load_json_map::<McpServerConfig>(&path, |s| s.name.clone());
        Self {
            servers: Arc::new(RwLock::new(servers)),
            path,
        }
    }

    pub async fn list(&self) -> Vec<McpServerConfig> {
        self.servers.read().await.values().cloned().collect()
    }

    pub async fn get(&self, name: &str) -> Option<McpServerConfig> {
        self.servers.read().await.get(name).cloned()
    }

    pub async fn upsert(&self, config: McpServerConfig) -> anyhow::Result<()> {
        let mut servers = self.servers.write().await;
        let mut next = servers.clone();
        next.insert(config.name.clone(), config);
        persist_json(&self.path, &next).await?;
        *servers = next;
        Ok(())
    }

    pub async fn delete(&self, name: &str) -> anyhow::Result<bool> {
        let mut servers = self.servers.write().await;
        if !servers.contains_key(name) {
            return Ok(false);
        }
        let mut next = servers.clone();
        next.remove(name);
        persist_json(&self.path, &next).await?;
        *servers = next;
        Ok(true)
    }
}

// ── Persistence helpers ────────────────────────────────────────────

/// Load a JSON file containing an array of items into a HashMap keyed by name.
fn load_json_map<T>(path: &Path, key_fn: fn(&T) -> String) -> HashMap<String, T>
where
    T: serde::de::DeserializeOwned,
{
    match std::fs::read_to_string(path) {
        Ok(data) => match serde_json::from_str::<Vec<T>>(&data) {
            Ok(items) => items
                .into_iter()
                .map(|item| (key_fn(&item), item))
                .collect(),
            Err(e) => {
                warn!(path = %path.display(), error = %e, "failed to parse persisted data, starting empty");
                HashMap::new()
            }
        },
        Err(_) => HashMap::new(),
    }
}

/// Persist a HashMap of items to a JSON file atomically with private permissions.
async fn persist_json<T: Serialize>(path: &Path, map: &HashMap<String, T>) -> anyhow::Result<()> {
    let items: Vec<&T> = map.values().collect();
    let data = serde_json::to_vec_pretty(&items).context("failed to serialize persisted data")?;
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || write_private_atomic(&path, &data))
        .await
        .context("persistence write task panicked")?
}
