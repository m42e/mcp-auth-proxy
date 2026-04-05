use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::warn;

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

    pub async fn upsert(&self, profile: Profile) {
        let mut profiles = self.profiles.write().await;
        profiles.insert(profile.name.clone(), profile);
        persist_json(&self.path, &profiles);
    }

    pub async fn delete(&self, name: &str) -> bool {
        let mut profiles = self.profiles.write().await;
        let removed = profiles.remove(name).is_some();
        if removed {
            persist_json(&self.path, &profiles);
        }
        removed
    }
}

use crate::config::ExtraHeader;

/// Configuration for an MCP server added via the settings UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerConfig {
    pub name: String,
    pub url: String,
    #[serde(default = "default_auth_header")]
    pub auth_header: String,
    #[serde(default)]
    pub auth_prefix: Option<String>,
    pub credential_ref: String,
    /// Additional headers to inject, each resolved via the credential provider
    #[serde(default)]
    pub extra_headers: Vec<ExtraHeader>,
}

fn default_auth_header() -> String {
    "Authorization".to_string()
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

    pub async fn upsert(&self, config: McpServerConfig) {
        let mut servers = self.servers.write().await;
        servers.insert(config.name.clone(), config);
        persist_json(&self.path, &servers);
    }

    pub async fn delete(&self, name: &str) -> bool {
        let mut servers = self.servers.write().await;
        let removed = servers.remove(name).is_some();
        if removed {
            persist_json(&self.path, &servers);
        }
        removed
    }
}

// ── Persistence helpers ────────────────────────────────────────────

/// Load a JSON file containing an array of items into a HashMap keyed by name.
fn load_json_map<T>(path: &PathBuf, key_fn: fn(&T) -> String) -> HashMap<String, T>
where
    T: serde::de::DeserializeOwned,
{
    match std::fs::read_to_string(path) {
        Ok(data) => match serde_json::from_str::<Vec<T>>(&data) {
            Ok(items) => items.into_iter().map(|item| (key_fn(&item), item)).collect(),
            Err(e) => {
                warn!(path = %path.display(), error = %e, "failed to parse persisted data, starting empty");
                HashMap::new()
            }
        },
        Err(_) => HashMap::new(),
    }
}

/// Persist a HashMap of items to a JSON file (array of values).
fn persist_json<T: Serialize>(path: &PathBuf, map: &HashMap<String, T>) {
    let items: Vec<&T> = map.values().collect();
    match serde_json::to_string_pretty(&items) {
        Ok(data) => {
            if let Some(parent) = path.parent() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    warn!(path = %parent.display(), error = %e, "failed to create data directory");
                    return;
                }
            }
            if let Err(e) = std::fs::write(path, data) {
                warn!(path = %path.display(), error = %e, "failed to persist data");
            }
        }
        Err(e) => {
            warn!(error = %e, "failed to serialize data for persistence");
        }
    }
}
