use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::RwLock;
use tracing::debug;

use super::AuthStrategy;
use crate::credential::CredentialProvider;

const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(300); // 5 minutes

/// Static token authentication — resolves a credential once, caches it,
/// and injects it as a configurable HTTP header.
pub struct StaticTokenAuth {
    header_name: String,
    prefix: Option<String>,
    credential_ref: String,
    provider: Arc<dyn CredentialProvider>,
    cached: RwLock<Option<CachedToken>>,
}

struct CachedToken {
    value: String,
    resolved_at: Instant,
}

impl StaticTokenAuth {
    pub fn new(
        header_name: String,
        prefix: Option<String>,
        credential_ref: String,
        provider: Arc<dyn CredentialProvider>,
    ) -> Self {
        Self {
            header_name,
            prefix,
            credential_ref,
            provider,
            cached: RwLock::new(None),
        }
    }

    async fn resolve_token(&self) -> Result<String> {
        let raw = self.provider.resolve(&self.credential_ref).await?;
        let value = if let Some(ref prefix) = self.prefix {
            format!("{} {}", prefix, raw)
        } else {
            raw
        };
        Ok(value)
    }

    async fn get_or_resolve(&self) -> Result<String> {
        // Check cache first (read lock)
        {
            let cache = self.cached.read().await;
            if let Some(ref cached) = *cache {
                if cached.resolved_at.elapsed() < DEFAULT_CACHE_TTL {
                    return Ok(cached.value.clone());
                }
            }
        }

        // Cache miss or expired — resolve and update (write lock)
        let mut cache = self.cached.write().await;

        // Double-check after acquiring write lock
        if let Some(ref cached) = *cache {
            if cached.resolved_at.elapsed() < DEFAULT_CACHE_TTL {
                return Ok(cached.value.clone());
            }
        }

        debug!(credential_ref = %self.credential_ref, "resolving static credential");
        let value = self.resolve_token().await?;

        *cache = Some(CachedToken {
            value: value.clone(),
            resolved_at: Instant::now(),
        });

        Ok(value)
    }
}

#[async_trait]
impl AuthStrategy for StaticTokenAuth {
    async fn get_auth_headers(&self) -> Result<Vec<(String, String)>> {
        let value = self.get_or_resolve().await?;
        Ok(vec![(self.header_name.clone(), value)])
    }

    async fn handle_unauthorized(&self) -> Result<()> {
        // Evict cache so next request re-resolves the credential
        debug!("upstream returned 401 — evicting cached credential");
        let mut cache = self.cached.write().await;
        *cache = None;
        Ok(())
    }
}
