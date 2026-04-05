pub mod oauth;
pub mod static_token;

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

use crate::config::{AuthConfig, AuthMethod};
use crate::credential::CredentialProvider;
use crate::storage::TokenStorage;

/// Trait for applying authentication to outgoing requests.
#[async_trait]
pub trait AuthStrategy: Send + Sync {
    /// Apply authentication headers/credentials to the given header map.
    /// Returns the header name and value to inject.
    async fn get_auth_header(&self) -> Result<(String, String)>;

    /// Called when upstream returns 401 — gives the strategy a chance to refresh.
    async fn handle_unauthorized(&self) -> Result<()>;
}

/// Create an auth strategy from config.
pub fn create_auth_strategy(
    auth_config: &AuthConfig,
    upstream_name: &str,
    credential_provider: Arc<dyn CredentialProvider>,
    token_storage: Arc<dyn TokenStorage>,
) -> Result<Arc<dyn AuthStrategy>> {
    match auth_config.method {
        AuthMethod::Static => {
            let credential_ref = auth_config
                .credential_ref
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("static auth requires credential_ref"))?
                .clone();

            Ok(Arc::new(static_token::StaticTokenAuth::new(
                auth_config.header.clone(),
                auth_config.prefix.clone(),
                credential_ref,
                credential_provider,
            )))
        }
        AuthMethod::OAuth => {
            let oauth_config = auth_config
                .oauth
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("oauth auth requires [upstream.auth.oauth] section"))?;

            Ok(Arc::new(oauth::OAuthAuth::new(
                upstream_name.to_string(),
                auth_config.header.clone(),
                oauth_config,
                credential_provider,
                token_storage,
            )?))
        }
    }
}
