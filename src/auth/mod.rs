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
    /// Returns one or more (header-name, header-value) pairs to inject.
    async fn get_auth_headers(&self) -> Result<Vec<(String, String)>>;

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
    let primary: Arc<dyn AuthStrategy> = match auth_config.method {
        AuthMethod::Static => {
            let credential_ref = auth_config
                .credential_ref
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("static auth requires credential_ref"))?
                .clone();

            Arc::new(static_token::StaticTokenAuth::new(
                auth_config.header.clone(),
                auth_config.prefix.clone(),
                credential_ref,
                credential_provider.clone(),
            ))
        }
        AuthMethod::OAuth => {
            let oauth_config = auth_config
                .oauth
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("oauth auth requires [upstream.auth.oauth] section"))?;

            Arc::new(oauth::OAuthAuth::new(
                upstream_name.to_string(),
                auth_config.header.clone(),
                oauth_config,
                credential_provider.clone(),
                token_storage,
            )?)
        }
    };

    if auth_config.extra_headers.is_empty() {
        return Ok(primary);
    }

    // Wrap primary with extra static-token headers
    let mut extras: Vec<Arc<dyn AuthStrategy>> = Vec::new();
    for eh in &auth_config.extra_headers {
        extras.push(Arc::new(static_token::StaticTokenAuth::new(
            eh.header.clone(),
            eh.prefix.clone(),
            eh.credential_ref.clone(),
            credential_provider.clone(),
        )));
    }

    Ok(Arc::new(CompositeAuth { primary, extras }))
}

/// Combines a primary auth strategy with additional static-token headers.
struct CompositeAuth {
    primary: Arc<dyn AuthStrategy>,
    extras: Vec<Arc<dyn AuthStrategy>>,
}

#[async_trait]
impl AuthStrategy for CompositeAuth {
    async fn get_auth_headers(&self) -> Result<Vec<(String, String)>> {
        let mut headers = self.primary.get_auth_headers().await?;
        for extra in &self.extras {
            headers.extend(extra.get_auth_headers().await?);
        }
        Ok(headers)
    }

    async fn handle_unauthorized(&self) -> Result<()> {
        self.primary.handle_unauthorized().await?;
        for extra in &self.extras {
            extra.handle_unauthorized().await?;
        }
        Ok(())
    }
}
