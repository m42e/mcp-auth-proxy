pub mod bitwarden;
pub mod keepass_provider;
pub mod onepassword;

use anyhow::Result;
use async_trait::async_trait;

use crate::config::CredentialProviderConfig;

/// Trait for resolving credential references to actual secret values.
#[async_trait]
pub trait CredentialProvider: Send + Sync {
    /// Resolve a credential reference string to its secret value.
    async fn resolve(&self, reference: &str) -> Result<String>;
}

/// Create a credential provider from configuration.
pub fn create_provider(config: &CredentialProviderConfig) -> Result<Box<dyn CredentialProvider>> {
    match config {
        CredentialProviderConfig::OnePassword { .. } => {
            Ok(Box::new(onepassword::OnePasswordProvider::new()))
        }
        CredentialProviderConfig::Bitwarden { .. } => {
            Ok(Box::new(bitwarden::BitwardenProvider::new()))
        }
        CredentialProviderConfig::KeePass {
            database_path,
            password_env,
            key_file,
        } => Ok(Box::new(keepass_provider::KeePassProvider::new(
            database_path.clone(),
            password_env.clone(),
            key_file.clone(),
        ))),
    }
}
