pub mod encrypted_file;
pub mod keychain;

use anyhow::Result;
use async_trait::async_trait;
use tracing::warn;

use crate::config::{StorageType, TokenStorageConfig};

/// Trait for persisting OAuth tokens and DCR client credentials.
#[async_trait]
pub trait TokenStorage: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<String>>;
    async fn set(&self, key: &str, value: &str) -> Result<()>;
    async fn delete(&self, key: &str) -> Result<()>;
}

/// Create a token storage from configuration, with fallback support.
pub fn create_storage(config: &TokenStorageConfig) -> Result<Box<dyn TokenStorage>> {
    let primary = create_storage_by_type(&config.storage_type, config);

    match primary {
        Ok(storage) => Ok(storage),
        Err(e) => {
            if let Some(ref fallback_type) = config.fallback {
                warn!(
                    error = %e,
                    "primary token storage ({:?}) unavailable, falling back to {:?}",
                    config.storage_type,
                    fallback_type
                );
                create_storage_by_type(fallback_type, config)
            } else {
                Err(e)
            }
        }
    }
}

fn create_storage_by_type(
    storage_type: &StorageType,
    config: &TokenStorageConfig,
) -> Result<Box<dyn TokenStorage>> {
    match storage_type {
        StorageType::Keychain => {
            let store = keychain::KeychainStorage::new()?;
            Ok(Box::new(store))
        }
        StorageType::EncryptedFile => {
            let path = config
                .encrypted_file
                .as_ref()
                .and_then(|c| c.path.clone())
                .unwrap_or_else(default_encrypted_file_path);
            let store = encrypted_file::EncryptedFileStorage::new(path)?;
            Ok(Box::new(store))
        }
    }
}

fn default_encrypted_file_path() -> std::path::PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("mcp-auth-proxy")
        .join("tokens.enc")
}
