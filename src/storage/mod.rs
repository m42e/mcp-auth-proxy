pub mod encrypted_file;
pub mod keychain;

use std::path::{Path, PathBuf};

use anyhow::Result;
use async_trait::async_trait;
use tracing::warn;

use crate::config::{StorageType, TokenStorageConfig};

/// Trait for persisting OAuth tokens and DCR client credentials.
#[allow(clippy::double_must_use)]
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
            let encrypted_cfg = config.encrypted_file.as_ref();
            let path = encrypted_cfg
                .and_then(|c| c.path.clone())
                .map(expand_tilde)
                .unwrap_or_else(default_encrypted_file_path);
            let key_env = encrypted_cfg.and_then(|c| c.key_env.as_deref());
            let store = encrypted_file::EncryptedFileStorage::with_key_env(path, key_env)?;
            Ok(Box::new(store))
        }
    }
}

fn expand_tilde(path: PathBuf) -> PathBuf {
    if path == Path::new("~") {
        return dirs::home_dir().unwrap_or(path);
    }
    if let Ok(rest) = path.strip_prefix("~") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    path
}

fn default_encrypted_file_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("mcp-auth-proxy")
        .join("tokens.enc")
}

#[cfg(test)]
mod tests {
    use super::expand_tilde;
    use std::path::PathBuf;

    #[test]
    fn expands_leading_tilde_in_paths() {
        if let Some(home) = dirs::home_dir() {
            assert_eq!(expand_tilde(PathBuf::from("~")), home);
            assert_eq!(
                expand_tilde(PathBuf::from("~/.config/mcp-auth-proxy/tokens.enc")),
                home.join(".config/mcp-auth-proxy/tokens.enc")
            );
        }
        assert_eq!(
            expand_tilde(PathBuf::from("/var/lib/tokens.enc")),
            PathBuf::from("/var/lib/tokens.enc")
        );
    }
}
