pub mod encrypted_file;
pub mod keychain;

use std::io::Write;
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

pub(crate) fn ensure_private_dir(dir: &Path) -> Result<()> {
    use anyhow::Context;
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .with_context(|| format!("failed to create directory: {}", dir.display()))?;
    Ok(())
}

pub(crate) fn create_private_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub(crate) fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use anyhow::Context;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure_private_dir(parent)?;

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("data.tmp");
    let tmp_path = parent.join(format!(".{file_name}.tmp.{:016x}", rand::random::<u64>()));

    if let Err(err) = create_private_new(&tmp_path, bytes) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err)
            .with_context(|| format!("failed to write temporary file: {}", tmp_path.display()));
    }

    if let Err(err) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err).with_context(|| format!("failed to replace file: {}", path.display()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::expand_tilde;
    use std::path::PathBuf;

    #[cfg(unix)]
    #[test]
    fn private_writes_preserve_existing_dirs_and_secure_new_dirs() {
        use std::os::unix::fs::PermissionsExt;

        let shared = std::env::temp_dir().join(format!(
            "mcp-auth-proxy-permissions-{:016x}",
            rand::random::<u64>()
        ));
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).unwrap();

        super::write_private_atomic(&shared.join("tokens.enc"), b"tokens").unwrap();
        let nested = shared.join("app/nested");
        super::write_private_atomic(&nested.join("tokens.enc"), b"tokens").unwrap();

        let mode =
            |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&shared), 0o755);
        assert_eq!(mode(&shared.join("app")), 0o700);
        assert_eq!(mode(&nested), 0o700);
        assert_eq!(mode(&shared.join("tokens.enc")), 0o600);
        assert_eq!(mode(&nested.join("tokens.enc")), 0o600);
        std::fs::remove_dir_all(shared).unwrap();
    }

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
