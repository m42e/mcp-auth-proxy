use anyhow::{Context, Result};
use async_trait::async_trait;

use super::TokenStorage;

const SERVICE_NAME: &str = "mcp-auth-proxy";

/// OS keychain-backed token storage using the `keyring` crate.
/// Uses macOS Keychain, Windows Credential Manager, or Linux secret-service.
pub struct KeychainStorage {
    // Verify keychain access works on construction
    _verified: (),
}

impl KeychainStorage {
    pub fn new() -> Result<Self> {
        // Test keychain access by creating a probe entry
        let entry = keyring::Entry::new(SERVICE_NAME, "__probe__")
            .context("failed to create keyring entry — OS keychain may not be available")?;

        // Try a get (will return NotFound, which is fine — we just need no platform error)
        match entry.get_password() {
            Ok(_) | Err(keyring::Error::NoEntry) => {}
            Err(e) => {
                anyhow::bail!("OS keychain not available: {}", e);
            }
        }

        Ok(Self { _verified: () })
    }

    fn entry(key: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(SERVICE_NAME, key).context("failed to create keyring entry")
    }
}

#[async_trait]
impl TokenStorage for KeychainStorage {
    async fn get(&self, key: &str) -> Result<Option<String>> {
        let key = key.to_string();
        tokio::task::spawn_blocking(move || {
            let entry = Self::entry(&key)?;
            match entry.get_password() {
                Ok(value) => Ok(Some(value)),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(anyhow::anyhow!("keychain get failed: {}", e)),
            }
        })
        .await
        .context("keychain task panicked")?
    }

    async fn set(&self, key: &str, value: &str) -> Result<()> {
        let key = key.to_string();
        let value = value.to_string();
        tokio::task::spawn_blocking(move || {
            let entry = Self::entry(&key)?;
            entry
                .set_password(&value)
                .context("keychain set failed")?;
            Ok(())
        })
        .await
        .context("keychain task panicked")?
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let key = key.to_string();
        tokio::task::spawn_blocking(move || {
            let entry = Self::entry(&key)?;
            match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(anyhow::anyhow!("keychain delete failed: {}", e)),
            }
        })
        .await
        .context("keychain task panicked")?
    }
}
