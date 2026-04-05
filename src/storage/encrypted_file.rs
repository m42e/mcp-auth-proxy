use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{Context, Result};
use async_trait::async_trait;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::sync::Mutex;

use super::TokenStorage;

/// AES-256-GCM encrypted JSON file for token storage.
/// The encryption key is derived from a machine-specific seed (hostname + username).
pub struct EncryptedFileStorage {
    path: PathBuf,
    cipher: Aes256Gcm,
    // In-memory cache to avoid re-reading file on every access
    cache: Mutex<Option<HashMap<String, String>>>,
}

impl EncryptedFileStorage {
    pub fn new(path: PathBuf) -> Result<Self> {
        // Derive encryption key from machine-specific data
        let key = derive_machine_key();
        let cipher = Aes256Gcm::new(&key.into());

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create token storage directory: {}", parent.display()))?;
        }

        Ok(Self {
            path,
            cipher,
            cache: Mutex::new(None),
        })
    }

    async fn load(&self) -> Result<HashMap<String, String>> {
        let mut cache = self.cache.lock().await;
        if let Some(ref data) = *cache {
            return Ok(data.clone());
        }

        let data = if self.path.exists() {
            let encrypted = tokio::fs::read(&self.path)
                .await
                .with_context(|| format!("failed to read token file: {}", self.path.display()))?;

            if encrypted.len() < 12 {
                // File is corrupted or empty — start fresh
                HashMap::new()
            } else {
                let (nonce_bytes, ciphertext) = encrypted.split_at(12);
                let nonce = Nonce::from_slice(nonce_bytes);

                let plaintext = self
                    .cipher
                    .decrypt(nonce, ciphertext)
                    .map_err(|_| anyhow::anyhow!("failed to decrypt token file — key mismatch or corruption"))?;

                serde_json::from_slice(&plaintext)
                    .context("failed to parse decrypted token data")?
            }
        } else {
            HashMap::new()
        };

        *cache = Some(data.clone());
        Ok(data)
    }

    async fn save(&self, data: &HashMap<String, String>) -> Result<()> {
        let plaintext =
            serde_json::to_vec(data).context("failed to serialize token data")?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext.as_slice())
            .map_err(|_| anyhow::anyhow!("failed to encrypt token data"))?;

        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);

        tokio::fs::write(&self.path, &out)
            .await
            .with_context(|| format!("failed to write token file: {}", self.path.display()))?;

        let mut cache = self.cache.lock().await;
        *cache = Some(data.clone());

        Ok(())
    }
}

#[async_trait]
impl TokenStorage for EncryptedFileStorage {
    async fn get(&self, key: &str) -> Result<Option<String>> {
        let data = self.load().await?;
        Ok(data.get(key).cloned())
    }

    async fn set(&self, key: &str, value: &str) -> Result<()> {
        let mut data = self.load().await?;
        data.insert(key.to_string(), value.to_string());
        self.save(&data).await
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let mut data = self.load().await?;
        data.remove(key);
        self.save(&data).await
    }
}

/// Derive a 256-bit key from machine-specific data.
/// This is NOT a secure key derivation for adversarial scenarios — it protects
/// against casual file access but not determined attackers with local access.
fn derive_machine_key() -> [u8; 32] {
    let mut hasher = Sha256::new();

    // Use hostname
    if let Ok(hostname) = hostname::get() {
        hasher.update(hostname.as_encoded_bytes());
    }

    // Use username
    hasher.update(whoami::username().as_bytes());

    // Static application salt
    hasher.update(b"mcp-auth-proxy-token-storage-v1");

    hasher.finalize().into()
}
