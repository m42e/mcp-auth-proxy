use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{Context, Result};
use async_trait::async_trait;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tracing::warn;

use super::TokenStorage;

const FILE_MAGIC_V2: &[u8; 8] = b"MCPTOK2\0";
const DEFAULT_TOKEN_KEY_ENV: &str = "MCP_AUTH_PROXY_TOKEN_KEY";

/// AES-256-GCM encrypted JSON file for token storage.
/// Uses an explicit environment secret when configured, or a random 256-bit
/// key stored alongside the token file with `0600` permissions on Unix.
pub struct EncryptedFileStorage {
    path: PathBuf,
    cipher: Aes256Gcm,
    state: Mutex<Option<HashMap<String, String>>>,
}

impl EncryptedFileStorage {
    #[allow(dead_code)]
    pub fn new(path: PathBuf) -> Result<Self> {
        Self::with_key_env(path, None)
    }

    pub fn with_key_env(path: PathBuf, key_env: Option<&str>) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                ensure_private_dir(parent)?;
            }
        }

        let key = resolve_or_create_key(&path, key_env)?;
        let cipher = Aes256Gcm::new(&key.into());

        Ok(Self {
            path,
            cipher,
            state: Mutex::new(None),
        })
    }

    async fn load_into_guard<'a>(
        &self,
        guard: &'a mut Option<HashMap<String, String>>,
    ) -> Result<&'a HashMap<String, String>> {
        if guard.is_none() {
            let (data, needs_migration) = self.read_from_disk().await?;
            if needs_migration {
                warn!(
                    path = %self.path.display(),
                    "migrating legacy machine-keyed token storage to v2 key format"
                );
                self.write_to_disk(&data).await?;
            }
            *guard = Some(data);
        }
        Ok(guard.as_ref().expect("populated above"))
    }

    async fn read_from_disk(&self) -> Result<(HashMap<String, String>, bool)> {
        let path = self.path.clone();
        let encrypted = match tokio::fs::read(&path).await {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok((HashMap::new(), false));
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed to read token file: {}", path.display()));
            }
        };

        if encrypted.is_empty() {
            return Ok((HashMap::new(), false));
        }

        if let Some(rest) = encrypted.strip_prefix(FILE_MAGIC_V2) {
            if rest.len() < 12 {
                anyhow::bail!("token file '{}' is truncated or corrupted", path.display());
            }
            let (nonce_bytes, ciphertext) = rest.split_at(12);
            let nonce = Nonce::from_slice(nonce_bytes);
            let plaintext = self.cipher.decrypt(nonce, ciphertext).map_err(|_| {
                anyhow::anyhow!("failed to decrypt token file — key mismatch or corruption")
            })?;
            let data = serde_json::from_slice(&plaintext)
                .context("failed to parse decrypted token data")?;
            return Ok((data, false));
        }

        // Legacy v1 format (no magic header, machine-derived key)
        if encrypted.len() < 12 {
            anyhow::bail!("token file '{}' is truncated or corrupted", path.display());
        }
        let (nonce_bytes, ciphertext) = encrypted.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        let legacy_cipher = Aes256Gcm::new(&derive_legacy_machine_key().into());
        let plaintext = legacy_cipher.decrypt(nonce, ciphertext).map_err(|_| {
            anyhow::anyhow!("failed to decrypt token file — key mismatch or corruption")
        })?;
        let data =
            serde_json::from_slice(&plaintext).context("failed to parse decrypted token data")?;
        Ok((data, true))
    }

    async fn write_to_disk(&self, data: &HashMap<String, String>) -> Result<()> {
        let plaintext = serde_json::to_vec(data).context("failed to serialize token data")?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext.as_slice())
            .map_err(|_| anyhow::anyhow!("failed to encrypt token data"))?;

        let mut out = Vec::with_capacity(FILE_MAGIC_V2.len() + 12 + ciphertext.len());
        out.extend_from_slice(FILE_MAGIC_V2);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);

        let path = self.path.clone();
        tokio::task::spawn_blocking(move || write_private_atomic(&path, &out))
            .await
            .context("token write task panicked")??;

        Ok(())
    }
}

#[async_trait]
impl TokenStorage for EncryptedFileStorage {
    async fn get(&self, key: &str) -> Result<Option<String>> {
        let mut guard = self.state.lock().await;
        let data = self.load_into_guard(&mut guard).await?;
        Ok(data.get(key).cloned())
    }

    async fn set(&self, key: &str, value: &str) -> Result<()> {
        let mut guard = self.state.lock().await;
        let mut next = self.load_into_guard(&mut guard).await?.clone();
        next.insert(key.to_string(), value.to_string());
        self.write_to_disk(&next).await?;
        *guard = Some(next);
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let mut guard = self.state.lock().await;
        let mut next = self.load_into_guard(&mut guard).await?.clone();
        if next.remove(key).is_some() {
            self.write_to_disk(&next).await?;
            *guard = Some(next);
        }
        Ok(())
    }
}

fn resolve_or_create_key(token_path: &Path, key_env: Option<&str>) -> Result<[u8; 32]> {
    if let Some(env_name) = key_env {
        let secret = std::env::var(env_name)
            .with_context(|| format!("token storage key env var '{env_name}' is not set"))?;
        if secret.is_empty() {
            anyhow::bail!("token storage key env var '{env_name}' is empty");
        }
        return Ok(derive_env_key(&secret));
    }

    if let Ok(secret) = std::env::var(DEFAULT_TOKEN_KEY_ENV) {
        if !secret.is_empty() {
            return Ok(derive_env_key(&secret));
        }
    }

    let key_path = key_file_path(token_path);
    match std::fs::read_to_string(&key_path) {
        Ok(encoded) => decode_key_file(&key_path, encoded.trim()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            let encoded = base64::engine::general_purpose::STANDARD.encode(key);
            match create_private_new(&key_path, encoded.as_bytes()) {
                Ok(()) => Ok(key),
                Err(create_err) if create_err.kind() == std::io::ErrorKind::AlreadyExists => {
                    let encoded = std::fs::read_to_string(&key_path).with_context(|| {
                        format!("failed to read token key file: {}", key_path.display())
                    })?;
                    decode_key_file(&key_path, encoded.trim())
                }
                Err(create_err) => Err(create_err).with_context(|| {
                    format!("failed to create token key file: {}", key_path.display())
                }),
            }
        }
        Err(err) => Err(err)
            .with_context(|| format!("failed to read token key file: {}", key_path.display())),
    }
}

fn decode_key_file(key_path: &Path, encoded: &str) -> Result<[u8; 32]> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .with_context(|| format!("invalid base64 in token key file: {}", key_path.display()))?;
    let key: [u8; 32] = raw.try_into().map_err(|_| {
        anyhow::anyhow!(
            "token key file '{}' has invalid key length (expected 32 bytes)",
            key_path.display()
        )
    })?;
    Ok(key)
}

fn key_file_path(token_path: &Path) -> PathBuf {
    let mut os = token_path.as_os_str().to_os_string();
    os.push(".key");
    PathBuf::from(os)
}

fn derive_env_key(secret: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"mcp-auth-proxy-token-key-v2\0");
    hasher.update(secret.as_bytes());
    hasher.finalize().into()
}

fn derive_legacy_machine_key() -> [u8; 32] {
    let mut hasher = Sha256::new();
    if let Ok(hostname) = hostname::get() {
        hasher.update(hostname.as_encoded_bytes());
    }
    hasher.update(whoami::username().as_bytes());
    hasher.update(b"mcp-auth-proxy-token-storage-v1");
    hasher.finalize().into()
}

fn ensure_private_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| {
        format!(
            "failed to create token storage directory: {}",
            dir.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).with_context(
            || format!("failed to set permissions on directory: {}", dir.display()),
        )?;
    }
    Ok(())
}

fn create_private_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
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

fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure_private_dir(parent)?;

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("tokens.enc");
    let tmp_path = parent.join(format!(".{file_name}.tmp.{:016x}", rand::random::<u64>()));

    if let Err(err) = create_private_new(&tmp_path, bytes) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err).with_context(|| {
            format!(
                "failed to write temporary token file: {}",
                tmp_path.display()
            )
        });
    }

    if let Err(err) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err)
            .with_context(|| format!("failed to replace token file: {}", path.display()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        derive_legacy_machine_key, write_private_atomic, EncryptedFileStorage, FILE_MAGIC_V2,
    };
    use crate::storage::TokenStorage;
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mcp-auth-proxy-test-{name}-{:016x}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn roundtrip_and_concurrent_writes_preserve_all_keys() {
        let dir = temp_dir("concurrent");
        let path = dir.join("tokens.enc");
        let storage = Arc::new(EncryptedFileStorage::new(path.clone()).unwrap());

        let mut handles = Vec::new();
        for idx in 0..10 {
            let s = storage.clone();
            handles.push(tokio::spawn(async move {
                s.set(&format!("key-{idx}"), &format!("val-{idx}"))
                    .await
                    .unwrap();
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }

        // Verify persisted on disk by re-opening with the sibling key file
        let reopened = EncryptedFileStorage::new(path.clone()).unwrap();
        for idx in 0..10 {
            assert_eq!(
                reopened
                    .get(&format!("key-{idx}"))
                    .await
                    .unwrap()
                    .as_deref(),
                Some(format!("val-{idx}").as_str())
            );
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            let key_mode = std::fs::metadata(format!("{}.key", path.display()))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(key_mode, 0o600);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn migrates_legacy_v1_file_to_v2() {
        let dir = temp_dir("migrate");
        let path = dir.join("tokens.enc");

        let mut map = HashMap::new();
        map.insert("refresh".to_string(), "rt-legacy".to_string());
        let plaintext = serde_json::to_vec(&map).unwrap();
        let nonce_bytes = [7u8; 12];
        let legacy_cipher = Aes256Gcm::new(&derive_legacy_machine_key().into());
        let ciphertext = legacy_cipher
            .encrypt(&Nonce::from(nonce_bytes), plaintext.as_slice())
            .unwrap();
        let mut legacy_bytes = Vec::new();
        legacy_bytes.extend_from_slice(&nonce_bytes);
        legacy_bytes.extend_from_slice(&ciphertext);
        write_private_atomic(&path, &legacy_bytes).unwrap();

        let storage = EncryptedFileStorage::new(path.clone()).unwrap();
        assert_eq!(
            storage.get("refresh").await.unwrap().as_deref(),
            Some("rt-legacy")
        );

        let migrated = std::fs::read(&path).unwrap();
        assert!(migrated.starts_with(FILE_MAGIC_V2));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn rejects_truncated_corrupted_file_instead_of_silently_resetting() {
        let dir = temp_dir("corrupt");
        let path = dir.join("tokens.enc");
        std::fs::write(&path, b"bad").unwrap();

        let storage = EncryptedFileStorage::new(path.clone()).unwrap();
        assert!(storage.get("anything").await.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
