use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::process::Command;
use tracing::{debug, warn};

use super::CredentialProvider;

/// 1Password credential provider using the `op` CLI.
///
/// Supports:
/// - Service accounts via `OP_SERVICE_ACCOUNT_TOKEN` env var (zero interaction)
/// - Interactive `op` CLI with biometric unlock
///
/// References use the `op://` format: `op://vault/item/field`
pub struct OnePasswordProvider;

impl OnePasswordProvider {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl CredentialProvider for OnePasswordProvider {
    async fn resolve(&self, reference: &str) -> Result<String> {
        if !reference.starts_with("op://") {
            anyhow::bail!(
                "1Password reference must start with 'op://', got: {}",
                reference
            );
        }

        debug!(reference, "resolving 1Password credential");

        let output = Command::new("op")
            .args(["read", reference, "--no-newline"])
            .output()
            .await
            .context("failed to execute `op` CLI — is 1Password CLI installed?")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("not signed in") || stderr.contains("session expired") {
                warn!("1Password session expired or not signed in");
                anyhow::bail!(
                    "1Password: not signed in. Run `op signin` or set OP_SERVICE_ACCOUNT_TOKEN. Error: {}",
                    stderr.trim()
                );
            }
            anyhow::bail!("1Password `op read` failed: {}", stderr.trim());
        }

        let secret = String::from_utf8(output.stdout)
            .context("1Password returned non-UTF-8 output")?;

        Ok(secret.trim_end().to_string())
    }
}
