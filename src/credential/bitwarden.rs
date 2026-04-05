use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::process::Command;
use tracing::{debug, warn};

use super::CredentialProvider;

/// Bitwarden credential provider using the `bw` CLI.
///
/// Supports:
/// - API key login via `BW_CLIENTID` + `BW_CLIENTSECRET` env vars
/// - Session token via `BW_SESSION` env var
/// - Interactive unlock
///
/// References are item search terms (name, ID, or URI).
pub struct BitwardenProvider;

impl BitwardenProvider {
    pub fn new() -> Self {
        Self
    }

    /// Ensure the vault is unlocked and return the session token.
    async fn get_session(&self) -> Result<Option<String>> {
        // Check if BW_SESSION is already set
        if let Ok(session) = std::env::var("BW_SESSION") {
            if !session.is_empty() {
                return Ok(Some(session));
            }
        }

        // Check vault status
        let output = Command::new("bw")
            .arg("status")
            .output()
            .await
            .context("failed to execute `bw` CLI — is Bitwarden CLI installed?")?;

        let status_str = String::from_utf8_lossy(&output.stdout);

        if status_str.contains("\"unauthenticated\"") {
            // Try API key login if env vars are set
            if std::env::var("BW_CLIENTID").is_ok() && std::env::var("BW_CLIENTSECRET").is_ok() {
                let login_output = Command::new("bw")
                    .args(["login", "--apikey"])
                    .output()
                    .await
                    .context("bw login --apikey failed")?;

                if !login_output.status.success() {
                    let stderr = String::from_utf8_lossy(&login_output.stderr);
                    anyhow::bail!("Bitwarden API key login failed: {}", stderr.trim());
                }
            } else {
                anyhow::bail!(
                    "Bitwarden vault is not authenticated. Run `bw login` or set BW_CLIENTID + BW_CLIENTSECRET"
                );
            }
        }

        if status_str.contains("\"locked\"") {
            // Try unlocking with password from env
            if let Ok(password) = std::env::var("BW_PASSWORD") {
                let unlock_output = Command::new("bw")
                    .args(["unlock", "--passwordenv", "BW_PASSWORD", "--raw"])
                    .output()
                    .await
                    .context("bw unlock failed")?;

                if unlock_output.status.success() {
                    let session = String::from_utf8(unlock_output.stdout)
                        .context("bw unlock returned non-UTF-8")?;
                    let session = session.trim().to_string();
                    if !session.is_empty() {
                        return Ok(Some(session));
                    }
                }
                let _ = password; // suppress unused warning
            }

            warn!("Bitwarden vault is locked and no BW_PASSWORD env var set");
            anyhow::bail!(
                "Bitwarden vault is locked. Set BW_PASSWORD env var or run `bw unlock`"
            );
        }

        // Vault is unlocked without a session token (might work for some commands)
        Ok(None)
    }
}

#[async_trait]
impl CredentialProvider for BitwardenProvider {
    async fn resolve(&self, reference: &str) -> Result<String> {
        debug!(reference, "resolving Bitwarden credential");

        let session = self.get_session().await?;

        let mut cmd = Command::new("bw");
        cmd.args(["get", "password", reference]);

        if let Some(ref session_token) = session {
            cmd.args(["--session", session_token]);
        }

        let output = cmd
            .output()
            .await
            .context("failed to execute `bw get password`")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);

            // If "get password" fails, try "get item" and extract the password field
            if stderr.contains("Not found") {
                return self.resolve_item_field(reference, &session).await;
            }

            anyhow::bail!("Bitwarden `bw get password` failed: {}", stderr.trim());
        }

        let secret =
            String::from_utf8(output.stdout).context("Bitwarden returned non-UTF-8 output")?;

        Ok(secret.trim_end().to_string())
    }
}

impl BitwardenProvider {
    /// Fallback: get the full item JSON and extract the password or a custom field.
    /// Reference format: "item-name" or "item-name/field-name"
    async fn resolve_item_field(
        &self,
        reference: &str,
        session: &Option<String>,
    ) -> Result<String> {
        let (item_name, field_name) = if let Some(pos) = reference.rfind('/') {
            (&reference[..pos], Some(&reference[pos + 1..]))
        } else {
            (reference, None)
        };

        let mut cmd = Command::new("bw");
        cmd.args(["get", "item", item_name]);

        if let Some(ref session_token) = session {
            cmd.args(["--session", session_token]);
        }

        let output = cmd
            .output()
            .await
            .context("failed to execute `bw get item`")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Bitwarden `bw get item` failed: {}", stderr.trim());
        }

        let item: serde_json::Value = serde_json::from_slice(&output.stdout)
            .context("failed to parse Bitwarden item JSON")?;

        if let Some(field) = field_name {
            // Look in custom fields
            if let Some(fields) = item["fields"].as_array() {
                for f in fields {
                    if f["name"].as_str() == Some(field) {
                        if let Some(value) = f["value"].as_str() {
                            return Ok(value.to_string());
                        }
                    }
                }
            }
            // Look in login fields
            if let Some(value) = item["login"][field].as_str() {
                return Ok(value.to_string());
            }
            anyhow::bail!(
                "Bitwarden: field '{}' not found in item '{}'",
                field,
                item_name
            );
        }

        // Default to login.password
        item["login"]["password"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("Bitwarden: no password field in item '{}'", item_name))
    }
}
