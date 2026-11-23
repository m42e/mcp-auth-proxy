use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::Value;
use tokio::process::Command;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use super::CredentialProvider;

/// Bitwarden credential provider using the `bw` CLI.
///
/// Supports:
/// - API key login via `BW_CLIENTID` + `BW_CLIENTSECRET` env vars
/// - Session token via `BW_SESSION` env var
/// - Unlock via `BW_PASSWORD` env var
///
/// References are item search terms (name, ID, or URI).
#[derive(Default)]
pub struct BitwardenProvider {
    cached_session: Mutex<Option<String>>,
}

impl BitwardenProvider {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ensure the vault is unlocked and return the session token.
    async fn get_session(&self) -> Result<Option<String>> {
        // Prefer explicit BW_SESSION env var if set
        if let Ok(session) = std::env::var("BW_SESSION") {
            if !session.is_empty() {
                return Ok(Some(session));
            }
        }

        {
            let cached = self.cached_session.lock().await;
            if let Some(ref session) = *cached {
                return Ok(Some(session.clone()));
            }
        }

        // Check vault status
        let output = Command::new("bw")
            .arg("status")
            .output()
            .await
            .context("failed to execute `bw` CLI — is Bitwarden CLI installed?")?;

        let status = parse_bw_status(&output.stdout)?;

        if status == "unauthenticated" {
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

        if status == "unauthenticated" || status == "locked" {
            // Try unlocking with password from env
            if std::env::var("BW_PASSWORD").is_ok_and(|p| !p.is_empty()) {
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
                        *self.cached_session.lock().await = Some(session.clone());
                        return Ok(Some(session));
                    }
                }
            }

            warn!("Bitwarden vault is locked and no BW_PASSWORD env var set");
            anyhow::bail!("Bitwarden vault is locked. Set BW_PASSWORD env var or run `bw unlock`");
        }

        // Vault is unlocked without a session token
        Ok(None)
    }

    async fn resolve_once(&self, reference: &str, session: Option<&str>) -> Result<String> {
        let mut cmd = Command::new("bw");
        cmd.args(["get", "password", "--", reference]);
        if let Some(session_token) = session {
            cmd.env("BW_SESSION", session_token);
        }

        let output = cmd
            .output()
            .await
            .context("failed to execute `bw get password`")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);

            // If "get password" fails, try "get item" and extract the password field
            if stderr.contains("Not found") {
                return self.resolve_item_field(reference, session).await;
            }

            anyhow::bail!("Bitwarden `bw get password` failed: {}", stderr.trim());
        }

        let secret =
            String::from_utf8(output.stdout).context("Bitwarden returned non-UTF-8 output")?;

        Ok(secret.trim_end_matches(&['\r', '\n'][..]).to_string())
    }
}

#[async_trait]
impl CredentialProvider for BitwardenProvider {
    async fn resolve(&self, reference: &str) -> Result<String> {
        let reference = reference.trim();
        if reference.is_empty() {
            anyhow::bail!("Bitwarden reference cannot be empty");
        }
        debug!(reference, "resolving Bitwarden credential");

        let session = self.get_session().await?;
        match self.resolve_once(reference, session.as_deref()).await {
            Ok(secret) => Ok(secret),
            Err(err) if session.is_some() && std::env::var("BW_SESSION").is_err() => {
                // Cached session may have locked/expired; clear cache and retry once.
                *self.cached_session.lock().await = None;
                let fresh_session = self.get_session().await?;
                self.resolve_once(reference, fresh_session.as_deref())
                    .await
                    .or(Err(err))
            }
            Err(err) => Err(err),
        }
    }
}

impl BitwardenProvider {
    /// Fallback: get the full item JSON and extract the password or a custom field.
    /// Reference format: "item-name" or "item-name/field-name"
    async fn resolve_item_field(&self, reference: &str, session: Option<&str>) -> Result<String> {
        let (item_name, field_name) = if let Some(pos) = reference.rfind('/') {
            (&reference[..pos], Some(&reference[pos + 1..]))
        } else {
            (reference, None)
        };

        let mut cmd = Command::new("bw");
        cmd.args(["get", "item", "--", item_name]);
        if let Some(session_token) = session {
            cmd.env("BW_SESSION", session_token);
        }

        let output = cmd
            .output()
            .await
            .context("failed to execute `bw get item`")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Bitwarden `bw get item` failed: {}", stderr.trim());
        }

        let item: Value = serde_json::from_slice(&output.stdout)
            .context("failed to parse Bitwarden item JSON")?;
        extract_item_field(&item, item_name, field_name)
    }
}

fn parse_bw_status(stdout: &[u8]) -> Result<String> {
    let parsed: Value =
        serde_json::from_slice(stdout).context("failed to parse `bw status` JSON output")?;
    parsed
        .get("status")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("`bw status` output missing 'status' field"))
}

fn extract_item_field(item: &Value, item_name: &str, field_name: Option<&str>) -> Result<String> {
    if let Some(field) = field_name {
        if let Some(fields) = item["fields"].as_array() {
            for f in fields {
                if f["name"].as_str() == Some(field) {
                    if let Some(value) = f["value"].as_str() {
                        return Ok(value.to_string());
                    }
                }
            }
        }
        if let Some(value) = item["login"][field].as_str() {
            return Ok(value.to_string());
        }
        anyhow::bail!(
            "Bitwarden: field '{}' not found in item '{}'",
            field,
            item_name
        );
    }

    item["login"]["password"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("Bitwarden: no password field in item '{}'", item_name))
}

#[cfg(test)]
mod tests {
    use super::{extract_item_field, parse_bw_status};
    use serde_json::json;

    #[test]
    fn parses_bw_status_json() {
        assert_eq!(
            parse_bw_status(br#"{"status":"locked"}"#).unwrap(),
            "locked"
        );
        assert_eq!(
            parse_bw_status(br#"{"status":"unlocked","userEmail":"a@b"}"#).unwrap(),
            "unlocked"
        );
        assert!(parse_bw_status(b"not-json").is_err());
    }

    #[test]
    fn extracts_custom_and_login_fields() {
        let item = json!({
            "login": { "password": "pw ", "username": "alice" },
            "fields": [{ "name": "api_key", "value": "secret-123" }]
        });
        assert_eq!(extract_item_field(&item, "myitem", None).unwrap(), "pw ");
        assert_eq!(
            extract_item_field(&item, "myitem", Some("api_key")).unwrap(),
            "secret-123"
        );
        assert_eq!(
            extract_item_field(&item, "myitem", Some("username")).unwrap(),
            "alice"
        );
    }
}
