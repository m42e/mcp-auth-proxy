use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(rename = "upstream")]
    pub upstreams: Vec<UpstreamConfig>,
    pub credential_provider: CredentialProviderConfig,
    #[serde(default)]
    pub token_storage: TokenStorageConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    3100
}

#[derive(Debug, Deserialize)]
pub struct UpstreamConfig {
    pub name: String,
    pub path_prefix: String,
    #[serde(default = "default_transport")]
    pub transport: TransportType,
    #[serde(default)]
    pub log_mcp_traffic: bool,
    /// URL for HTTP upstream
    pub url: Option<String>,
    /// Command for stdio upstream
    pub command: Option<String>,
    /// Arguments for stdio upstream command
    #[serde(default)]
    pub args: Vec<String>,
    /// Environment variables for stdio upstream
    #[serde(default)]
    pub env: std::collections::HashMap<String, String>,
    pub auth: AuthConfig,
}

fn default_transport() -> TransportType {
    TransportType::Http
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TransportType {
    Http,
    Stdio,
}

#[derive(Debug, Deserialize)]
pub struct AuthConfig {
    pub method: AuthMethod,
    /// HTTP header name for token injection (default: "Authorization")
    #[serde(default = "default_auth_header")]
    pub header: String,
    /// Prefix prepended to the token value (e.g. "Bearer")
    pub prefix: Option<String>,
    /// Credential reference resolved via the credential provider (for static auth)
    pub credential_ref: Option<String>,
    /// OAuth configuration (for oauth auth)
    pub oauth: Option<OAuthConfig>,
    /// Additional headers to inject, each resolved via the credential provider
    #[serde(default)]
    pub extra_headers: Vec<ExtraHeader>,
}

/// An additional header to inject, resolved via the credential provider.
#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct ExtraHeader {
    pub header: String,
    #[serde(default)]
    pub prefix: Option<String>,
    pub credential_ref: String,
}

fn default_auth_header() -> String {
    "Authorization".to_string()
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    Static,
    OAuth,
}

#[derive(Debug, Deserialize)]
pub struct OAuthConfig {
    /// The OAuth authorization server URL (used for discovery)
    pub server_url: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Local port for the OAuth callback listener
    #[serde(default = "default_redirect_port")]
    pub redirect_port: u16,
    /// Client name for DCR
    #[serde(default = "default_client_name")]
    pub client_name: String,
}

fn default_redirect_port() -> u16 {
    8765
}

fn default_client_name() -> String {
    "mcp-auth-proxy".to_string()
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum CredentialProviderConfig {
    #[serde(rename = "onepassword")]
    OnePassword {},
    Bitwarden {},
    #[serde(rename = "keepass")]
    KeePass {
        database_path: PathBuf,
        /// Environment variable name containing the master password
        #[serde(default = "default_keepass_password_env")]
        password_env: String,
        key_file: Option<PathBuf>,
    },
}

fn default_keepass_password_env() -> String {
    "KEEPASS_PASSWORD".to_string()
}

// OnePassword and Bitwarden are configured via environment variables:
// - 1Password: OP_SERVICE_ACCOUNT_TOKEN or interactive `op` CLI
// - Bitwarden: BW_SESSION / BW_CLIENTID + BW_CLIENTSECRET env vars

#[derive(Debug, Deserialize)]
pub struct TokenStorageConfig {
    #[serde(default = "default_storage_type")]
    #[serde(rename = "type")]
    pub storage_type: StorageType,
    /// Fallback storage type if primary is unavailable
    pub fallback: Option<StorageType>,
    pub encrypted_file: Option<EncryptedFileConfig>,
}

impl Default for TokenStorageConfig {
    fn default() -> Self {
        Self {
            storage_type: StorageType::Keychain,
            fallback: Some(StorageType::EncryptedFile),
            encrypted_file: None,
        }
    }
}

fn default_storage_type() -> StorageType {
    StorageType::Keychain
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StorageType {
    Keychain,
    EncryptedFile,
}

#[derive(Debug, Deserialize)]
pub struct EncryptedFileConfig {
    pub path: Option<PathBuf>,
}

impl Config {
    pub fn validate(&self) -> anyhow::Result<()> {
        for upstream in &self.upstreams {
            if !upstream.path_prefix.starts_with('/') {
                anyhow::bail!(
                    "upstream '{}': path_prefix must start with '/'",
                    upstream.name
                );
            }
            match upstream.transport {
                TransportType::Http => {
                    if upstream.url.is_none() {
                        anyhow::bail!(
                            "upstream '{}': HTTP transport requires 'url' field",
                            upstream.name
                        );
                    }
                }
                TransportType::Stdio => {
                    if upstream.command.is_none() {
                        anyhow::bail!(
                            "upstream '{}': stdio transport requires 'command' field",
                            upstream.name
                        );
                    }
                }
            }
            match upstream.auth.method {
                AuthMethod::Static => {
                    if upstream.auth.credential_ref.is_none() {
                        anyhow::bail!(
                            "upstream '{}': static auth requires 'credential_ref'",
                            upstream.name
                        );
                    }
                }
                AuthMethod::OAuth => {
                    if upstream.auth.oauth.is_none() {
                        anyhow::bail!(
                            "upstream '{}': oauth auth requires [upstream.auth.oauth] section",
                            upstream.name
                        );
                    }
                }
            }
        }

        // Check for duplicate path prefixes
        let mut prefixes = std::collections::HashSet::new();
        for upstream in &self.upstreams {
            if !prefixes.insert(&upstream.path_prefix) {
                anyhow::bail!(
                    "duplicate path_prefix '{}' in upstream '{}'",
                    upstream.path_prefix,
                    upstream.name
                );
            }
        }

        Ok(())
    }
}
