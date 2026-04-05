use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use async_trait::async_trait;
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::AuthStrategy;
use crate::config::OAuthConfig;
use crate::credential::CredentialProvider;
use crate::storage::TokenStorage;

const TOKEN_EXPIRY_BUFFER: Duration = Duration::from_secs(300); // 5 minutes

/// OAuth 2.1 authentication with Dynamic Client Registration (DCR) and PKCE.
pub struct OAuthAuth {
    upstream_name: String,
    header_name: String,
    config: OAuthConfig,
    http_client: reqwest::Client,
    _credential_provider: Arc<dyn CredentialProvider>,
    token_storage: Arc<dyn TokenStorage>,
    state: RwLock<OAuthState>,
}

struct OAuthState {
    /// Discovered server metadata
    metadata: Option<ServerMetadata>,
    /// DCR client credentials
    client_credentials: Option<ClientCredentials>,
    /// Current access token + expiry
    access_token: Option<CachedAccessToken>,
    /// Refresh token
    refresh_token: Option<String>,
}

struct CachedAccessToken {
    value: String,
    expires_at: Instant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClientCredentials {
    client_id: String,
    client_secret: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ServerMetadata {
    authorization_endpoint: String,
    token_endpoint: String,
    registration_endpoint: Option<String>,
    // issuer, scopes_supported, etc. can be added as needed
}

#[derive(Debug, Serialize)]
struct DcrRequest {
    client_name: String,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    token_endpoint_auth_method: String,
}

#[derive(Debug, Deserialize)]
struct DcrResponse {
    client_id: String,
    client_secret: Option<String>,
}

impl OAuthAuth {
    pub fn new(
        upstream_name: String,
        header_name: String,
        config: &OAuthConfig,
        credential_provider: Arc<dyn CredentialProvider>,
        token_storage: Arc<dyn TokenStorage>,
    ) -> Result<Self> {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("failed to create HTTP client for OAuth")?;

        Ok(Self {
            upstream_name,
            header_name,
            config: OAuthConfig {
                server_url: config.server_url.clone(),
                scopes: config.scopes.clone(),
                redirect_port: config.redirect_port,
                client_name: config.client_name.clone(),
            },
            http_client,
            _credential_provider: credential_provider,
            token_storage,
            state: RwLock::new(OAuthState {
                metadata: None,
                client_credentials: None,
                access_token: None,
                refresh_token: None,
            }),
        })
    }

    fn storage_key(&self, suffix: &str) -> String {
        format!("oauth_{}_{}", self.upstream_name, suffix)
    }

    /// Discover OAuth server metadata from well-known endpoint.
    async fn discover(&self) -> Result<ServerMetadata> {
        let well_known_url = format!(
            "{}/.well-known/oauth-authorization-server",
            self.config.server_url.trim_end_matches('/')
        );

        debug!(url = %well_known_url, "discovering OAuth server metadata");

        let resp = self
            .http_client
            .get(&well_known_url)
            .send()
            .await
            .context("OAuth discovery request failed")?;

        if !resp.status().is_success() {
            anyhow::bail!(
                "OAuth discovery failed with status {}: {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            );
        }

        let metadata: ServerMetadata = resp
            .json()
            .await
            .context("failed to parse OAuth server metadata")?;

        debug!(
            auth_endpoint = %metadata.authorization_endpoint,
            token_endpoint = %metadata.token_endpoint,
            has_registration = metadata.registration_endpoint.is_some(),
            "OAuth discovery complete"
        );

        Ok(metadata)
    }

    /// Perform Dynamic Client Registration.
    async fn register_client(&self, metadata: &ServerMetadata) -> Result<ClientCredentials> {
        let registration_endpoint = metadata
            .registration_endpoint
            .as_ref()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "OAuth server does not support Dynamic Client Registration (no registration_endpoint)"
                )
            })?;

        let redirect_uri = format!("http://127.0.0.1:{}/callback", self.config.redirect_port);

        let dcr_request = DcrRequest {
            client_name: self.config.client_name.clone(),
            redirect_uris: vec![redirect_uri],
            grant_types: vec!["authorization_code".to_string(), "refresh_token".to_string()],
            token_endpoint_auth_method: "client_secret_post".to_string(),
        };

        debug!(endpoint = %registration_endpoint, "performing Dynamic Client Registration");

        let resp = self
            .http_client
            .post(registration_endpoint)
            .json(&dcr_request)
            .send()
            .await
            .context("DCR request failed")?;

        if !resp.status().is_success() {
            anyhow::bail!(
                "DCR failed with status {}: {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            );
        }

        let dcr_resp: DcrResponse = resp.json().await.context("failed to parse DCR response")?;

        let creds = ClientCredentials {
            client_id: dcr_resp.client_id,
            client_secret: dcr_resp.client_secret,
        };

        // Persist DCR credentials
        let creds_json =
            serde_json::to_string(&creds).context("failed to serialize DCR credentials")?;
        self.token_storage
            .set(&self.storage_key("client"), &creds_json)
            .await
            .context("failed to store DCR credentials")?;

        info!(client_id = %creds.client_id, "DCR registration successful");

        Ok(creds)
    }

    /// Run the full PKCE authorization code flow.
    async fn authorize(
        &self,
        metadata: &ServerMetadata,
        client_creds: &ClientCredentials,
    ) -> Result<(String, Option<String>, Option<Duration>)> {
        let redirect_uri = format!("http://127.0.0.1:{}/callback", self.config.redirect_port);

        let mut client_builder = BasicClient::new(ClientId::new(client_creds.client_id.clone()))
            .set_auth_uri(AuthUrl::new(metadata.authorization_endpoint.clone())?)
            .set_token_uri(TokenUrl::new(metadata.token_endpoint.clone())?)
            .set_redirect_uri(RedirectUrl::new(redirect_uri)?);

        if let Some(ref secret) = client_creds.client_secret {
            client_builder = client_builder.set_client_secret(ClientSecret::new(secret.clone()));
        }

        let client = client_builder;

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let mut auth_request = client
            .authorize_url(CsrfToken::new_random);

        for scope in &self.config.scopes {
            auth_request = auth_request.add_scope(Scope::new(scope.clone()));
        }

        let (auth_url, csrf_state) = auth_request
            .set_pkce_challenge(pkce_challenge)
            .url();

        // Open browser for authorization
        info!(url = %auth_url, "opening browser for OAuth authorization");

        if open::that(auth_url.as_str()).is_err() {
            eprintln!("\n=== OAuth Authorization Required ===");
            eprintln!("Open this URL in your browser:");
            eprintln!("{}", auth_url);
            eprintln!("====================================\n");
        }

        // Start local callback listener
        let (code, received_state) = Self::wait_for_callback(self.config.redirect_port).await?;

        // Verify CSRF state
        if received_state != *csrf_state.secret() {
            anyhow::bail!("OAuth CSRF state mismatch — possible attack");
        }

        // Exchange code for tokens
        let token_result = client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(pkce_verifier)
            .request_async(&self.http_client)
            .await
            .map_err(|e| anyhow::anyhow!("token exchange failed: {}", e))?;

        let access_token = token_result.access_token().secret().clone();
        let refresh_token = token_result.refresh_token().map(|t| t.secret().clone());
        let expires_in = token_result.expires_in();

        // Persist refresh token
        if let Some(ref rt) = refresh_token {
            self.token_storage
                .set(&self.storage_key("refresh_token"), rt)
                .await
                .context("failed to store refresh token")?;
        }

        info!("OAuth authorization successful");

        Ok((access_token, refresh_token, expires_in))
    }

    /// Listen for the OAuth callback on a local port.
    async fn wait_for_callback(port: u16) -> Result<(String, String)> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
            .await
            .with_context(|| format!("failed to bind OAuth callback listener on port {}", port))?;

        debug!(port, "waiting for OAuth callback");

        let (mut stream, _addr) = listener
            .accept()
            .await
            .context("failed to accept OAuth callback connection")?;

        let mut buf = vec![0u8; 4096];
        let n = stream
            .read(&mut buf)
            .await
            .context("failed to read OAuth callback")?;

        let request = String::from_utf8_lossy(&buf[..n]);

        // Parse the GET request to extract code and state
        let first_line = request
            .lines()
            .next()
            .ok_or_else(|| anyhow::anyhow!("empty callback request"))?;

        let path = first_line
            .split_whitespace()
            .nth(1)
            .ok_or_else(|| anyhow::anyhow!("malformed callback request"))?;

        let url = url::Url::parse(&format!("http://127.0.0.1{}", path))
            .context("failed to parse callback URL")?;

        let code = url
            .query_pairs()
            .find(|(k, _)| k == "code")
            .map(|(_, v)| v.to_string())
            .ok_or_else(|| anyhow::anyhow!("OAuth callback missing 'code' parameter"))?;

        let state = url
            .query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.to_string())
            .ok_or_else(|| anyhow::anyhow!("OAuth callback missing 'state' parameter"))?;

        // Send success response to browser
        let response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n\
            <html><body><h1>Authorization successful!</h1>\
            <p>You can close this window and return to mcp-auth-proxy.</p></body></html>";

        let _ = stream.write_all(response.as_bytes()).await;

        Ok((code, state))
    }

    /// Refresh the access token using the refresh token.
    async fn refresh_access_token(
        &self,
        metadata: &ServerMetadata,
        client_creds: &ClientCredentials,
        refresh_token: &str,
    ) -> Result<(String, Option<String>, Option<Duration>)> {
        let mut client_builder = BasicClient::new(ClientId::new(client_creds.client_id.clone()))
            .set_token_uri(TokenUrl::new(metadata.token_endpoint.clone())?);

        if let Some(ref secret) = client_creds.client_secret {
            client_builder = client_builder.set_client_secret(ClientSecret::new(secret.clone()));
        }

        let client = client_builder;

        debug!("refreshing OAuth access token");

        let token_result = client
            .exchange_refresh_token(&oauth2::RefreshToken::new(refresh_token.to_string()))
            .request_async(&self.http_client)
            .await
            .map_err(|e| anyhow::anyhow!("token refresh failed: {}", e))?;

        let access_token = token_result.access_token().secret().clone();
        let new_refresh_token = token_result.refresh_token().map(|t| t.secret().clone());
        let expires_in = token_result.expires_in();

        // Update stored refresh token if a new one was provided
        if let Some(ref rt) = new_refresh_token {
            self.token_storage
                .set(&self.storage_key("refresh_token"), rt)
                .await
                .context("failed to store new refresh token")?;
        }

        Ok((access_token, new_refresh_token, expires_in))
    }

    /// Ensure we have a valid access token, refreshing or re-authorizing as needed.
    async fn ensure_token(&self) -> Result<String> {
        // Check if current token is still valid
        {
            let state = self.state.read().await;
            if let Some(ref token) = state.access_token {
                if token.expires_at > Instant::now() {
                    return Ok(token.value.clone());
                }
            }
        }

        // Need to refresh or authorize
        let mut state = self.state.write().await;

        // Double-check after acquiring write lock
        if let Some(ref token) = state.access_token {
            if token.expires_at > Instant::now() {
                return Ok(token.value.clone());
            }
        }

        // Ensure metadata is discovered
        if state.metadata.is_none() {
            state.metadata = Some(self.discover().await?);
        }
        let metadata = state.metadata.clone().unwrap();

        // Ensure we have client credentials (from storage or DCR)
        if state.client_credentials.is_none() {
            // Try loading from storage
            if let Some(creds_json) = self
                .token_storage
                .get(&self.storage_key("client"))
                .await?
            {
                let creds: ClientCredentials = serde_json::from_str(&creds_json)
                    .context("failed to parse stored DCR credentials")?;
                state.client_credentials = Some(creds);
            } else {
                // Perform DCR
                let creds = self.register_client(&metadata).await?;
                state.client_credentials = Some(creds);
            }
        }
        let client_creds = state.client_credentials.clone().unwrap();

        // Try refresh first if we have a refresh token
        if state.refresh_token.is_none() {
            // Try loading from storage
            if let Some(rt) = self
                .token_storage
                .get(&self.storage_key("refresh_token"))
                .await?
            {
                state.refresh_token = Some(rt);
            }
        }

        let result = if let Some(ref rt) = state.refresh_token {
            match self
                .refresh_access_token(&metadata, &client_creds, rt)
                .await
            {
                Ok(result) => result,
                Err(e) => {
                    warn!(error = %e, "token refresh failed, falling back to full authorization");
                    // Clear stale refresh token
                    state.refresh_token = None;
                    let _ = self
                        .token_storage
                        .delete(&self.storage_key("refresh_token"))
                        .await;
                    // Full authorization flow
                    self.authorize(&metadata, &client_creds).await?
                }
            }
        } else {
            // Full authorization flow
            self.authorize(&metadata, &client_creds).await?
        };

        let (access_token, refresh_token, expires_in) = result;

        // Update state
        let expires_at = Instant::now()
            + expires_in.unwrap_or(Duration::from_secs(3600))
            - TOKEN_EXPIRY_BUFFER;

        state.access_token = Some(CachedAccessToken {
            value: access_token.clone(),
            expires_at,
        });

        if let Some(rt) = refresh_token {
            state.refresh_token = Some(rt);
        }

        Ok(access_token)
    }
}

#[async_trait]
impl AuthStrategy for OAuthAuth {
    async fn get_auth_headers(&self) -> Result<Vec<(String, String)>> {
        let access_token = self.ensure_token().await?;
        let value = format!("Bearer {}", access_token);
        Ok(vec![(self.header_name.clone(), value)])
    }

    async fn handle_unauthorized(&self) -> Result<()> {
        debug!("upstream returned 401 — clearing cached OAuth token");
        let mut state = self.state.write().await;
        state.access_token = None;
        Ok(())
    }
}
