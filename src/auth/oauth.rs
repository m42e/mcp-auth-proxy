use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use async_trait::async_trait;
use oauth2::basic::BasicClient;
use oauth2::{
    AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
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
    resource_url: String,
    http_client: reqwest::Client,
    credential_provider: Arc<dyn CredentialProvider>,
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
    #[serde(default = "default_client_auth_method")]
    token_endpoint_auth_method: String,
}

fn default_client_auth_method() -> String {
    "none".to_string()
}

#[derive(Debug, Clone, Deserialize)]
struct ServerMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    registration_endpoint: Option<String>,
    authorization_response_iss_parameter_supported: Option<bool>,
    #[serde(skip)]
    resource_scopes: Vec<String>,
    #[serde(skip)]
    resource_identifier: String,
}

#[derive(Debug, Deserialize)]
struct ProtectedResourceMetadata {
    resource: String,
    authorization_servers: Vec<String>,
    scopes_supported: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct CallbackResponse {
    code: Option<String>,
    state: Option<String>,
    iss: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct DcrRequest {
    client_name: String,
    application_type: String,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    response_types: Vec<String>,
    token_endpoint_auth_method: String,
}

#[derive(Debug, Deserialize)]
struct DcrResponse {
    client_id: String,
    client_secret: Option<String>,
    #[serde(default)]
    token_endpoint_auth_method: Option<String>,
}

impl OAuthAuth {
    pub fn new(
        upstream_name: String,
        header_name: String,
        config: &OAuthConfig,
        resource_url: String,
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
                client_id: config.client_id.clone(),
                client_secret_ref: config.client_secret_ref.clone(),
                token_endpoint_auth_method: config.token_endpoint_auth_method.clone(),
                scopes: config.scopes.clone(),
                redirect_port: config.redirect_port,
                client_name: config.client_name.clone(),
            },
            resource_url: canonical_resource_url(&resource_url)?,
            http_client,
            credential_provider,
            token_storage,
            state: RwLock::new(OAuthState {
                metadata: None,
                client_credentials: None,
                access_token: None,
                refresh_token: None,
            }),
        })
    }

    fn storage_key(&self, issuer: &str, suffix: &str) -> String {
        use sha2::{Digest, Sha256};

        let issuer_hash = Sha256::digest(issuer.as_bytes());
        let issuer_key = issuer_hash
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("oauth_{}_{}_{}", self.upstream_name, issuer_key, suffix)
    }

    /// Discover and validate OAuth server metadata for the configured issuer.
    async fn discover(&self) -> Result<ServerMetadata> {
        let issuer = self.config.server_url.as_str();
        let (resource_identifier, resource_scopes) =
            self.validate_resource_metadata(issuer).await?;
        let metadata_urls = authorization_metadata_urls(issuer)?;
        let mut last_error = None;
        let mut metadata = None;

        for well_known_url in metadata_urls {
            debug!(url = %well_known_url, issuer, "discovering OAuth server metadata");
            let response = match self.http_client.get(&well_known_url).send().await {
                Ok(response) => response,
                Err(error) => {
                    last_error = Some(error.to_string());
                    continue;
                }
            };
            if response.status() == reqwest::StatusCode::NOT_FOUND
                || response.status() == reqwest::StatusCode::METHOD_NOT_ALLOWED
            {
                continue;
            }
            if !response.status().is_success() {
                last_error = Some(format!(
                    "metadata endpoint returned HTTP {}",
                    response.status()
                ));
                continue;
            }

            match response.json::<ServerMetadata>().await {
                Ok(candidate) if candidate.issuer == issuer => {
                    metadata = Some(candidate);
                    break;
                }
                Ok(candidate) => {
                    anyhow::bail!(
                        "OAuth metadata issuer mismatch: configured '{}', metadata declares '{}'",
                        issuer,
                        candidate.issuer
                    );
                }
                Err(error) => last_error = Some(format!("invalid metadata: {error}")),
            }
        }

        let mut metadata = metadata.ok_or_else(|| {
            anyhow::anyhow!(
                "OAuth metadata discovery failed for issuer '{}': {}",
                issuer,
                last_error.unwrap_or_else(|| "no supported metadata endpoint found".to_string())
            )
        })?;
        metadata.resource_scopes = resource_scopes;
        metadata.resource_identifier = resource_identifier;

        debug!(
            auth_endpoint = %metadata.authorization_endpoint,
            token_endpoint = %metadata.token_endpoint,
            has_registration = metadata.registration_endpoint.is_some(),
            "OAuth discovery complete"
        );

        Ok(metadata)
    }

    async fn validate_resource_metadata(&self, issuer: &str) -> Result<(String, Vec<String>)> {
        let (challenged_metadata_url, challenged_scopes) =
            self.discover_protected_resource_challenge().await;
        let metadata_urls = match challenged_metadata_url {
            Some(url) => vec![validate_metadata_url(&url)?],
            None => protected_resource_metadata_urls(&self.resource_url)?,
        };
        for metadata_url in metadata_urls {
            let response = self
                .http_client
                .get(&metadata_url)
                .send()
                .await
                .with_context(|| {
                    format!("failed to fetch protected resource metadata from {metadata_url}")
                })?;
            if response.status() == reqwest::StatusCode::NOT_FOUND
                || response.status() == reqwest::StatusCode::METHOD_NOT_ALLOWED
            {
                continue;
            }
            if !response.status().is_success() {
                anyhow::bail!(
                    "protected resource metadata request to {} returned HTTP {}",
                    metadata_url,
                    response.status()
                );
            }

            let metadata: ProtectedResourceMetadata = response
                .json()
                .await
                .context("failed to parse protected resource metadata")?;
            let declared_resource = canonical_resource_url(&metadata.resource)?;
            if !resource_is_same_or_parent(&self.resource_url, &declared_resource)? {
                anyhow::bail!(
                    "protected resource metadata identifies '{}', which does not cover '{}'",
                    declared_resource,
                    self.resource_url
                );
            }
            if !metadata
                .authorization_servers
                .iter()
                .any(|authorization_server| authorization_server == issuer)
            {
                anyhow::bail!(
                    "configured OAuth issuer '{}' is not listed by protected resource '{}'",
                    issuer,
                    self.resource_url
                );
            }
            // A scope challenge is authoritative for this resource operation. Otherwise honor
            // explicit config, then fall back to the resource's advertised minimal scopes.
            let scopes = if let Some(challenged_scopes) = challenged_scopes.as_ref() {
                challenged_scopes.clone()
            } else if self.config.scopes.is_empty() {
                metadata.scopes_supported.clone().unwrap_or_default()
            } else {
                self.config.scopes.clone()
            };
            return Ok((declared_resource, scopes));
        }

        anyhow::bail!(
            "protected resource metadata was not found for '{}'",
            self.resource_url
        )
    }

    /// Read the resource metadata URL and scope guidance from the server's Bearer challenge.
    /// The probe is unauthenticated and intentionally best-effort; servers that do not expose a
    /// challenge on GET can still use the standard well-known metadata URLs.
    async fn discover_protected_resource_challenge(&self) -> (Option<String>, Option<Vec<String>>) {
        let response = self
            .http_client
            .get(&self.resource_url)
            .header(
                reqwest::header::ACCEPT,
                "text/event-stream, application/json",
            )
            .timeout(Duration::from_secs(5))
            .send()
            .await;
        let Ok(response) = response else {
            return (None, None);
        };

        parse_bearer_challenge(response.headers())
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
            application_type: "native".to_string(),
            redirect_uris: vec![redirect_uri],
            grant_types: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
            ],
            response_types: vec!["code".to_string()],
            token_endpoint_auth_method: "none".to_string(),
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

        let token_endpoint_auth_method = dcr_resp
            .token_endpoint_auth_method
            .unwrap_or_else(|| "none".to_string());

        let creds = ClientCredentials {
            client_id: dcr_resp.client_id,
            client_secret: (token_endpoint_auth_method != "none")
                .then_some(dcr_resp.client_secret)
                .flatten(),
            token_endpoint_auth_method,
        };

        // Persist DCR credentials
        let creds_json =
            serde_json::to_string(&creds).context("failed to serialize DCR credentials")?;
        self.token_storage
            .set(&self.storage_key(&metadata.issuer, "client"), &creds_json)
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
        if client_creds.token_endpoint_auth_method == "client_secret_post" {
            client_builder = client_builder.set_auth_type(AuthType::RequestBody);
        }

        let client = client_builder;

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let mut auth_request = client
            .authorize_url(CsrfToken::new_random)
            .add_extra_param("resource", metadata.resource_identifier.as_str());

        for scope in &metadata.resource_scopes {
            auth_request = auth_request.add_scope(Scope::new(scope.clone()));
        }

        let (auth_url, csrf_state) = auth_request.set_pkce_challenge(pkce_challenge).url();

        // Bind before opening the browser so a fast redirect cannot beat the listener.
        let callback_listener = Self::bind_callback_listener(self.config.redirect_port).await?;

        // Open browser for authorization
        info!(url = %auth_url, "opening browser for OAuth authorization");

        if open::that(auth_url.as_str()).is_err() {
            eprintln!("\n=== OAuth Authorization Required ===");
            eprintln!("Open this URL in your browser:");
            eprintln!("{}", auth_url);
            eprintln!("====================================\n");
        }

        let callback = Self::wait_for_callback(callback_listener).await?;

        if let Some(response_issuer) = callback.iss.as_deref() {
            if response_issuer != metadata.issuer {
                anyhow::bail!(
                    "OAuth authorization response issuer mismatch: expected '{}', got '{}'",
                    metadata.issuer,
                    response_issuer
                );
            }
        } else if metadata.authorization_response_iss_parameter_supported == Some(true) {
            anyhow::bail!("OAuth authorization response omitted the required 'iss' parameter");
        }

        let received_state = callback
            .state
            .ok_or_else(|| anyhow::anyhow!("OAuth callback missing 'state' parameter"))?;

        // Verify CSRF state
        if received_state != csrf_state.secret() {
            anyhow::bail!("OAuth CSRF state mismatch — possible attack");
        }

        if let Some(error) = callback.error {
            anyhow::bail!("OAuth authorization failed: {error}");
        }
        let code = callback
            .code
            .ok_or_else(|| anyhow::anyhow!("OAuth callback missing 'code' parameter"))?;

        // Exchange code for tokens
        let token_result = client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(pkce_verifier)
            .add_extra_param("resource", metadata.resource_identifier.as_str())
            .request_async(&self.http_client)
            .await
            .map_err(|e| anyhow::anyhow!("token exchange failed: {}", e))?;

        let access_token = token_result.access_token().secret().clone();
        let refresh_token = token_result.refresh_token().map(|t| t.secret().clone());
        let expires_in = token_result.expires_in();

        // Persist refresh token
        if let Some(ref rt) = refresh_token {
            self.token_storage
                .set(&self.storage_key(&metadata.issuer, "refresh_token"), rt)
                .await
                .context("failed to store refresh token")?;
        }

        info!("OAuth authorization successful");

        Ok((access_token, refresh_token, expires_in))
    }

    async fn bind_callback_listener(port: u16) -> Result<tokio::net::TcpListener> {
        tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
            .await
            .with_context(|| format!("failed to bind OAuth callback listener on port {port}"))
    }

    /// Listen for the OAuth callback on a local port.
    async fn wait_for_callback(listener: tokio::net::TcpListener) -> Result<CallbackResponse> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        debug!("waiting for OAuth callback");

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

        let mut request_parts = first_line.split_whitespace();
        let request_method = request_parts.next().unwrap_or_default();
        let path = request_parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("malformed callback request"))?;
        if request_method != "GET" {
            anyhow::bail!("OAuth callback must use GET");
        }

        let url = url::Url::parse(&format!("http://127.0.0.1{path}"))
            .context("failed to parse callback URL")?;

        if url.path() != "/callback" {
            anyhow::bail!("OAuth callback used an unexpected path");
        }

        let mut callback = CallbackResponse {
            code: None,
            state: None,
            iss: None,
            error: None,
        };
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "code" => callback.code = Some(value.into_owned()),
                "state" => callback.state = Some(value.into_owned()),
                "iss" => callback.iss = Some(value.into_owned()),
                "error" => callback.error = Some(value.into_owned()),
                _ => {}
            }
        }

        // Keep the callback response generic; never reflect authorization-server input into HTML.
        let (status, title, message) = if callback.error.is_some() || callback.code.is_none() {
            (
                "400 Bad Request",
                "Authorization failed",
                "Return to mcp-auth-proxy for details.",
            )
        } else {
            (
                "200 OK",
                "Authorization received",
                "You can close this window and return to mcp-auth-proxy.",
            )
        };
        let response = format!("HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n\
            <html><body><h1>{title}</h1><p>{message}</p></body></html>");

        let _ = stream.write_all(response.as_bytes()).await;

        Ok(callback)
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
        if client_creds.token_endpoint_auth_method == "client_secret_post" {
            client_builder = client_builder.set_auth_type(AuthType::RequestBody);
        }

        let client = client_builder;

        debug!("refreshing OAuth access token");

        let token_result = client
            .exchange_refresh_token(&oauth2::RefreshToken::new(refresh_token.to_string()))
            .add_extra_param("resource", metadata.resource_identifier.as_str())
            .request_async(&self.http_client)
            .await
            .map_err(|e| anyhow::anyhow!("token refresh failed: {}", e))?;

        let access_token = token_result.access_token().secret().clone();
        let new_refresh_token = token_result.refresh_token().map(|t| t.secret().clone());
        let expires_in = token_result.expires_in();

        // Update stored refresh token if a new one was provided
        if let Some(ref rt) = new_refresh_token {
            self.token_storage
                .set(&self.storage_key(&metadata.issuer, "refresh_token"), rt)
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
            if let Some(client_id) = self.config.client_id.as_ref() {
                let client_secret = match self.config.client_secret_ref.as_deref() {
                    Some(reference) => Some(self.credential_provider.resolve(reference).await?),
                    None => None,
                };
                let token_endpoint_auth_method = self
                    .config
                    .token_endpoint_auth_method
                    .clone()
                    .unwrap_or_else(|| {
                        if client_secret.is_some() {
                            "client_secret_basic".to_string()
                        } else {
                            "none".to_string()
                        }
                    });
                if !matches!(
                    token_endpoint_auth_method.as_str(),
                    "none" | "client_secret_basic" | "client_secret_post"
                ) {
                    anyhow::bail!(
                        "unsupported OAuth token endpoint auth method '{}'",
                        token_endpoint_auth_method
                    );
                }
                if token_endpoint_auth_method == "none" && client_secret.is_some() {
                    anyhow::bail!(
                        "OAuth client_secret_ref requires client_secret_basic or client_secret_post"
                    );
                }
                if token_endpoint_auth_method != "none" && client_secret.is_none() {
                    anyhow::bail!(
                        "OAuth token endpoint auth method '{}' requires client_secret_ref",
                        token_endpoint_auth_method
                    );
                }
                state.client_credentials = Some(ClientCredentials {
                    client_id: client_id.clone(),
                    client_secret,
                    token_endpoint_auth_method,
                });
            } else {
                // Try loading issuer-bound credentials before performing DCR.
                if let Some(creds_json) = self
                    .token_storage
                    .get(&self.storage_key(&metadata.issuer, "client"))
                    .await?
                {
                    let creds: ClientCredentials = serde_json::from_str(&creds_json)
                        .context("failed to parse stored DCR credentials")?;
                    state.client_credentials = Some(creds);
                } else {
                    let creds = self.register_client(&metadata).await?;
                    state.client_credentials = Some(creds);
                }
            }
        }
        let client_creds = state.client_credentials.clone().unwrap();

        // Try refresh first if we have a refresh token
        if state.refresh_token.is_none() {
            // Try loading from storage
            if let Some(rt) = self
                .token_storage
                .get(&self.storage_key(&metadata.issuer, "refresh_token"))
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
                        .delete(&self.storage_key(&metadata.issuer, "refresh_token"))
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
        let lifetime = expires_in.unwrap_or(Duration::from_secs(3600));
        let expiry_buffer = TOKEN_EXPIRY_BUFFER.min(lifetime / 10);
        let expires_at = Instant::now() + lifetime.saturating_sub(expiry_buffer);

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

fn canonical_resource_url(resource_url: &str) -> Result<String> {
    let parsed = url::Url::parse(resource_url).context("invalid OAuth resource URL")?;
    if parsed.query().is_some() || parsed.fragment().is_some() {
        anyhow::bail!("OAuth resource URL must not contain a query or fragment");
    }
    if parsed.scheme() != "https"
        && !(parsed.scheme() == "http"
            && parsed
                .host_str()
                .and_then(|host| host.parse::<std::net::IpAddr>().ok())
                .is_some_and(|ip| ip.is_loopback()))
        && !(parsed.scheme() == "http" && parsed.host_str() == Some("localhost"))
    {
        anyhow::bail!("OAuth resource URL must use HTTPS, except for a loopback HTTP URL");
    }
    if parsed.host_str().is_none() {
        anyhow::bail!("OAuth resource URL must include a host");
    }

    let mut canonical = parsed.to_string();
    if canonical.ends_with('/') {
        canonical.pop();
    }
    Ok(canonical)
}

fn validate_metadata_url(metadata_url: &str) -> Result<String> {
    let parsed =
        url::Url::parse(metadata_url).context("invalid protected resource metadata URL")?;
    if parsed.fragment().is_some() || parsed.host_str().is_none() {
        anyhow::bail!(
            "protected resource metadata URL must be absolute and must not include a fragment"
        );
    }
    if parsed.scheme() != "https"
        && !(parsed.scheme() == "http"
            && parsed
                .host_str()
                .and_then(|host| host.parse::<std::net::IpAddr>().ok())
                .is_some_and(|ip| ip.is_loopback()))
        && !(parsed.scheme() == "http" && parsed.host_str() == Some("localhost"))
    {
        anyhow::bail!(
            "protected resource metadata URL must use HTTPS, except for a loopback HTTP URL"
        );
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        anyhow::bail!("protected resource metadata URL must not contain credentials");
    }
    Ok(parsed.to_string())
}

fn authorization_metadata_urls(issuer: &str) -> Result<Vec<String>> {
    let parsed = url::Url::parse(issuer).context("invalid OAuth authorization server issuer")?;
    if parsed.query().is_some() || parsed.fragment().is_some() || parsed.host_str().is_none() {
        anyhow::bail!("OAuth issuer must be an absolute URL without query or fragment");
    }
    if parsed.scheme() != "https"
        && !(parsed.scheme() == "http"
            && parsed
                .host_str()
                .and_then(|host| host.parse::<std::net::IpAddr>().ok())
                .is_some_and(|ip| ip.is_loopback()))
        && !(parsed.scheme() == "http" && parsed.host_str() == Some("localhost"))
    {
        anyhow::bail!("OAuth issuer must use HTTPS, except for a loopback HTTP URL");
    }

    let origin = format!(
        "{}://{}{}",
        parsed.scheme(),
        parsed.host_str().unwrap(),
        parsed
            .port()
            .map(|port| format!(":{port}"))
            .unwrap_or_default()
    );
    let issuer_path = parsed.path().trim_matches('/');
    let mut urls = Vec::new();
    if issuer_path.is_empty() {
        urls.push(format!("{origin}/.well-known/oauth-authorization-server"));
        urls.push(format!("{origin}/.well-known/openid-configuration"));
    } else {
        urls.push(format!(
            "{origin}/.well-known/oauth-authorization-server/{issuer_path}"
        ));
        urls.push(format!(
            "{origin}/.well-known/openid-configuration/{issuer_path}"
        ));
        urls.push(format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        ));
    }
    Ok(urls)
}

fn protected_resource_metadata_urls(resource_url: &str) -> Result<Vec<String>> {
    let parsed = url::Url::parse(resource_url).context("invalid OAuth resource URL")?;
    let origin = format!(
        "{}://{}{}",
        parsed.scheme(),
        parsed
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("OAuth resource URL must include a host"))?,
        parsed
            .port()
            .map(|port| format!(":{port}"))
            .unwrap_or_default()
    );
    let resource_path = parsed.path().trim_matches('/');
    let mut urls = Vec::new();
    if !resource_path.is_empty() {
        urls.push(format!(
            "{origin}/.well-known/oauth-protected-resource/{resource_path}"
        ));
    }
    urls.push(format!("{origin}/.well-known/oauth-protected-resource"));
    Ok(urls)
}

fn resource_is_same_or_parent(target: &str, declared_resource: &str) -> Result<bool> {
    let target = url::Url::parse(target).context("invalid configured OAuth resource URL")?;
    let declared = url::Url::parse(declared_resource)
        .context("invalid resource identifier in protected resource metadata")?;
    if target.scheme() != declared.scheme()
        || target.host_str() != declared.host_str()
        || target.port_or_known_default() != declared.port_or_known_default()
    {
        return Ok(false);
    }

    let target_path = target.path().trim_end_matches('/');
    let declared_path = declared.path().trim_end_matches('/');
    Ok(declared_path.is_empty()
        || target_path == declared_path
        || target_path.starts_with(&format!("{declared_path}/")))
}

fn parse_bearer_challenge(
    headers: &reqwest::header::HeaderMap,
) -> (Option<String>, Option<Vec<String>>) {
    let mut metadata_url = None;
    let mut scopes = None;

    for header in headers.get_all(reqwest::header::WWW_AUTHENTICATE).iter() {
        let Ok(header) = header.to_str() else {
            continue;
        };
        let mut in_bearer_challenge = false;
        for segment in split_auth_header_parameters(header) {
            let segment = segment.trim();
            if segment.is_empty() {
                continue;
            }

            let Some((left, value)) = segment.split_once('=') else {
                in_bearer_challenge = segment.eq_ignore_ascii_case("Bearer");
                continue;
            };
            let left = left.trim();
            if let Some((scheme, parameter)) = left.split_once(char::is_whitespace) {
                in_bearer_challenge = scheme.eq_ignore_ascii_case("Bearer");
                if !in_bearer_challenge {
                    continue;
                }
                if let Some(value) = parse_auth_parameter_value(value) {
                    store_challenge_parameter(
                        parameter.trim(),
                        value,
                        &mut metadata_url,
                        &mut scopes,
                    );
                }
                continue;
            }

            if !in_bearer_challenge {
                continue;
            }
            if let Some(value) = parse_auth_parameter_value(value) {
                store_challenge_parameter(left, value, &mut metadata_url, &mut scopes);
            }
        }
    }

    (metadata_url, scopes)
}

fn split_auth_header_parameters(header: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let mut escaped = false;
    for (index, character) in header.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '\\' && in_quotes {
            escaped = true;
        } else if character == '"' {
            in_quotes = !in_quotes;
        } else if character == ',' && !in_quotes {
            segments.push(&header[start..index]);
            start = index + character.len_utf8();
        }
    }
    segments.push(&header[start..]);
    segments
}

fn parse_auth_parameter_value(value: &str) -> Option<String> {
    let value = value.trim();
    if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        let value = &value[1..value.len() - 1];
        let mut unescaped = String::with_capacity(value.len());
        let mut characters = value.chars();
        while let Some(character) = characters.next() {
            if character == '\\' {
                unescaped.push(characters.next()?);
            } else {
                unescaped.push(character);
            }
        }
        Some(unescaped)
    } else if !value.is_empty() {
        Some(value.to_string())
    } else {
        None
    }
}

fn store_challenge_parameter(
    key: &str,
    value: String,
    metadata_url: &mut Option<String>,
    scopes: &mut Option<Vec<String>>,
) {
    match key.to_ascii_lowercase().as_str() {
        "resource_metadata" => *metadata_url = Some(value),
        "scope" => {
            let parsed_scopes = value
                .split_ascii_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>();
            if !parsed_scopes.is_empty() {
                *scopes = Some(parsed_scopes);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use reqwest::header::{HeaderMap, HeaderValue, WWW_AUTHENTICATE};

    use super::parse_bearer_challenge;

    #[test]
    fn parses_resource_metadata_and_scopes_from_bearer_challenge() {
        let mut headers = HeaderMap::new();
        headers.append(
            WWW_AUTHENTICATE,
            HeaderValue::from_static(
                "Basic realm=legacy, Bearer realm=api, resource_metadata=\"https://mcp.example/.well-known/oauth-protected-resource\", scope=\"files:read files:write\"",
            ),
        );

        let (metadata_url, scopes) = parse_bearer_challenge(&headers);
        assert_eq!(
            metadata_url.as_deref(),
            Some("https://mcp.example/.well-known/oauth-protected-resource")
        );
        assert_eq!(
            scopes,
            Some(vec!["files:read".into(), "files:write".into()])
        );
    }

    #[test]
    fn ignores_parameters_from_non_bearer_challenges() {
        let mut headers = HeaderMap::new();
        headers.append(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"resource_metadata=not-a-bearer-challenge\""),
        );

        assert_eq!(parse_bearer_challenge(&headers), (None, None));
    }
}
