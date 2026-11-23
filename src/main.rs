mod auth;
mod config;
mod credential;
mod mcp_logging;
mod mcp_protocol;
mod proxy;
mod settings;
mod storage;
mod tool_cache;

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::config::{Config, TransportType};

#[derive(Parser)]
#[command(name = "mcp-auth-proxy")]
#[command(version)]
#[command(about = "MCP authentication proxy — forwards requests with injected credentials")]
struct Cli {
    /// Path to the TOML configuration file
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    /// Validate config and credential provider connectivity, then exit
    #[arg(long)]
    validate: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // Load config
    let config_str = std::fs::read_to_string(&cli.config)
        .with_context(|| format!("failed to read config file: {}", cli.config))?;

    let config: Config =
        toml::from_str(&config_str).with_context(|| "failed to parse config file")?;

    config.validate()?;

    info!(upstreams = config.upstreams.len(), "loaded configuration");

    // Create credential provider
    let credential_provider: Arc<dyn credential::CredentialProvider> =
        Arc::from(credential::create_provider(&config.credential_provider)?);

    // Create token storage
    let token_storage: Arc<dyn storage::TokenStorage> =
        Arc::from(storage::create_storage(&config.token_storage)?);

    // Validate mode — test connectivity and exit
    if cli.validate {
        info!("validation mode — testing credential provider");
        let mut failures = 0usize;
        if let Some(ref token_ref) = config.server.admin_token_ref {
            match credential_provider.resolve(token_ref).await {
                Ok(_) => info!("server admin token resolution OK"),
                Err(e) => {
                    failures += 1;
                    error!(error = %e, "server admin token resolution FAILED");
                }
            }
        }
        for upstream in &config.upstreams {
            if let Some(ref cred_ref) = upstream.auth.credential_ref {
                match credential_provider.resolve(cred_ref).await {
                    Ok(_) => info!(upstream = %upstream.name, "credential resolution OK"),
                    Err(e) => {
                        failures += 1;
                        error!(upstream = %upstream.name, error = %e, "credential resolution FAILED");
                    }
                }
            }
            for extra in &upstream.auth.extra_headers {
                match credential_provider.resolve(&extra.credential_ref).await {
                    Ok(_) => {
                        info!(upstream = %upstream.name, header = %extra.header, "extra header credential resolution OK")
                    }
                    Err(e) => {
                        failures += 1;
                        error!(upstream = %upstream.name, header = %extra.header, error = %e, "extra header credential resolution FAILED");
                    }
                }
            }
            if let Some(secret_ref) = upstream
                .auth
                .oauth
                .as_ref()
                .and_then(|oauth| oauth.client_secret_ref.as_deref())
            {
                match credential_provider.resolve(secret_ref).await {
                    Ok(_) => info!(upstream = %upstream.name, "OAuth client-secret resolution OK"),
                    Err(e) => {
                        failures += 1;
                        error!(upstream = %upstream.name, error = %e, "OAuth client-secret resolution FAILED");
                    }
                }
            }
        }
        if failures > 0 {
            anyhow::bail!("validation failed with {failures} error(s)");
        }
        info!("validation complete");
        return Ok(());
    }

    // Build upstream states
    let mut upstreams = Vec::new();
    for upstream_config in &config.upstreams {
        let upstream_route_name = upstream_config
            .path_prefix
            .trim_start_matches('/')
            .to_string();
        let auth_strategy = auth::create_auth_strategy(
            &upstream_config.auth,
            &upstream_config.name,
            upstream_config.url.as_deref(),
            credential_provider.clone(),
            token_storage.clone(),
        )?;

        let http = match upstream_config.transport {
            TransportType::Http => {
                let url = upstream_config.url.as_ref().unwrap();
                Some(proxy::http_upstream::HttpUpstream::new(
                    upstream_route_name.clone(),
                    url.clone(),
                    upstream_config.log_mcp_traffic,
                )?)
            }
            TransportType::Stdio => None,
        };

        let stdio = match upstream_config.transport {
            TransportType::Stdio => {
                let command = upstream_config.command.as_ref().unwrap().clone();
                Some(proxy::stdio_upstream::StdioUpstream::new(
                    upstream_route_name.clone(),
                    command,
                    upstream_config.args.clone(),
                    upstream_config.env.clone(),
                    upstream_config.log_mcp_traffic,
                ))
            }
            TransportType::Http => None,
        };

        upstreams.push(Arc::new(proxy::UpstreamState {
            name: upstream_route_name,
            transport: upstream_config.transport.clone(),
            auth: auth_strategy,
            http,
            stdio,
            from_config: true,
            auth_header: upstream_config.auth.header.clone(),
            auth_prefix: upstream_config.auth.prefix.clone(),
            extra_headers: upstream_config.auth.extra_headers.clone(),
            credential_ref: upstream_config.auth.credential_ref.clone(),
            log_mcp_traffic: upstream_config.log_mcp_traffic,
        }));
    }

    // Create tool cache and profile store
    let tool_cache = tool_cache::ToolCache::new();

    // Derive data directory from config file location
    let config_dir = std::path::Path::new(&cli.config)
        .parent()
        .unwrap_or(std::path::Path::new("."));
    let data_dir = config_dir.join("data");
    let profile_store = settings::ProfileStore::new(data_dir.join("profiles.json"));
    let mcp_server_store = settings::McpServerStore::new(data_dir.join("servers.json"));

    // Re-register persisted dynamic MCP servers as upstreams
    for server in mcp_server_store.list().await {
        match proxy::build_dynamic_upstream(
            &server,
            credential_provider.clone(),
            token_storage.clone(),
        ) {
            Ok(upstream) => {
                upstreams.push(upstream);
                info!(server = %server.name, "restored persisted MCP server");
            }
            Err(e) => {
                error!(server = %server.name, error = %e, "failed to restore persisted MCP server");
            }
        }
    }

    // Resolve optional / required /settings admin token
    let admin_token = if let Some(ref token_ref) = config.server.admin_token_ref {
        Some(
            credential_provider
                .resolve(token_ref)
                .await
                .with_context(|| {
                    format!("failed to resolve server.admin_token_ref '{token_ref}'")
                })?,
        )
    } else if let Ok(env_token) = std::env::var("MCP_AUTH_PROXY_ADMIN_TOKEN") {
        if !env_token.is_empty() {
            Some(env_token)
        } else {
            None
        }
    } else {
        None
    };

    let admin_token = match admin_token {
        Some(token) => Some(token),
        None if !proxy::is_loopback_host(&config.server.host) => {
            let generated = proxy::generate_random_hex_token();
            warn!(
                host = %config.server.host,
                "server.host is non-loopback and no admin token was configured; generated an ephemeral /settings admin token"
            );
            eprintln!("Generated ephemeral /settings admin token: {generated}");
            Some(generated)
        }
        None => None,
    };

    let settings_security = proxy::SettingsSecurityConfig {
        bound_host: config.server.host.clone(),
        admin_token,
        allow_insecure_dynamic_upstreams: config.server.allow_insecure_dynamic_upstreams,
    };

    // Clone upstreams for background cache refresh
    let upstreams_for_cache: Vec<Arc<proxy::UpstreamState>> = upstreams.to_vec();
    let tool_cache_bg = tool_cache.clone();

    // Build router
    let app = proxy::build_router_with_security(
        upstreams,
        tool_cache,
        profile_store,
        mcp_server_store,
        credential_provider,
        token_storage,
        settings_security,
    );

    // Start server
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("failed to bind to {}", addr))?;

    info!(addr = %addr, "mcp-auth-proxy listening");

    // Refresh tool cache in the background at startup
    tokio::spawn(async move {
        for upstream in &upstreams_for_cache {
            if let Err(e) = tool_cache_bg.refresh_upstream(upstream).await {
                warn!(upstream = %upstream.name, error = %e, "failed to cache tools at startup");
            }
        }
    });

    axum::serve(listener, app).await.context("server error")?;

    Ok(())
}
