mod auth;
mod config;
mod credential;
mod proxy;
mod storage;

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::config::{Config, TransportType};
use crate::proxy::UpstreamState;

#[derive(Parser)]
#[command(name = "mcp-auth-proxy")]
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

    info!(
        upstreams = config.upstreams.len(),
        "loaded configuration"
    );

    // Create credential provider
    let credential_provider: Arc<dyn credential::CredentialProvider> =
        Arc::from(credential::create_provider(&config.credential_provider)?);

    // Create token storage
    let token_storage: Arc<dyn storage::TokenStorage> =
        Arc::from(storage::create_storage(&config.token_storage)?);

    // Validate mode — test connectivity and exit
    if cli.validate {
        info!("validation mode — testing credential provider");
        for upstream in &config.upstreams {
            if let Some(ref cred_ref) = upstream.auth.credential_ref {
                match credential_provider.resolve(cred_ref).await {
                    Ok(_) => info!(upstream = %upstream.name, "credential resolution OK"),
                    Err(e) => error!(upstream = %upstream.name, error = %e, "credential resolution FAILED"),
                }
            }
        }
        info!("validation complete");
        return Ok(());
    }

    // Build upstream states
    let mut upstreams = Vec::new();
    for upstream_config in &config.upstreams {
        let auth_strategy = auth::create_auth_strategy(
            &upstream_config.auth,
            &upstream_config.name,
            credential_provider.clone(),
            token_storage.clone(),
        )?;

        let http = match upstream_config.transport {
            TransportType::Http => {
                let url = upstream_config.url.as_ref().unwrap();
                Some(proxy::http_upstream::HttpUpstream::new(url.clone())?)
            }
            TransportType::Stdio => None,
        };

        let stdio = match upstream_config.transport {
            TransportType::Stdio => {
                let command = upstream_config.command.as_ref().unwrap().clone();
                Some(proxy::stdio_upstream::StdioUpstream::new(
                    command,
                    upstream_config.args.clone(),
                    upstream_config.env.clone(),
                ))
            }
            TransportType::Http => None,
        };

        upstreams.push(Arc::new(UpstreamState {
            name: upstream_config.path_prefix.trim_start_matches('/').to_string(),
            transport: upstream_config.transport.clone(),
            auth: auth_strategy,
            http,
            stdio,
        }));
    }

    // Build router
    let app = proxy::build_router(upstreams);

    // Start server
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("failed to bind to {}", addr))?;

    info!(addr = %addr, "mcp-auth-proxy listening");

    axum::serve(listener, app)
        .await
        .context("server error")?;

    Ok(())
}

