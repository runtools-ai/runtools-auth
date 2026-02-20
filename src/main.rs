use anyhow::Result;
use std::sync::Arc;
use tracing::info;

mod api;
mod auth;
mod config;
mod credentials;
mod crypto;
mod error;
mod providers;
mod store;
mod webhooks;

use auth::JwksKeyStore;
use config::Config;
use crypto::CryptoEngine;
use providers::ProviderRegistry;
use store::TokenStore;

/// Shared application state.
pub struct AppState {
    pub config: Config,
    pub store: TokenStore,
    pub crypto: CryptoEngine,
    pub registry: ProviderRegistry,
    pub jwks: JwksKeyStore,
}

pub type SharedState = Arc<AppState>;

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env if present
    let _ = dotenvy::dotenv();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "runtools_auth=info".into()),
        )
        .init();

    // Load config
    let config = Config::from_env()?;
    info!("runtools-auth v{}", env!("CARGO_PKG_VERSION"));
    info!("Listening on {}:{}", config.host, config.port);

    // Initialize components
    let crypto = CryptoEngine::new(&config.master_key, &config.hmac_secret)?;
    let store = TokenStore::new(&config.database_url).await?;
    store.migrate().await?;
    info!("Database connected and migrated ✓");

    let mut registry = ProviderRegistry::new();
    providers::register_defaults(&mut registry, &config);
    info!("Registered {} OAuth providers", registry.count());

    // Initialize JWKS key store for JWT signature verification
    let jwks = JwksKeyStore::workos();
    match jwks.warm_cache().await {
        Ok(()) => info!("JWKS keys cached ✓ (JWT signature verification enabled)"),
        Err(e) => {
            tracing::warn!(
                "⚠️  Failed to fetch JWKS keys: {e}. \
                 JWT signature verification will retry on first request."
            );
        }
    }

    // Build shared state
    let state: SharedState = Arc::new(AppState {
        config: config.clone(),
        store,
        crypto,
        registry,
        jwks,
    });

    // Start refresh daemon
    let daemon_state = state.clone();
    tokio::spawn(async move {
        store::refresh_daemon(daemon_state).await;
    });

    // Build router
    let app = api::router(state);

    // Start server
    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("Server ready ✓");
    axum::serve(listener, app).await?;

    Ok(())
}
