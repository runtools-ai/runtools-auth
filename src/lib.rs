pub mod api;
pub mod auth;
pub mod config;
pub mod credentials;
pub mod crypto;
pub mod error;
pub mod providers;
pub mod store;
pub mod webhooks;

pub use config::Config;
pub use error::AuthError;

use std::sync::Arc;

/// Shared application state passed to all API handlers.
pub struct AppState {
    pub config: Config,
    pub store: store::TokenStore,
    pub crypto: crypto::CryptoEngine,
    pub registry: providers::ProviderRegistry,
    pub jwks: auth::JwksKeyStore,
}

pub type SharedState = Arc<AppState>;
