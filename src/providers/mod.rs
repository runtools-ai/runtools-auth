mod google;
mod registry;
mod traits;

pub use google::GoogleProvider;
pub use registry::ProviderRegistry;
pub use traits::{OAuthProvider, TokenSet};

use crate::config::Config;

/// Register all platform-level providers that have credentials configured.
pub fn register_defaults(registry: &mut ProviderRegistry, config: &Config) {
    // Google
    if let (Some(id), Some(secret)) = (&config.google_client_id, &config.google_client_secret) {
        registry.register(Box::new(GoogleProvider::new(id.clone(), secret.clone())));
    }

    // TODO: Slack, GitHub, Discord, Microsoft providers
}
