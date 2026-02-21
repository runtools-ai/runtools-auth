mod discord;
mod github;
mod google;
mod linkedin;
mod microsoft;
mod registry;
mod slack;
mod telegram;
mod traits;
mod whatsapp;
mod x;

pub use discord::DiscordProvider;
pub use github::GitHubProvider;
pub use google::GoogleProvider;
pub use linkedin::LinkedInProvider;
pub use microsoft::MicrosoftProvider;
pub use registry::ProviderRegistry;
pub use slack::SlackProvider;
pub use telegram::TelegramProvider;
pub use traits::{OAuthProvider, TokenSet};
pub use whatsapp::WhatsAppProvider;
pub use x::XProvider;

use crate::config::Config;

/// Register all platform-level providers that have credentials configured.
pub fn register_defaults(registry: &mut ProviderRegistry, config: &Config) {
    // Google
    if let (Some(id), Some(secret)) = (&config.google_client_id, &config.google_client_secret) {
        registry.register(Box::new(GoogleProvider::new(id.clone(), secret.clone())));
    }

    // GitHub
    if let (Some(id), Some(secret)) = (&config.github_client_id, &config.github_client_secret) {
        registry.register(Box::new(GitHubProvider::new(id.clone(), secret.clone())));
    }

    // Slack
    if let (Some(id), Some(secret)) = (&config.slack_client_id, &config.slack_client_secret) {
        registry.register(Box::new(SlackProvider::new(id.clone(), secret.clone())));
    }

    // Discord
    if let (Some(id), Some(secret)) = (&config.discord_client_id, &config.discord_client_secret) {
        registry.register(Box::new(DiscordProvider::new(id.clone(), secret.clone())));
    }

    // X (Twitter)
    if let (Some(id), Some(secret)) = (&config.x_client_id, &config.x_client_secret) {
        registry.register(Box::new(XProvider::new(id.clone(), secret.clone())));
    }

    // LinkedIn
    if let (Some(id), Some(secret)) = (&config.linkedin_client_id, &config.linkedin_client_secret) {
        registry.register(Box::new(LinkedInProvider::new(id.clone(), secret.clone())));
    }

    // Microsoft
    if let (Some(id), Some(secret)) = (&config.microsoft_client_id, &config.microsoft_client_secret) {
        registry.register(Box::new(MicrosoftProvider::new(id.clone(), secret.clone())));
    }

    // Telegram (uses bot token only — no client_id/secret pair)
    if let Some(token) = &config.telegram_bot_token {
        registry.register(Box::new(TelegramProvider::new(token.clone())));
    }

    // WhatsApp (uses Meta/Facebook OAuth)
    if let (Some(id), Some(secret)) = (&config.whatsapp_client_id, &config.whatsapp_client_secret) {
        registry.register(Box::new(WhatsAppProvider::new(id.clone(), secret.clone())));
    }
}
