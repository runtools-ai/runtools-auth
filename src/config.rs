use anyhow::{Context, Result};

/// Application configuration, loaded from environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    // ── Server ──────────────────────────────────────────────────────────
    pub host: String,
    pub port: u16,
    pub base_url: String,
    /// Dashboard frontend URL for post-OAuth redirects
    pub dashboard_url: String,

    // ── Database (PostgreSQL, shared with orchestrator/tools/billing) ──
    pub database_url: String,

    // ── Crypto ──────────────────────────────────────────────────────────
    /// 32-byte base64-encoded master key for AES-256-GCM encryption.
    pub master_key: String,
    /// 32-byte base64-encoded HMAC key for state parameter signing.
    pub hmac_secret: String,

    // ── Service-to-service auth ─────────────────────────────────────────
    /// Shared secret for internal service calls (replaces FC_SECRET etc.)
    pub auth_service_secret: String,

    // ── WorkOS ──────────────────────────────────────────────────────────
    pub workos_api_key: Option<String>,
    pub workos_client_id: Option<String>,
    pub workos_cookie_password: Option<String>,
    /// JWKS URL for JWT signature verification (optional, fall back to decode-only)
    pub workos_jwks_url: Option<String>,
    /// Webhook signing secret for WorkOS webhook signature verification
    pub workos_webhook_secret: String,

    // ── OAuth Provider Credentials ──────────────────────────────────────
    pub google_client_id: Option<String>,
    pub google_client_secret: Option<String>,
    pub slack_client_id: Option<String>,
    pub slack_client_secret: Option<String>,
    pub github_client_id: Option<String>,
    pub github_client_secret: Option<String>,
    pub discord_client_id: Option<String>,
    pub discord_client_secret: Option<String>,
    pub x_client_id: Option<String>,
    pub x_client_secret: Option<String>,
    pub linkedin_client_id: Option<String>,
    pub linkedin_client_secret: Option<String>,
    pub microsoft_client_id: Option<String>,
    pub microsoft_client_secret: Option<String>,
    pub telegram_bot_token: Option<String>,
    pub whatsapp_client_id: Option<String>,
    pub whatsapp_client_secret: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Config {
            host: std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "8420".into())
                .parse()
                .context("Invalid PORT")?,
            base_url: std::env::var("BASE_URL")
                .unwrap_or_else(|_| "http://localhost:8420".into()),
            dashboard_url: std::env::var("DASHBOARD_URL")
                .unwrap_or_else(|_| "https://runtools.ai".into()),

            database_url: std::env::var("DATABASE_URL")
                .context("DATABASE_URL is required (PostgreSQL connection string)")?,
            master_key: std::env::var("MASTER_KEY")
                .context("MASTER_KEY is required (32 bytes, base64)")?,
            hmac_secret: std::env::var("HMAC_SECRET")
                .context("HMAC_SECRET is required (32 bytes, base64)")?,

            auth_service_secret: std::env::var("AUTH_SERVICE_SECRET")
                .context("AUTH_SERVICE_SECRET is required for service-to-service auth")?,

            workos_api_key: std::env::var("WORKOS_API_KEY").ok(),
            workos_client_id: std::env::var("WORKOS_CLIENT_ID").ok(),
            workos_cookie_password: std::env::var("WORKOS_COOKIE_PASSWORD").ok(),
            workos_jwks_url: std::env::var("WORKOS_JWKS_URL").ok(),
            workos_webhook_secret: std::env::var("WORKOS_WEBHOOK_SECRET").unwrap_or_default(),

            google_client_id: std::env::var("GOOGLE_CLIENT_ID").ok(),
            google_client_secret: std::env::var("GOOGLE_CLIENT_SECRET").ok(),
            slack_client_id: std::env::var("SLACK_CLIENT_ID").ok(),
            slack_client_secret: std::env::var("SLACK_CLIENT_SECRET").ok(),
            github_client_id: std::env::var("GITHUB_CLIENT_ID").ok(),
            github_client_secret: std::env::var("GITHUB_CLIENT_SECRET").ok(),
            discord_client_id: std::env::var("DISCORD_CLIENT_ID").ok(),
            discord_client_secret: std::env::var("DISCORD_CLIENT_SECRET").ok(),
            x_client_id: std::env::var("X_CLIENT_ID").ok(),
            x_client_secret: std::env::var("X_CLIENT_SECRET").ok(),
            linkedin_client_id: std::env::var("LINKEDIN_CLIENT_ID").ok(),
            linkedin_client_secret: std::env::var("LINKEDIN_CLIENT_SECRET").ok(),
            microsoft_client_id: std::env::var("MICROSOFT_CLIENT_ID").ok(),
            microsoft_client_secret: std::env::var("MICROSOFT_CLIENT_SECRET").ok(),
            telegram_bot_token: std::env::var("TELEGRAM_BOT_TOKEN").ok(),
            whatsapp_client_id: std::env::var("WHATSAPP_CLIENT_ID").ok(),
            whatsapp_client_secret: std::env::var("WHATSAPP_CLIENT_SECRET").ok(),
        })
    }

    /// Get the OAuth callback URL for a specific provider.
    pub fn callback_url(&self, provider: &str) -> String {
        format!("{}/v1/oauth/callback/{}", self.base_url, provider)
    }
}
