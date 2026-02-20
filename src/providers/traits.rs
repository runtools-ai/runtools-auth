use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::error::OAuthError;

/// A set of tokens returned from an OAuth provider after code exchange or refresh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSet {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub scope: Option<String>,
}

/// Trait that every OAuth provider must implement.
///
/// Each implementation is ~100-150 lines and handles the provider-specific
/// quirks of OAuth (authorization URL format, token endpoint, refresh behavior, etc.)
#[async_trait]
pub trait OAuthProvider: Send + Sync {
    /// Unique provider identifier (e.g., "google", "slack", "github").
    fn id(&self) -> &str;

    /// Human-readable display name (e.g., "Google", "Slack", "GitHub").
    fn display_name(&self) -> &str;

    /// List of scopes this provider supports.
    fn available_scopes(&self) -> Vec<String>;

    /// Build the authorization URL that the user should be redirected to.
    ///
    /// - `scopes`: The OAuth scopes to request.
    /// - `state`: An opaque, HMAC-signed state string for CSRF protection.
    /// - `redirect_uri`: The callback URL registered with the provider.
    fn auth_url(&self, scopes: &[String], state: &str, redirect_uri: &str) -> String;

    /// Exchange an authorization code for an access token (and optionally refresh token).
    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
    ) -> Result<TokenSet, OAuthError>;

    /// Refresh an expired access token using a refresh token.
    async fn refresh_token(&self, refresh_token: &str) -> Result<TokenSet, OAuthError>;

    /// Revoke an access or refresh token. Not all providers support this.
    async fn revoke(&self, _token: &str) -> Result<(), OAuthError> {
        Ok(())
    }

    /// How long tokens from this provider typically live.
    /// Used by the refresh daemon to know when to proactively refresh.
    fn token_ttl(&self) -> Duration {
        Duration::from_secs(3600) // 1 hour default
    }

    /// Whether this provider supports PKCE (Proof Key for Code Exchange).
    fn supports_pkce(&self) -> bool {
        false
    }
}
