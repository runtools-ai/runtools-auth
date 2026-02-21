use async_trait::async_trait;
use serde::Deserialize;
use std::time::Duration;

use super::traits::{OAuthProvider, TokenSet};
use crate::error::OAuthError;

/// Telegram Login Widget provider.
///
/// IMPORTANT: Telegram does NOT use standard OAuth 2.0.
/// Instead, it uses a Login Widget that returns HMAC-signed user data.
/// We adapt this to fit the OAuthProvider trait:
///
/// - `auth_url` → returns a page with the Telegram Login Widget
/// - `exchange_code` → verifies the HMAC-signed callback data
/// - No access/refresh tokens — we get user info (id, name, username, photo)
/// - The "access_token" we store is the bot token for API calls
///
/// Flow:
/// 1. User clicks "Login with Telegram" → redirects to Telegram
/// 2. Telegram sends data back to callback: id, first_name, username, photo_url, auth_date, hash
/// 3. We verify the hash using SHA-256(bot_token) as the HMAC key
/// 4. Store the user data as the "token" for later use
#[allow(dead_code)]
pub struct TelegramProvider {
    bot_token: String,
    http: reqwest::Client,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct TelegramCallbackData {
    id: u64,
    first_name: Option<String>,
    last_name: Option<String>,
    username: Option<String>,
    photo_url: Option<String>,
    auth_date: u64,
    hash: String,
}

impl TelegramProvider {
    pub fn new(bot_token: String) -> Self {
        Self {
            bot_token,
            http: reqwest::Client::new(),
        }
    }

    /// Verify the Telegram Login Widget callback data.
    /// Returns the user data as a JSON string if valid.
    fn verify_callback(&self, data: &str) -> Result<String, OAuthError> {
        use hmac::{Hmac, Mac};
        use sha2::{Digest, Sha256};

        // Parse the callback data (comes as query string or JSON)
        let params: std::collections::HashMap<String, String> =
            serde_urlencoded::from_str(data).map_err(|e| {
                OAuthError::FlowError(format!("Failed to parse callback data: {e}"))
            })?;

        let hash = params
            .get("hash")
            .ok_or_else(|| OAuthError::FlowError("Missing hash in callback".into()))?
            .clone();

        // Build the data-check-string (alphabetically sorted key=value pairs, excluding hash)
        let mut check_pairs: Vec<String> = params
            .iter()
            .filter(|(k, _)| k.as_str() != "hash")
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        check_pairs.sort();
        let data_check_string = check_pairs.join("\n");

        // secret_key = SHA256(bot_token)
        let secret_key = Sha256::digest(self.bot_token.as_bytes());

        // Verify: HMAC-SHA256(data_check_string, secret_key) == hash
        let mut mac = Hmac::<Sha256>::new_from_slice(&secret_key)
            .map_err(|e| OAuthError::FlowError(format!("HMAC init failed: {e}")))?;
        mac.update(data_check_string.as_bytes());

        let expected = hex::encode(mac.finalize().into_bytes());
        if expected != hash {
            return Err(OAuthError::FlowError("Invalid Telegram hash".into()));
        }

        // Check auth_date is not too old (allow 1 hour)
        if let Some(auth_date_str) = params.get("auth_date") {
            if let Ok(auth_date) = auth_date_str.parse::<u64>() {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if now - auth_date > 3600 {
                    return Err(OAuthError::FlowError("Telegram auth data expired".into()));
                }
            }
        }

        // Return all user data as JSON — this becomes the "access token"
        let user_data = serde_json::json!({
            "id": params.get("id"),
            "first_name": params.get("first_name"),
            "last_name": params.get("last_name"),
            "username": params.get("username"),
            "photo_url": params.get("photo_url"),
        });

        Ok(user_data.to_string())
    }
}

#[async_trait]
impl OAuthProvider for TelegramProvider {
    fn id(&self) -> &str {
        "telegram"
    }

    fn display_name(&self) -> &str {
        "Telegram"
    }

    fn available_scopes(&self) -> Vec<String> {
        // Telegram doesn't have traditional scopes — the Login Widget
        // grants access to user profile data only
        vec![
            "profile".into(),
            "bot_api".into(),
        ]
    }

    fn auth_url(&self, _scopes: &[String], state: &str, redirect_uri: &str) -> String {
        // Extract bot username from bot token (first part before :)
        // In practice, the bot_id part is numeric — we need the bot username
        // which should be configured separately. For now, encode the redirect
        // so the frontend can render the Telegram Login Widget.
        format!(
            "/v1/oauth/telegram-widget?\
             redirect_uri={redirect_uri}\
             &state={state}",
            redirect_uri = urlencoding(redirect_uri),
            state = urlencoding(state),
        )
    }

    async fn exchange_code(
        &self,
        code: &str,
        _redirect_uri: &str,
    ) -> Result<TokenSet, OAuthError> {
        // For Telegram, the "code" is actually the full callback query string
        // containing id, first_name, username, photo_url, auth_date, hash
        let user_data = self.verify_callback(code)?;

        Ok(TokenSet {
            access_token: user_data, // Store user info as the "token"
            refresh_token: None,
            token_type: "telegram_login".into(),
            expires_in: None, // Telegram logins don't expire
            scope: Some("profile".into()),
        })
    }

    async fn refresh_token(&self, _refresh_token: &str) -> Result<TokenSet, OAuthError> {
        Err(OAuthError::RefreshFailed(
            "Telegram Login Widget does not support token refresh".into(),
        ))
    }

    async fn revoke(&self, _token: &str) -> Result<(), OAuthError> {
        // Telegram doesn't have a revocation endpoint
        // The login is session-based on Telegram's side
        Ok(())
    }

    fn token_ttl(&self) -> Duration {
        // Telegram logins don't expire — set to 90 days
        Duration::from_secs(90 * 24 * 3600)
    }

    fn supports_pkce(&self) -> bool {
        false
    }
}

fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
