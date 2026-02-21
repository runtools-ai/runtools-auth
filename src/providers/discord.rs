use async_trait::async_trait;
use serde::Deserialize;
use std::time::Duration;

use super::traits::{OAuthProvider, TokenSet};
use crate::error::OAuthError;

/// Discord OAuth 2.0 provider.
///
/// Quirks:
/// - Standard OAuth 2.0 flow.
/// - Uses `identify` scope for basic user info.
/// - `bot` scope is special — adds the bot to a guild (not a user token).
/// - Refresh tokens ARE supported and tokens expire in 7 days.
pub struct DiscordProvider {
    client_id: String,
    client_secret: String,
    http: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct DiscordTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    scope: Option<String>,
}

impl DiscordProvider {
    pub fn new(client_id: String, client_secret: String) -> Self {
        Self {
            client_id,
            client_secret,
            http: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl OAuthProvider for DiscordProvider {
    fn id(&self) -> &str {
        "discord"
    }

    fn display_name(&self) -> &str {
        "Discord"
    }

    fn available_scopes(&self) -> Vec<String> {
        vec![
            "identify".into(),
            "email".into(),
            "guilds".into(),
            "guilds.join".into(),
            "guilds.members.read".into(),
            "messages.read".into(),
            "webhook.incoming".into(),
            "connections".into(),
        ]
    }

    fn auth_url(&self, scopes: &[String], state: &str, redirect_uri: &str) -> String {
        let scope_str = scopes.join(" ");
        format!(
            "https://discord.com/api/oauth2/authorize?\
             client_id={client_id}\
             &redirect_uri={redirect_uri}\
             &response_type=code\
             &scope={scope}\
             &state={state}\
             &prompt=consent",
            client_id = urlencoding(&self.client_id),
            redirect_uri = urlencoding(redirect_uri),
            scope = urlencoding(&scope_str),
            state = urlencoding(state),
        )
    }

    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
    ) -> Result<TokenSet, OAuthError> {
        let resp = self
            .http
            .post("https://discord.com/api/oauth2/token")
            .form(&[
                ("code", code),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("redirect_uri", redirect_uri),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await
            .map_err(|e| OAuthError::FlowError(format!("Token exchange request failed: {e}")))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(OAuthError::FlowError(format!(
                "Discord token exchange failed: {body}"
            )));
        }

        let token_resp: DiscordTokenResponse = resp
            .json()
            .await
            .map_err(|e| OAuthError::FlowError(format!("Failed to parse token response: {e}")))?;

        Ok(TokenSet {
            access_token: token_resp.access_token,
            refresh_token: token_resp.refresh_token,
            token_type: token_resp.token_type,
            expires_in: token_resp.expires_in,
            scope: token_resp.scope,
        })
    }

    async fn refresh_token(&self, refresh_token: &str) -> Result<TokenSet, OAuthError> {
        let resp = self
            .http
            .post("https://discord.com/api/oauth2/token")
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
            ])
            .send()
            .await
            .map_err(|e| OAuthError::RefreshFailed(format!("Refresh request failed: {e}")))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(OAuthError::RefreshFailed(format!(
                "Discord refresh failed: {body}"
            )));
        }

        let token_resp: DiscordTokenResponse = resp
            .json()
            .await
            .map_err(|e| OAuthError::RefreshFailed(format!("Failed to parse refresh response: {e}")))?;

        Ok(TokenSet {
            access_token: token_resp.access_token,
            refresh_token: token_resp.refresh_token,
            token_type: token_resp.token_type,
            expires_in: token_resp.expires_in,
            scope: token_resp.scope,
        })
    }

    async fn revoke(&self, token: &str) -> Result<(), OAuthError> {
        let resp = self
            .http
            .post("https://discord.com/api/oauth2/token/revoke")
            .form(&[
                ("token", token),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
            ])
            .send()
            .await
            .map_err(|e| OAuthError::FlowError(format!("Revoke request failed: {e}")))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(OAuthError::FlowError(format!(
                "Discord revoke failed: {body}"
            )));
        }

        Ok(())
    }

    fn token_ttl(&self) -> Duration {
        Duration::from_secs(7 * 24 * 3600) // Discord tokens expire in 7 days
    }

    fn supports_pkce(&self) -> bool {
        false
    }
}

fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
