use async_trait::async_trait;
use serde::Deserialize;
use std::time::Duration;

use super::traits::{OAuthProvider, TokenSet};
use crate::error::OAuthError;

/// Slack OAuth 2.0 provider.
///
/// Quirks:
/// - Uses `oauth.v2.access` endpoint for token exchange.
/// - Returns `authed_user.access_token` for user tokens, `access_token` for bot tokens.
/// - User tokens don't expire; bot tokens rotate if token rotation is enabled.
/// - Scopes are comma-separated, NOT space-separated.
/// - Revocation uses `auth.revoke` API method.
pub struct SlackProvider {
    client_id: String,
    client_secret: String,
    http: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct SlackTokenResponse {
    ok: bool,
    access_token: Option<String>,
    token_type: Option<String>,
    scope: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
    // For user tokens
    authed_user: Option<SlackAuthedUser>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SlackAuthedUser {
    access_token: Option<String>,
    token_type: Option<String>,
    scope: Option<String>,
}

impl SlackProvider {
    pub fn new(client_id: String, client_secret: String) -> Self {
        Self {
            client_id,
            client_secret,
            http: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl OAuthProvider for SlackProvider {
    fn id(&self) -> &str {
        "slack"
    }

    fn display_name(&self) -> &str {
        "Slack"
    }

    fn available_scopes(&self) -> Vec<String> {
        vec![
            // User scopes
            "users:read".into(),
            "users:read.email".into(),
            "channels:read".into(),
            "channels:history".into(),
            "chat:write".into(),
            "files:read".into(),
            "files:write".into(),
            "reactions:read".into(),
            "reactions:write".into(),
            "search:read".into(),
            "im:read".into(),
            "im:write".into(),
            "im:history".into(),
            "groups:read".into(),
            "groups:history".into(),
            "mpim:read".into(),
            "mpim:history".into(),
            "team:read".into(),
            "emoji:read".into(),
            "pins:read".into(),
            "pins:write".into(),
            "bookmarks:read".into(),
            "bookmarks:write".into(),
        ]
    }

    fn auth_url(&self, scopes: &[String], state: &str, redirect_uri: &str) -> String {
        // Slack uses user_scope for user tokens
        let scope_str = scopes.join(",");
        format!(
            "https://slack.com/oauth/v2/authorize?\
             client_id={client_id}\
             &redirect_uri={redirect_uri}\
             &user_scope={scope}\
             &state={state}",
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
            .post("https://slack.com/api/oauth.v2.access")
            .form(&[
                ("code", code),
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
                ("redirect_uri", redirect_uri),
            ])
            .send()
            .await
            .map_err(|e| OAuthError::FlowError(format!("Token exchange request failed: {e}")))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(OAuthError::FlowError(format!(
                "Slack token exchange failed: {body}"
            )));
        }

        let token_resp: SlackTokenResponse = resp
            .json()
            .await
            .map_err(|e| OAuthError::FlowError(format!("Failed to parse token response: {e}")))?;

        if !token_resp.ok {
            return Err(OAuthError::FlowError(format!(
                "Slack OAuth error: {}",
                token_resp.error.unwrap_or_else(|| "unknown".into())
            )));
        }

        // Prefer user token if present, otherwise use bot token
        if let Some(authed) = &token_resp.authed_user {
            if let Some(ref at) = authed.access_token {
                return Ok(TokenSet {
                    access_token: at.clone(),
                    refresh_token: None, // User tokens don't have refresh
                    token_type: authed.token_type.clone().unwrap_or_else(|| "user".into()),
                    expires_in: None,
                    scope: authed.scope.clone(),
                });
            }
        }

        // Fall back to bot token
        Ok(TokenSet {
            access_token: token_resp
                .access_token
                .ok_or_else(|| OAuthError::FlowError("no access_token in response".into()))?,
            refresh_token: token_resp.refresh_token,
            token_type: token_resp
                .token_type
                .unwrap_or_else(|| "bot".into()),
            expires_in: token_resp.expires_in,
            scope: token_resp.scope,
        })
    }

    async fn refresh_token(&self, refresh_token: &str) -> Result<TokenSet, OAuthError> {
        // Slack token rotation (if enabled for the app)
        let resp = self
            .http
            .post("https://slack.com/api/oauth.v2.access")
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
            ])
            .send()
            .await
            .map_err(|e| OAuthError::RefreshFailed(format!("Refresh request failed: {e}")))?;

        let token_resp: SlackTokenResponse = resp
            .json()
            .await
            .map_err(|e| OAuthError::RefreshFailed(format!("Failed to parse refresh response: {e}")))?;

        if !token_resp.ok {
            return Err(OAuthError::RefreshFailed(format!(
                "Slack refresh error: {}",
                token_resp.error.unwrap_or_else(|| "unknown".into())
            )));
        }

        Ok(TokenSet {
            access_token: token_resp
                .access_token
                .ok_or_else(|| OAuthError::RefreshFailed("no access_token in response".into()))?,
            refresh_token: token_resp.refresh_token,
            token_type: token_resp.token_type.unwrap_or_else(|| "bot".into()),
            expires_in: token_resp.expires_in,
            scope: token_resp.scope,
        })
    }

    async fn revoke(&self, token: &str) -> Result<(), OAuthError> {
        let resp = self
            .http
            .post("https://slack.com/api/auth.revoke")
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| OAuthError::FlowError(format!("Revoke request failed: {e}")))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(OAuthError::FlowError(format!(
                "Slack revoke failed: {body}"
            )));
        }

        Ok(())
    }

    fn token_ttl(&self) -> Duration {
        // Slack user tokens don't expire. Bot tokens with rotation expire in 12 hours.
        // Use 12 hours as a safe default.
        Duration::from_secs(12 * 3600)
    }

    fn supports_pkce(&self) -> bool {
        false
    }
}

fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
