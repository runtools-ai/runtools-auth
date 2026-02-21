use async_trait::async_trait;
use serde::Deserialize;
use std::time::Duration;

use super::traits::{OAuthProvider, TokenSet};
use crate::error::OAuthError;

/// X (Twitter) OAuth 2.0 provider.
///
/// Quirks:
/// - Uses OAuth 2.0 with PKCE (required).
/// - Free tier: no refresh tokens.
/// - Basic/Pro: refresh tokens supported, access tokens expire in 2 hours.
/// - Token endpoint requires Basic auth (client_id:client_secret base64).
/// - Scopes use dot notation: tweet.read, users.read, etc.
pub struct XProvider {
    client_id: String,
    client_secret: String,
    http: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct XTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    scope: Option<String>,
}

impl XProvider {
    pub fn new(client_id: String, client_secret: String) -> Self {
        Self {
            client_id,
            client_secret,
            http: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl OAuthProvider for XProvider {
    fn id(&self) -> &str {
        "x"
    }

    fn display_name(&self) -> &str {
        "X (Twitter)"
    }

    fn available_scopes(&self) -> Vec<String> {
        vec![
            "tweet.read".into(),
            "tweet.write".into(),
            "tweet.moderate.write".into(),
            "users.read".into(),
            "follows.read".into(),
            "follows.write".into(),
            "offline.access".into(),
            "space.read".into(),
            "mute.read".into(),
            "mute.write".into(),
            "like.read".into(),
            "like.write".into(),
            "list.read".into(),
            "list.write".into(),
            "block.read".into(),
            "block.write".into(),
            "bookmark.read".into(),
            "bookmark.write".into(),
            "dm.read".into(),
            "dm.write".into(),
        ]
    }

    fn auth_url(&self, scopes: &[String], state: &str, redirect_uri: &str) -> String {
        let scope_str = scopes.join(" ");
        // X OAuth 2.0 with PKCE — code_challenge handled by caller
        format!(
            "https://twitter.com/i/oauth2/authorize?\
             client_id={client_id}\
             &redirect_uri={redirect_uri}\
             &response_type=code\
             &scope={scope}\
             &state={state}\
             &code_challenge=challenge\
             &code_challenge_method=plain",
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
            .post("https://api.twitter.com/2/oauth2/token")
            .basic_auth(&self.client_id, Some(&self.client_secret))
            .form(&[
                ("code", code),
                ("redirect_uri", redirect_uri),
                ("grant_type", "authorization_code"),
                ("code_verifier", "challenge"), // Matches plain PKCE challenge
            ])
            .send()
            .await
            .map_err(|e| OAuthError::FlowError(format!("Token exchange request failed: {e}")))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(OAuthError::FlowError(format!(
                "X token exchange failed: {body}"
            )));
        }

        let token_resp: XTokenResponse = resp
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
            .post("https://api.twitter.com/2/oauth2/token")
            .basic_auth(&self.client_id, Some(&self.client_secret))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
            ])
            .send()
            .await
            .map_err(|e| OAuthError::RefreshFailed(format!("Refresh request failed: {e}")))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(OAuthError::RefreshFailed(format!(
                "X refresh failed: {body}"
            )));
        }

        let token_resp: XTokenResponse = resp
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
            .post("https://api.twitter.com/2/oauth2/revoke")
            .basic_auth(&self.client_id, Some(&self.client_secret))
            .form(&[("token", token)])
            .send()
            .await
            .map_err(|e| OAuthError::FlowError(format!("Revoke request failed: {e}")))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(OAuthError::FlowError(format!(
                "X revoke failed: {body}"
            )));
        }

        Ok(())
    }

    fn token_ttl(&self) -> Duration {
        Duration::from_secs(2 * 3600) // X tokens expire in 2 hours
    }

    fn supports_pkce(&self) -> bool {
        true
    }
}

fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
