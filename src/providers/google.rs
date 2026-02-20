use async_trait::async_trait;
use serde::Deserialize;
use std::time::Duration;

use super::traits::{OAuthProvider, TokenSet};
use crate::error::OAuthError;

/// Google OAuth 2.0 provider.
///
/// Supports: Gmail, Calendar, Drive, Sheets, and all Google API scopes.
/// Token lifetime: 1 hour.
/// Refresh: Supported (requires `access_type=offline` and `prompt=consent`).
pub struct GoogleProvider {
    client_id: String,
    client_secret: String,
    http: reqwest::Client,
}

// Raw token response from Google's token endpoint
#[derive(Debug, Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    token_type: String,
    expires_in: Option<u64>,
    scope: Option<String>,
}

impl GoogleProvider {
    pub fn new(client_id: String, client_secret: String) -> Self {
        Self {
            client_id,
            client_secret,
            http: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl OAuthProvider for GoogleProvider {
    fn id(&self) -> &str {
        "google"
    }

    fn display_name(&self) -> &str {
        "Google"
    }

    fn available_scopes(&self) -> Vec<String> {
        vec![
            "https://www.googleapis.com/auth/gmail.readonly".into(),
            "https://www.googleapis.com/auth/gmail.send".into(),
            "https://www.googleapis.com/auth/gmail.modify".into(),
            "https://www.googleapis.com/auth/calendar".into(),
            "https://www.googleapis.com/auth/calendar.readonly".into(),
            "https://www.googleapis.com/auth/drive".into(),
            "https://www.googleapis.com/auth/drive.readonly".into(),
            "https://www.googleapis.com/auth/spreadsheets".into(),
            "https://www.googleapis.com/auth/spreadsheets.readonly".into(),
            "https://www.googleapis.com/auth/documents".into(),
            "https://www.googleapis.com/auth/documents.readonly".into(),
            "openid".into(),
            "email".into(),
            "profile".into(),
        ]
    }

    fn auth_url(&self, scopes: &[String], state: &str, redirect_uri: &str) -> String {
        let scope_str = scopes.join(" ");
        format!(
            "https://accounts.google.com/o/oauth2/v2/auth?\
             client_id={client_id}\
             &redirect_uri={redirect_uri}\
             &response_type=code\
             &scope={scope}\
             &state={state}\
             &access_type=offline\
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
            .post("https://oauth2.googleapis.com/token")
            .form(&[
                ("code", code),
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
                ("redirect_uri", redirect_uri),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await
            .map_err(|e| OAuthError::FlowError(format!("Token exchange request failed: {e}")))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(OAuthError::FlowError(format!(
                "Google token exchange failed: {body}"
            )));
        }

        let token_resp: GoogleTokenResponse = resp
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
            .post("https://oauth2.googleapis.com/token")
            .form(&[
                ("refresh_token", refresh_token),
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
                ("grant_type", "refresh_token"),
            ])
            .send()
            .await
            .map_err(|e| OAuthError::RefreshFailed(format!("Refresh request failed: {e}")))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(OAuthError::RefreshFailed(format!(
                "Google refresh failed: {body}"
            )));
        }

        let token_resp: GoogleTokenResponse = resp
            .json()
            .await
            .map_err(|e| OAuthError::RefreshFailed(format!("Failed to parse refresh response: {e}")))?;

        Ok(TokenSet {
            access_token: token_resp.access_token,
            // Google doesn't always return a new refresh token on refresh
            refresh_token: token_resp.refresh_token,
            token_type: token_resp.token_type,
            expires_in: token_resp.expires_in,
            scope: token_resp.scope,
        })
    }

    async fn revoke(&self, token: &str) -> Result<(), OAuthError> {
        let resp = self
            .http
            .post("https://oauth2.googleapis.com/revoke")
            .form(&[("token", token)])
            .send()
            .await
            .map_err(|e| OAuthError::FlowError(format!("Revoke request failed: {e}")))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(OAuthError::FlowError(format!(
                "Google revoke failed: {body}"
            )));
        }

        Ok(())
    }

    fn token_ttl(&self) -> Duration {
        Duration::from_secs(3600) // Google tokens expire in 1 hour
    }

    fn supports_pkce(&self) -> bool {
        true
    }
}

/// Simple percent-encoding for URL parameters.
fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
