use async_trait::async_trait;
use serde::Deserialize;
use std::time::Duration;

use super::traits::{OAuthProvider, TokenSet};
use crate::error::OAuthError;

/// Microsoft OAuth 2.0 provider (Azure AD v2.0).
///
/// Quirks:
/// - Uses Azure AD v2.0 endpoint (supports personal + work accounts).
/// - Multi-tenant by default (`common` endpoint).
/// - Refresh tokens supported and recommended.
/// - Scopes must include `offline_access` to get refresh tokens.
/// - Token lifetime: 1 hour (access), 90 days (refresh).
pub struct MicrosoftProvider {
    client_id: String,
    client_secret: String,
    http: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct MicrosoftTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    scope: Option<String>,
}

impl MicrosoftProvider {
    pub fn new(client_id: String, client_secret: String) -> Self {
        Self {
            client_id,
            client_secret,
            http: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl OAuthProvider for MicrosoftProvider {
    fn id(&self) -> &str {
        "microsoft"
    }

    fn display_name(&self) -> &str {
        "Microsoft"
    }

    fn available_scopes(&self) -> Vec<String> {
        vec![
            "openid".into(),
            "profile".into(),
            "email".into(),
            "offline_access".into(),
            "User.Read".into(),
            "Mail.Read".into(),
            "Mail.Send".into(),
            "Mail.ReadWrite".into(),
            "Calendars.Read".into(),
            "Calendars.ReadWrite".into(),
            "Files.Read".into(),
            "Files.Read.All".into(),
            "Files.ReadWrite".into(),
            "Files.ReadWrite.All".into(),
            "Sites.Read.All".into(),
            "Sites.ReadWrite.All".into(),
            "Notes.Read".into(),
            "Notes.ReadWrite".into(),
            "Tasks.Read".into(),
            "Tasks.ReadWrite".into(),
            "Chat.Read".into(),
            "Chat.ReadWrite".into(),
            "ChannelMessage.Read.All".into(),
            "Team.ReadBasic.All".into(),
        ]
    }

    fn auth_url(&self, scopes: &[String], state: &str, redirect_uri: &str) -> String {
        let scope_str = scopes.join(" ");
        format!(
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?\
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
            .post("https://login.microsoftonline.com/common/oauth2/v2.0/token")
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
                "Microsoft token exchange failed: {body}"
            )));
        }

        let token_resp: MicrosoftTokenResponse = resp
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
            .post("https://login.microsoftonline.com/common/oauth2/v2.0/token")
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
                "Microsoft refresh failed: {body}"
            )));
        }

        let token_resp: MicrosoftTokenResponse = resp
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

    async fn revoke(&self, _token: &str) -> Result<(), OAuthError> {
        // Microsoft doesn't have a straightforward token revocation endpoint
        // for v2.0 OAuth. The recommended approach is to use the "logout" endpoint
        // or simply let tokens expire. For now, we no-op.
        Ok(())
    }

    fn token_ttl(&self) -> Duration {
        Duration::from_secs(3600) // Microsoft access tokens expire in 1 hour
    }

    fn supports_pkce(&self) -> bool {
        true
    }
}

fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
