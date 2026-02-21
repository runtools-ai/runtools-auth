use async_trait::async_trait;
use serde::Deserialize;
use std::time::Duration;

use super::traits::{OAuthProvider, TokenSet};
use crate::error::OAuthError;

/// WhatsApp Business provider (via Meta/Facebook OAuth 2.0).
///
/// WhatsApp Business API uses Meta's Graph API and OAuth 2.0 flow.
/// This is the same underlying auth system as Facebook/Instagram but
/// with WhatsApp-specific permissions.
///
/// Quirks:
/// - Uses Facebook's OAuth 2.0 endpoints.
/// - Access tokens: short-lived (1–2 hours) → exchange for long-lived (60 days).
/// - System User tokens don't expire (for server-to-server).
/// - WhatsApp Business API requires approved Meta App with business verification.
pub struct WhatsAppProvider {
    client_id: String,     // Meta App ID
    client_secret: String, // Meta App Secret
    http: reqwest::Client,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct MetaTokenResponse {
    access_token: String,
    token_type: Option<String>,
    expires_in: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct MetaLongLivedTokenResponse {
    access_token: String,
    token_type: Option<String>,
    expires_in: Option<u64>,
}

impl WhatsAppProvider {
    pub fn new(client_id: String, client_secret: String) -> Self {
        Self {
            client_id,
            client_secret,
            http: reqwest::Client::new(),
        }
    }

    /// Exchange a short-lived token for a long-lived one (60 days).
    async fn get_long_lived_token(&self, short_token: &str) -> Result<TokenSet, OAuthError> {
        let resp = self
            .http
            .get("https://graph.facebook.com/v21.0/oauth/access_token")
            .query(&[
                ("grant_type", "fb_exchange_token"),
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
                ("fb_exchange_token", short_token),
            ])
            .send()
            .await
            .map_err(|e| OAuthError::FlowError(format!("Long-lived token request failed: {e}")))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(OAuthError::FlowError(format!(
                "Long-lived token exchange failed: {body}"
            )));
        }

        let token_resp: MetaLongLivedTokenResponse = resp
            .json()
            .await
            .map_err(|e| OAuthError::FlowError(format!("Failed to parse response: {e}")))?;

        Ok(TokenSet {
            access_token: token_resp.access_token,
            refresh_token: None, // Meta long-lived tokens don't have refresh tokens
            token_type: token_resp.token_type.unwrap_or_else(|| "bearer".into()),
            expires_in: token_resp.expires_in,
            scope: None,
        })
    }
}

#[async_trait]
impl OAuthProvider for WhatsAppProvider {
    fn id(&self) -> &str {
        "whatsapp"
    }

    fn display_name(&self) -> &str {
        "WhatsApp Business"
    }

    fn available_scopes(&self) -> Vec<String> {
        vec![
            "whatsapp_business_management".into(),
            "whatsapp_business_messaging".into(),
            "business_management".into(),
            "pages_messaging".into(),
            "public_profile".into(),
            "email".into(),
        ]
    }

    fn auth_url(&self, scopes: &[String], state: &str, redirect_uri: &str) -> String {
        let scope_str = scopes.join(",");
        format!(
            "https://www.facebook.com/v21.0/dialog/oauth?\
             client_id={client_id}\
             &redirect_uri={redirect_uri}\
             &scope={scope}\
             &state={state}\
             &response_type=code",
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
        // Step 1: Exchange code for short-lived token
        let resp = self
            .http
            .get("https://graph.facebook.com/v21.0/oauth/access_token")
            .query(&[
                ("code", code),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("redirect_uri", redirect_uri),
            ])
            .send()
            .await
            .map_err(|e| OAuthError::FlowError(format!("Token exchange request failed: {e}")))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(OAuthError::FlowError(format!(
                "WhatsApp token exchange failed: {body}"
            )));
        }

        let short_token: MetaTokenResponse = resp
            .json()
            .await
            .map_err(|e| OAuthError::FlowError(format!("Failed to parse token response: {e}")))?;

        // Step 2: Exchange short-lived for long-lived token (60 days)
        self.get_long_lived_token(&short_token.access_token).await
    }

    async fn refresh_token(&self, _refresh_token: &str) -> Result<TokenSet, OAuthError> {
        // Meta long-lived tokens can't be refreshed with a refresh token.
        // You need to re-authenticate or use a System User token (which doesn't expire).
        Err(OAuthError::RefreshFailed(
            "Meta/WhatsApp long-lived tokens cannot be refreshed. Re-authentication required.".into(),
        ))
    }

    async fn revoke(&self, token: &str) -> Result<(), OAuthError> {
        // Meta token revocation via Graph API
        let resp = self
            .http
            .delete(format!(
                "https://graph.facebook.com/v21.0/me/permissions?access_token={token}"
            ))
            .send()
            .await
            .map_err(|e| OAuthError::FlowError(format!("Revoke request failed: {e}")))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(OAuthError::FlowError(format!(
                "WhatsApp revoke failed: {body}"
            )));
        }

        Ok(())
    }

    fn token_ttl(&self) -> Duration {
        Duration::from_secs(60 * 24 * 3600) // Long-lived tokens last 60 days
    }

    fn supports_pkce(&self) -> bool {
        false
    }
}

fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
