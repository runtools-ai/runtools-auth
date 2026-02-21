use async_trait::async_trait;
use serde::Deserialize;
use std::time::Duration;

use super::traits::{OAuthProvider, TokenSet};
use crate::error::OAuthError;

/// GitHub OAuth 2.0 provider.
///
/// Quirks:
/// - GitHub tokens do NOT expire by default (no refresh token).
/// - Scopes are space-separated in the auth URL but comma-separated in token response.
/// - Token response is JSON (with Accept: application/json header).
/// - Supports both user tokens and GitHub Apps (this implements user OAuth).
pub struct GitHubProvider {
    client_id: String,
    client_secret: String,
    http: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct GitHubTokenResponse {
    access_token: String,
    token_type: String,
    scope: Option<String>,
    // GitHub doesn't return refresh_token or expires_in for standard OAuth
    // (GitHub Apps with expiring tokens are different)
    refresh_token: Option<String>,
    expires_in: Option<u64>,
}

impl GitHubProvider {
    pub fn new(client_id: String, client_secret: String) -> Self {
        Self {
            client_id,
            client_secret,
            http: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl OAuthProvider for GitHubProvider {
    fn id(&self) -> &str {
        "github"
    }

    fn display_name(&self) -> &str {
        "GitHub"
    }

    fn available_scopes(&self) -> Vec<String> {
        vec![
            "repo".into(),
            "repo:status".into(),
            "repo_deployment".into(),
            "public_repo".into(),
            "read:org".into(),
            "write:org".into(),
            "admin:org".into(),
            "read:user".into(),
            "user:email".into(),
            "gist".into(),
            "notifications".into(),
            "workflow".into(),
            "read:packages".into(),
            "write:packages".into(),
            "admin:repo_hook".into(),
            "admin:org_hook".into(),
        ]
    }

    fn auth_url(&self, scopes: &[String], state: &str, redirect_uri: &str) -> String {
        let scope_str = scopes.join(" ");
        format!(
            "https://github.com/login/oauth/authorize?\
             client_id={client_id}\
             &redirect_uri={redirect_uri}\
             &scope={scope}\
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
            .post("https://github.com/login/oauth/access_token")
            .header("Accept", "application/json")
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
                "GitHub token exchange failed: {body}"
            )));
        }

        let token_resp: GitHubTokenResponse = resp
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

    async fn refresh_token(&self, _refresh_token: &str) -> Result<TokenSet, OAuthError> {
        // Standard GitHub OAuth tokens don't expire and don't have refresh tokens.
        // GitHub Apps with expiring tokens would need refresh, but that's a different flow.
        Err(OAuthError::RefreshFailed(
            "GitHub tokens do not expire — no refresh needed".into(),
        ))
    }

    async fn revoke(&self, token: &str) -> Result<(), OAuthError> {
        // GitHub uses DELETE to revoke OAuth app authorizations
        let resp = self
            .http
            .delete(format!(
                "https://api.github.com/applications/{}/token",
                self.client_id
            ))
            .basic_auth(&self.client_id, Some(&self.client_secret))
            .header("Accept", "application/vnd.github+json")
            .json(&serde_json::json!({ "access_token": token }))
            .send()
            .await
            .map_err(|e| OAuthError::FlowError(format!("Revoke request failed: {e}")))?;

        if !resp.status().is_success() && resp.status().as_u16() != 422 {
            let body = resp.text().await.unwrap_or_default();
            return Err(OAuthError::FlowError(format!(
                "GitHub revoke failed: {body}"
            )));
        }

        Ok(())
    }

    fn token_ttl(&self) -> Duration {
        // GitHub tokens don't expire — set to 30 days so we don't try to refresh
        Duration::from_secs(30 * 24 * 3600)
    }

    fn supports_pkce(&self) -> bool {
        false
    }
}

fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
