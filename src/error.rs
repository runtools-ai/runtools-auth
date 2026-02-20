use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Unified error type for the runtools-auth service.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    // ── Auth Errors ─────────────────────────────────────────────────────
    #[error("Authentication required")]
    Unauthorized,

    #[error("Insufficient permissions: {0}")]
    Forbidden(String),

    #[error("Invalid token: {0}")]
    InvalidToken(String),

    #[error("Token expired")]
    TokenExpired,

    // ── Resource Errors ─────────────────────────────────────────────────
    #[error("{0} not found")]
    NotFound(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    // ── Crypto Errors ───────────────────────────────────────────────────
    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    // ── Provider Errors ─────────────────────────────────────────────────
    #[error("OAuth provider error: {0}")]
    ProviderError(String),

    #[error("Provider {0} not found")]
    ProviderNotFound(String),

    // ── Internal ────────────────────────────────────────────────────────
    #[error("Database error: {0}")]
    Database(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("WorkOS error: {0}")]
    WorkOS(String),

    // ── Legacy variants (used by existing crypto/provider code) ─────────
    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Invalid state parameter")]
    InvalidState,

    #[error("OAuth flow error: {0}")]
    FlowError(String),

    #[error("Token refresh failed: {0}")]
    RefreshFailed(String),
}

/// Backward-compat alias: existing crypto + provider modules reference `OAuthError`.
pub type OAuthError = AuthError;

impl From<sqlx::Error> for AuthError {
    fn from(e: sqlx::Error) -> Self {
        tracing::error!("Database error: {e}");
        AuthError::Database(e.to_string())
    }
}

impl From<anyhow::Error> for AuthError {
    fn from(e: anyhow::Error) -> Self {
        AuthError::Internal(e.to_string())
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            AuthError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            AuthError::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
            AuthError::InvalidToken(_) => (StatusCode::UNAUTHORIZED, "invalid_token"),
            AuthError::TokenExpired => (StatusCode::UNAUTHORIZED, "token_expired"),
            AuthError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
            AuthError::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            AuthError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            AuthError::Encryption(_) => (StatusCode::INTERNAL_SERVER_ERROR, "encryption_error"),
            AuthError::Decryption(_) => (StatusCode::INTERNAL_SERVER_ERROR, "decryption_error"),
            AuthError::ProviderError(_) => (StatusCode::BAD_GATEWAY, "provider_error"),
            AuthError::ProviderNotFound(_) => (StatusCode::NOT_FOUND, "provider_not_found"),
            AuthError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, "database_error"),
            AuthError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
            AuthError::WorkOS(_) => (StatusCode::BAD_GATEWAY, "workos_error"),
            // Legacy variants
            AuthError::CryptoError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "crypto_error"),
            AuthError::InvalidState => (StatusCode::BAD_REQUEST, "invalid_state"),
            AuthError::FlowError(_) => (StatusCode::BAD_GATEWAY, "flow_error"),
            AuthError::RefreshFailed(_) => (StatusCode::BAD_GATEWAY, "refresh_failed"),
        };

        let body = json!({
            "error": {
                "code": code,
                "message": self.to_string(),
            }
        });

        (status, axum::Json(body)).into_response()
    }
}
