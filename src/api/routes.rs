//! API route handlers for the unified runtools-auth service.
//!
//! All handlers receive `SharedState` via Axum state extraction.
//! Authentication for credential management endpoints is done via
//! the same verify logic this service exposes.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{delete, get, patch, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;

use crate::auth::verify;
use crate::auth::AuthContext;
use crate::credentials;
use crate::error::AuthError;
use crate::store::db::ConnectionUpsert;
use crate::webhooks::workos as workos_webhooks;
use crate::SharedState;

// =============================================================================
// V1 Router
// =============================================================================

pub fn v1_router(state: SharedState) -> Router {
    Router::new()
        // ── Health ───────────────────────────────────────────────────────
        .route("/status", get(status))
        // ── Auth ─────────────────────────────────────────────────────────
        .route("/auth/verify", post(auth_verify))
        .route("/auth/resolve", get(auth_resolve))
        .route("/auth/logout-url", get(auth_logout_url))
        // ── API Keys ─────────────────────────────────────────────────────
        .route("/api-keys", post(api_key_create))
        .route("/api-keys", get(api_key_list))
        .route("/api-keys/{id}", get(api_key_get))
        .route("/api-keys/{id}", patch(api_key_update))
        .route("/api-keys/{id}", delete(api_key_revoke))
        .route("/api-keys/verify", post(api_key_verify))
        // ── SSH Keys ─────────────────────────────────────────────────────
        .route("/ssh-keys", post(ssh_key_create))
        .route("/ssh-keys", get(ssh_key_list))
        .route("/ssh-keys/{id}", delete(ssh_key_delete))
        .route("/ssh-keys/for-sandbox", get(ssh_keys_for_sandbox))
        // ── Secrets ──────────────────────────────────────────────────────
        .route("/secrets", post(secret_upsert))
        .route("/secrets", get(secret_list))
        .route("/secrets/{name}/reveal", post(secret_reveal))
        .route("/secrets/{name}", delete(secret_delete))
        .route("/secrets/{name}/inject", get(secret_inject))
        // ── OAuth ────────────────────────────────────────────────────────
        .route("/oauth/providers", get(oauth_providers))
        .route("/oauth/start/{provider}", get(oauth_start))
        .route("/oauth/callback/{provider}", get(oauth_callback))
        .route("/oauth/token/{provider}", get(oauth_token))
        .route("/oauth/connections", get(oauth_connections))
        .route("/oauth/connections/{id}", delete(oauth_connection_delete))
        // ── Webhooks ─────────────────────────────────────────────────────
        .route("/webhooks/workos", post(workos_webhooks::workos_webhook))
        .with_state(state)
}

// =============================================================================
// Health
// =============================================================================

async fn status() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "service": "runtools-auth",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

// =============================================================================
// Auth Endpoints
// =============================================================================

#[derive(Deserialize)]
struct VerifyRequest {
    token: String,
    /// If the caller knows the org_id (from headers), pass it here.
    org_id: Option<String>,
    /// If the caller knows the user_id (from headers), pass it here.
    user_id: Option<String>,
}

/// POST /v1/auth/verify — Verify a JWT or API key and return AuthContext.
///
/// This is the main endpoint that all services call to authenticate requests.
/// Replaces the duplicated validateWorkOSToken/verifyRuntoolsApiKey logic.
async fn auth_verify(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<VerifyRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    // Check for internal service-to-service auth
    if let Some(internal) = headers.get("x-internal-secret") {
        let internal_str = internal.to_str().unwrap_or_default();
        let org_id = body.org_id.as_deref().unwrap_or_default();
        let user_id = body.user_id.as_deref().unwrap_or("system");
        let ctx = verify::verify_internal(
            internal_str,
            &state.config.auth_service_secret,
            org_id,
            user_id,
        )?;
        return Ok(Json(json!({ "data": ctx })));
    }

    let token = &body.token;

    // Try API key first (starts with rt_)
    if token.starts_with("rt_") {
        let ctx = verify::verify_api_key(token, state.store.pool()).await?;
        return Ok(Json(json!({ "data": ctx })));
    }

    // Try JWT (starts with eyJ)
    if token.starts_with("eyJ") {
        let ctx = verify::verify_token(token, state.store.pool(), Some(&state.jwks)).await?;
        return Ok(Json(json!({ "data": ctx })));
    }

    Err(AuthError::InvalidToken("unrecognized token format".into()))
}

#[derive(Deserialize)]
struct ResolveQuery {
    workos_user_id: Option<String>,
    workos_org_id: Option<String>,
    internal_user_id: Option<String>,
    internal_org_id: Option<String>,
}

/// GET /v1/auth/resolve — Bidirectional ID resolution (WorkOS ↔ internal).
///
/// Used during migration — services that still need internal UUIDs for DB joins
/// can call this to translate.
async fn auth_resolve(
    State(state): State<SharedState>,
    Query(q): Query<ResolveQuery>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let resolved = verify::resolve_ids(
        state.store.pool(),
        q.workos_user_id.as_deref(),
        q.workos_org_id.as_deref(),
        q.internal_user_id.as_deref(),
        q.internal_org_id.as_deref(),
    )
    .await?;

    Ok(Json(json!({ "data": resolved })))
}

#[derive(serde::Deserialize)]
struct LogoutUrlQuery {
    session_id: String,
    return_to: Option<String>,
}

/// GET /v1/auth/logout-url — Get a WorkOS logout URL for a given session ID.
///
/// Calls the WorkOS REST API directly (no SDK required in Rust).
async fn auth_logout_url(
    State(state): State<SharedState>,
    Query(q): Query<LogoutUrlQuery>,
) -> Result<Json<serde_json::Value>, AuthError> {
    if state.config.workos_api_key.is_none() {
        return Err(AuthError::Internal("WORKOS_API_KEY not configured".into()));
    }

    // Helper to percent-encode a string using the url crate
    let encode = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();

    let mut logout_url = format!(
        "https://api.workos.com/user_management/sessions/logout?session_id={}",
        encode(&q.session_id)
    );
    if let Some(return_to) = &q.return_to {
        logout_url.push_str(&format!("&return_to={}", encode(return_to)));
    }

    Ok(Json(json!({ "data": { "url": logout_url } })))
}

// =============================================================================
// API Key Endpoints
// =============================================================================


/// Extract and verify auth from headers for protected endpoints.
async fn require_auth(
    state: &SharedState,
    headers: &HeaderMap,
) -> Result<AuthContext, AuthError> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthError::Unauthorized)?;

    let token = if auth_header.starts_with("Bearer ") {
        &auth_header[7..]
    } else {
        return Err(AuthError::Unauthorized);
    };

    // Internal secret check
    if let Some(internal) = headers.get("x-internal-secret") {
        let org_id = headers
            .get("x-org-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        let user_id = headers
            .get("x-user-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("system");
        return verify::verify_internal(
            internal.to_str().unwrap_or_default(),
            &state.config.auth_service_secret,
            org_id,
            user_id,
        );
    }

    if token.starts_with("rt_") {
        verify::verify_api_key(token, state.store.pool()).await
    } else if token.starts_with("eyJ") {
        verify::verify_token(token, state.store.pool(), Some(&state.jwks)).await
    } else {
        Err(AuthError::InvalidToken("unrecognized token format".into()))
    }
}

#[derive(Deserialize)]
struct CreateApiKeyBody {
    name: String,
    #[serde(default)]
    scopes: Vec<String>,
    expires_in: Option<String>,
    #[serde(default)]
    is_test: bool,
}

async fn api_key_create(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<CreateApiKeyBody>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let auth = require_auth(&state, &headers).await?;
    let org_id = auth
        .internal_org_id
        .as_deref()
        .ok_or_else(|| AuthError::BadRequest("org context required".into()))?;

    let result = credentials::keys::create_api_key(
        state.store.pool(),
        org_id,
        &body.name,
        &body.scopes,
        auth.internal_user_id.as_deref(),
        body.expires_in.as_deref(),
        body.is_test,
    )
    .await?;

    Ok(Json(json!({
        "data": result,
        "message": "Store this key securely. You will not be able to see it again."
    })))
}

async fn api_key_list(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AuthError> {
    let auth = require_auth(&state, &headers).await?;
    let org_id = auth
        .internal_org_id
        .as_deref()
        .ok_or_else(|| AuthError::BadRequest("org context required".into()))?;

    let keys = credentials::keys::list_api_keys(state.store.pool(), org_id).await?;

    Ok(Json(json!({ "data": keys })))
}

async fn api_key_get(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let auth = require_auth(&state, &headers).await?;
    let org_id = auth
        .internal_org_id
        .as_deref()
        .ok_or_else(|| AuthError::BadRequest("org context required".into()))?;

    let key = credentials::keys::get_api_key(state.store.pool(), &id, org_id).await?;

    Ok(Json(json!({ "data": key })))
}

#[derive(Deserialize)]
struct UpdateApiKeyBody {
    name: Option<String>,
    scopes: Option<Vec<String>>,
}

async fn api_key_update(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<UpdateApiKeyBody>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let auth = require_auth(&state, &headers).await?;
    let org_id = auth
        .internal_org_id
        .as_deref()
        .ok_or_else(|| AuthError::BadRequest("org context required".into()))?;

    credentials::keys::update_api_key(
        state.store.pool(),
        &id,
        org_id,
        body.name.as_deref(),
        body.scopes.as_deref(),
    )
    .await?;

    Ok(Json(json!({ "data": { "success": true } })))
}

async fn api_key_revoke(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let auth = require_auth(&state, &headers).await?;
    let org_id = auth
        .internal_org_id
        .as_deref()
        .ok_or_else(|| AuthError::BadRequest("org context required".into()))?;

    credentials::keys::revoke_api_key(state.store.pool(), &id, org_id).await?;

    Ok(Json(json!({ "data": { "success": true } })))
}

#[derive(Deserialize)]
struct VerifyApiKeyBody {
    key: String,
}

/// POST /v1/api-keys/verify — Internal endpoint for other services to verify API keys.
async fn api_key_verify(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<VerifyApiKeyBody>,
) -> Result<Json<serde_json::Value>, AuthError> {
    // This endpoint requires internal auth
    let internal = headers
        .get("x-internal-secret")
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthError::Unauthorized)?;

    if internal != state.config.auth_service_secret {
        return Err(AuthError::Unauthorized);
    }

    let ctx = verify::verify_api_key(&body.key, state.store.pool()).await?;

    Ok(Json(json!({ "data": ctx })))
}

// =============================================================================
// SSH Key Endpoints
// =============================================================================

#[derive(Deserialize)]
struct CreateSshKeyBody {
    name: String,
    public_key: String,
}

async fn ssh_key_create(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<CreateSshKeyBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), AuthError> {
    let auth = require_auth(&state, &headers).await?;
    let org_id = auth
        .internal_org_id
        .as_deref()
        .ok_or_else(|| AuthError::BadRequest("org context required".into()))?;

    let result =
        credentials::ssh::create_ssh_key(state.store.pool(), org_id, &body.name, &body.public_key)
            .await?;

    Ok((StatusCode::CREATED, Json(json!({ "data": result }))))
}

async fn ssh_key_list(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AuthError> {
    let auth = require_auth(&state, &headers).await?;
    let org_id = auth
        .internal_org_id
        .as_deref()
        .ok_or_else(|| AuthError::BadRequest("org context required".into()))?;

    let keys = credentials::ssh::list_ssh_keys(state.store.pool(), org_id).await?;

    Ok(Json(json!({ "data": keys })))
}

async fn ssh_key_delete(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let auth = require_auth(&state, &headers).await?;
    let org_id = auth
        .internal_org_id
        .as_deref()
        .ok_or_else(|| AuthError::BadRequest("org context required".into()))?;

    credentials::ssh::delete_ssh_key(state.store.pool(), &id, org_id).await?;

    Ok(Json(json!({ "data": { "success": true } })))
}

#[derive(Deserialize)]
struct SshForSandboxQuery {
    org_id: String,
    #[serde(default)]
    key_ids: Vec<String>,
}

/// GET /v1/ssh-keys/for-sandbox — Internal endpoint to get SSH keys for sandbox creation.
async fn ssh_keys_for_sandbox(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<SshForSandboxQuery>,
) -> Result<Json<serde_json::Value>, AuthError> {
    // Internal-only endpoint
    let internal = headers
        .get("x-internal-secret")
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthError::Unauthorized)?;

    if internal != state.config.auth_service_secret {
        return Err(AuthError::Unauthorized);
    }

    let keys = credentials::ssh::get_keys_for_sandbox(state.store.pool(), &q.org_id, &q.key_ids)
        .await?;

    Ok(Json(json!({ "data": keys })))
}

// =============================================================================
// Secrets Endpoints
// =============================================================================

#[derive(Deserialize)]
struct UpsertSecretBody {
    name: String,
    value: String,
    #[serde(default = "default_scope")]
    scope: String,
    /// Optional category for grouping (e.g. 'provider', 'custom'). Defaults to 'custom'.
    category: Option<String>,
    description: Option<String>,
}

fn default_scope() -> String {
    "all".into()
}

async fn secret_upsert(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<UpsertSecretBody>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let auth = require_auth(&state, &headers).await?;
    let org_id = auth
        .internal_org_id
        .as_deref()
        .ok_or_else(|| AuthError::BadRequest("org context required".into()))?;

    let result = credentials::secrets::upsert_secret(
        state.store.pool(),
        &state.crypto,
        org_id,
        &body.name,
        &body.value,
        &body.scope,
        body.category.as_deref(),
        body.description.as_deref(),
        auth.internal_user_id.as_deref(),
    )
    .await?;

    Ok(Json(json!({ "data": result })))
}

#[derive(Deserialize)]
struct ListSecretsQuery {
    scope: Option<String>,
}

async fn secret_list(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<ListSecretsQuery>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let auth = require_auth(&state, &headers).await?;
    let org_id = auth
        .internal_org_id
        .as_deref()
        .ok_or_else(|| AuthError::BadRequest("org context required".into()))?;

    let secrets =
        credentials::secrets::list_secrets(state.store.pool(), org_id, q.scope.as_deref())
            .await?;

    Ok(Json(json!({ "data": secrets })))
}

async fn secret_reveal(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let auth = require_auth(&state, &headers).await?;
    let org_id = auth
        .internal_org_id
        .as_deref()
        .ok_or_else(|| AuthError::BadRequest("org context required".into()))?;

    let value =
        credentials::secrets::reveal_secret(state.store.pool(), &state.crypto, org_id, &name)
            .await?;

    // Audit log
    let _ = state
        .store
        .log_event(
            &auth.org_id,
            &auth.user_id,
            "secret.revealed",
            "",
            serde_json::json!({ "name": name }),
        )
        .await;

    Ok(Json(json!({ "data": { "name": name, "value": value } })))
}

async fn secret_delete(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let auth = require_auth(&state, &headers).await?;
    let org_id = auth
        .internal_org_id
        .as_deref()
        .ok_or_else(|| AuthError::BadRequest("org context required".into()))?;

    credentials::secrets::delete_secret(state.store.pool(), org_id, &name).await?;

    Ok(Json(json!({ "data": { "success": true } })))
}

#[derive(Deserialize)]
struct InjectSecretQuery {
    org_id: String,
    #[serde(default = "default_scope")]
    scope: String,
}

/// GET /v1/secrets/:name/inject — Internal endpoint for sandbox secret injection.
async fn secret_inject(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(q): Query<InjectSecretQuery>,
) -> Result<Json<serde_json::Value>, AuthError> {
    // Internal-only
    let internal = headers
        .get("x-internal-secret")
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthError::Unauthorized)?;

    if internal != state.config.auth_service_secret {
        return Err(AuthError::Unauthorized);
    }

    let value = credentials::secrets::get_secret_for_injection(
        state.store.pool(),
        &state.crypto,
        &q.org_id,
        &name,
        &q.scope,
    )
    .await?;

    Ok(Json(json!({ "data": { "name": name, "value": value } })))
}

// =============================================================================
// OAuth Endpoints
// =============================================================================

/// GET /v1/oauth/providers — List available OAuth providers.
async fn oauth_providers(State(state): State<SharedState>) -> impl IntoResponse {
    let providers: Vec<&str> = state.registry.list();
    Json(json!({ "data": providers }))
}

#[derive(Deserialize)]
struct OAuthStartQuery {
    org_id: String,
    #[serde(default)]
    user_id: String,
    #[serde(default)]
    scopes: String,
}

/// GET /v1/oauth/start/:provider — Initiate an OAuth flow.
///
/// Requires authentication — prevents unauthenticated users from initiating OAuth flows.
async fn oauth_start(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(provider_id): Path<String>,
    Query(q): Query<OAuthStartQuery>,
) -> Result<Response, AuthError> {
    // Require authentication before initiating OAuth
    let _auth = require_auth(&state, &headers).await?;

    let provider = state
        .registry
        .get(&provider_id)
        .ok_or_else(|| AuthError::ProviderNotFound(provider_id.clone()))?;

    // Build state parameter: orgId:userId:timestamp
    let timestamp = chrono::Utc::now().timestamp();
    let state_data = format!("{}:{}:{}", q.org_id, q.user_id, timestamp);
    let signed_state = state
        .crypto
        .sign_state(&state_data)
        .map_err(|e| AuthError::Internal(e.to_string()))?;

    let scopes: Vec<String> = if q.scopes.is_empty() {
        vec![]
    } else {
        q.scopes.split(',').map(|s| s.trim().to_string()).collect()
    };

    let callback_url = state.config.callback_url(&provider_id);
    let auth_url = provider.auth_url(&scopes, &signed_state, &callback_url);

    Ok(Redirect::temporary(&auth_url).into_response())
}

#[derive(Deserialize)]
struct OAuthCallbackQuery {
    code: String,
    state: String,
}

/// GET /v1/oauth/callback/:provider — Handle OAuth callback.
async fn oauth_callback(
    State(state): State<SharedState>,
    Path(provider_id): Path<String>,
    Query(q): Query<OAuthCallbackQuery>,
) -> Result<Response, AuthError> {
    // Verify state signature
    let state_data = state
        .crypto
        .verify_state(&q.state)
        .map_err(|_| AuthError::BadRequest("invalid state parameter".into()))?;

    // Parse state: org_id:user_id:timestamp
    let parts: Vec<&str> = state_data.split(':').collect();
    if parts.len() < 3 {
        return Err(AuthError::BadRequest("malformed state parameter".into()));
    }

    let org_id = parts[0].to_string();
    let user_id = parts[1].to_string();
    let timestamp: i64 = parts[2]
        .parse()
        .map_err(|_| AuthError::BadRequest("invalid timestamp in state".into()))?;

    // Check 10-minute expiry on state
    let now = chrono::Utc::now().timestamp();
    if now - timestamp > 600 {
        return Err(AuthError::BadRequest("OAuth session expired".into()));
    }

    // Exchange code for tokens
    let provider = state
        .registry
        .get(&provider_id)
        .ok_or_else(|| AuthError::ProviderNotFound(provider_id.clone()))?;

    let callback_url = state.config.callback_url(&provider_id);
    let tokens = provider
        .exchange_code(&q.code, &callback_url)
        .await
        .map_err(|e| AuthError::ProviderError(e.to_string()))?;

    let expires_at = tokens
        .expires_in
        .map(|secs| chrono::Utc::now() + chrono::Duration::seconds(secs as i64));

    // Store the connection
    let conn = ConnectionUpsert {
        org_id: org_id.clone(),
        user_id: user_id.clone(),
        provider: provider_id.clone(),
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        token_type: tokens.token_type,
        scopes: tokens.scope.unwrap_or_default(),
        expires_at,
        platform_user_id: String::new(),
        platform_username: String::new(),
        display_name: String::new(),
        profile_image_url: String::new(),
        raw_profile: None,
    };

    let conn_id = state.store.upsert_connection(&state.crypto, &conn).await?;

    // Audit log
    let _ = state
        .store
        .log_event(
            &org_id,
            &user_id,
            "oauth.connected",
            &provider_id,
            json!({ "connection_id": conn_id }),
        )
        .await;

    // Redirect to success page
    let redirect_url = format!(
        "{}/oauth/success?provider={}&connection_id={}",
        state.config.base_url, provider_id, conn_id
    );
    Ok(Redirect::temporary(&redirect_url).into_response())
}

#[derive(Deserialize)]
struct OAuthTokenQuery {
    org_id: String,
    #[serde(default)]
    user_id: String,
}

/// GET /v1/oauth/token/:provider — Get a valid access token (auto-refreshes if expired).
async fn oauth_token(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(provider_id): Path<String>,
    Query(q): Query<OAuthTokenQuery>,
) -> Result<Json<serde_json::Value>, AuthError> {
    // Require internal auth for token retrieval
    let internal = headers
        .get("x-internal-secret")
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthError::Unauthorized)?;

    if internal != state.config.auth_service_secret {
        return Err(AuthError::Unauthorized);
    }

    let token = state
        .store
        .get_token(&state.crypto, &q.org_id, &q.user_id, &provider_id)
        .await?;

    let token = token.ok_or_else(|| AuthError::NotFound("OAuth connection".into()))?;

    // If expired, try to refresh
    if token.is_expired {
        if let Some(ref rt) = token.refresh_token {
            let provider = state
                .registry
                .get(&provider_id)
                .ok_or_else(|| AuthError::ProviderNotFound(provider_id.clone()))?;

            match provider.refresh_token(rt).await {
                Ok(new_tokens) => {
                    let expires_at = new_tokens
                        .expires_in
                        .map(|secs| chrono::Utc::now() + chrono::Duration::seconds(secs as i64));

                    state
                        .store
                        .update_refreshed_tokens(
                            &state.crypto,
                            &token.id,
                            &new_tokens.access_token,
                            new_tokens.refresh_token.as_deref(),
                            expires_at,
                        )
                        .await?;

                    return Ok(Json(json!({
                        "data": {
                            "access_token": new_tokens.access_token,
                            "expires_at": expires_at,
                            "refreshed": true,
                        }
                    })));
                }
                Err(e) => {
                    return Err(AuthError::ProviderError(format!(
                        "token refresh failed: {e}"
                    )));
                }
            }
        }

        return Err(AuthError::ProviderError(
            "token expired and no refresh token available".into(),
        ));
    }

    Ok(Json(json!({
        "data": {
            "access_token": token.access_token,
            "expires_at": token.expires_at,
            "refreshed": false,
        }
    })))
}

/// GET /v1/oauth/connections — List OAuth connections.
async fn oauth_connections(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<OAuthTokenQuery>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let _auth = require_auth(&state, &headers).await?;

    let connections = state
        .store
        .list_connections(&q.org_id, Some(&q.user_id))
        .await?;

    Ok(Json(json!({ "data": connections })))
}

/// DELETE /v1/oauth/connections/:id — Delete an OAuth connection.
///
/// Uses internal_org_id (UUID) for DB lookup since oauth_connections.org_id stores
/// internal UUIDs, not WorkOS org IDs.
async fn oauth_connection_delete(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let auth = require_auth(&state, &headers).await?;

    // Use internal_org_id for DB operations (oauth_connections.org_id = internal UUID)
    let org_id = auth.internal_org_id.as_deref()
        .or(if !auth.org_id.is_empty() { Some(auth.org_id.as_str()) } else { None })
        .ok_or_else(|| AuthError::BadRequest("could not resolve org_id".into()))?;

    state
        .store
        .delete_connection(&id, org_id)
        .await?;

    Ok(Json(json!({ "data": { "success": true } })))
}
