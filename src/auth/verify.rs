//! Authentication verification — JWT validation and API key verification.
//!
//! This module replaces the duplicated auth logic from:
//! - orchestrator `src/lib/auth.ts` (643 lines)
//! - tools service `src/lib/auth.ts` (222 lines)  
//! - billing service `src/lib/auth.ts` (202 lines)
//! - dashboard `src/lib/resolve-org.ts` (43 lines)

use crate::error::AuthError;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use tokio::sync::RwLock;

// ─────────────────────────────────────────────────────────────────────────────
// Auth Context — the unified identity object returned by all verify endpoints
// ─────────────────────────────────────────────────────────────────────────────

/// Canonical auth context returned by verify endpoints.
/// Every service in the platform receives this same shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    /// WorkOS user ID (e.g. "user_01HXYZ...") — canonical user identifier.
    pub user_id: String,

    /// WorkOS org ID (e.g. "org_01HXYZ...") — canonical org identifier.
    pub org_id: String,

    /// Internal user UUID from our `users` table (for DB joins).
    pub internal_user_id: Option<String>,

    /// Internal org UUID from our `organizations` table (for DB joins).
    pub internal_org_id: Option<String>,

    /// How this request was authenticated.
    pub auth_method: AuthMethod,

    /// WorkOS role (from JWT claims).
    pub role: Option<String>,

    /// WorkOS permissions (from JWT claims).
    pub permissions: Vec<String>,

    /// API key scopes (if authenticated via API key).
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    Workos,
    ApiKey,
    Internal,
}

// ─────────────────────────────────────────────────────────────────────────────
// JWKS Cache — Fetches and caches WorkOS signing keys for JWT verification
// ─────────────────────────────────────────────────────────────────────────────

/// JWKS response from WorkOS
#[derive(Debug, Deserialize, Clone)]
struct JwksResponse {
    keys: Vec<JwkKey>,
}

/// Individual JWK key
#[derive(Debug, Deserialize, Clone)]
struct JwkKey {
    kid: String,
    kty: String,
    #[serde(rename = "use")]
    key_use: Option<String>,
    n: String, // RSA modulus
    e: String, // RSA exponent
    alg: Option<String>,
}

/// Cached JWKS keys with expiration
struct JwksCache {
    keys: Vec<JwkKey>,
    fetched_at: std::time::Instant,
}

/// Thread-safe JWKS key cache
pub struct JwksKeyStore {
    cache: RwLock<Option<JwksCache>>,
    jwks_url: String,
    /// How long to cache JWKS keys (default 1 hour)
    cache_ttl: std::time::Duration,
}

impl JwksKeyStore {
    pub fn new(jwks_url: &str) -> Self {
        Self {
            cache: RwLock::new(None),
            jwks_url: jwks_url.to_string(),
            cache_ttl: std::time::Duration::from_secs(3600),
        }
    }

    /// WorkOS JWKS endpoint
    pub fn workos() -> Self {
        Self::new("https://api.workos.com/sso/jwks/client_01KFV7CDYY88X8EZZXGRGW9WFK")
    }

    /// Get the decoding key for a specific kid, fetching/refreshing JWKS as needed
    async fn get_decoding_key(&self, kid: &str) -> Result<DecodingKey, AuthError> {
        // Try cache first
        {
            let cache = self.cache.read().await;
            if let Some(ref cached) = *cache {
                if cached.fetched_at.elapsed() < self.cache_ttl {
                    if let Some(key) = cached.keys.iter().find(|k| k.kid == kid) {
                        return Self::jwk_to_decoding_key(key);
                    }
                }
            }
        }

        // Cache miss or expired — fetch fresh keys
        self.refresh_keys().await?;

        // Try again with fresh keys
        let cache = self.cache.read().await;
        if let Some(ref cached) = *cache {
            if let Some(key) = cached.keys.iter().find(|k| k.kid == kid) {
                return Self::jwk_to_decoding_key(key);
            }
        }

        Err(AuthError::InvalidToken(format!(
            "no JWKS key found for kid '{kid}'"
        )))
    }

    /// Fetch JWKS keys from WorkOS
    async fn refresh_keys(&self) -> Result<(), AuthError> {
        tracing::info!("Fetching JWKS keys from {}", self.jwks_url);

        let resp = reqwest::get(&self.jwks_url)
            .await
            .map_err(|e| AuthError::Internal(format!("JWKS fetch failed: {e}")))?;

        let jwks: JwksResponse = resp
            .json()
            .await
            .map_err(|e| AuthError::Internal(format!("JWKS parse failed: {e}")))?;

        tracing::info!("Cached {} JWKS keys", jwks.keys.len());

        let mut cache = self.cache.write().await;
        *cache = Some(JwksCache {
            keys: jwks.keys,
            fetched_at: std::time::Instant::now(),
        });

        Ok(())
    }

    /// Convert a JWK to a DecodingKey
    fn jwk_to_decoding_key(key: &JwkKey) -> Result<DecodingKey, AuthError> {
        if key.kty != "RSA" {
            return Err(AuthError::InvalidToken(format!(
                "unsupported key type: {}",
                key.kty
            )));
        }

        DecodingKey::from_rsa_components(&key.n, &key.e)
            .map_err(|e| AuthError::InvalidToken(format!("invalid RSA key components: {e}")))
    }

    /// Pre-warm the cache on startup
    pub async fn warm_cache(&self) -> Result<(), AuthError> {
        self.refresh_keys().await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WorkOS JWT validation (with signature verification!)
// ─────────────────────────────────────────────────────────────────────────────

/// WorkOS JWT payload structure.
#[derive(Debug, Deserialize)]
struct WorkOSJWTPayload {
    iss: String,
    sub: String,
    org_id: Option<String>,
    role: Option<String>,
    #[serde(default)]
    permissions: Vec<String>,
    exp: i64,
    #[allow(dead_code)]
    iat: i64,
}

/// JWT header for extracting kid
#[derive(Debug, Deserialize)]
struct JwtHeader {
    kid: Option<String>,
    alg: Option<String>,
}

/// Validate a WorkOS access token (JWT) with full signature verification.
pub async fn verify_token(
    access_token: &str,
    db: &PgPool,
    jwks: Option<&JwksKeyStore>,
) -> Result<AuthContext, AuthError> {
    let parts: Vec<&str> = access_token.split('.').collect();
    if parts.len() != 3 {
        return Err(AuthError::InvalidToken("invalid JWT format".into()));
    }

    // ── Signature verification ──────────────────────────────────────────
    let payload: WorkOSJWTPayload = if let Some(jwks_store) = jwks {
        // Parse the JWT header to get the kid
        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|_| AuthError::InvalidToken("invalid base64 in JWT header".into()))?;

        let header: JwtHeader = serde_json::from_slice(&header_bytes)
            .map_err(|e| AuthError::InvalidToken(format!("invalid JWT header: {e}")))?;

        let kid = header
            .kid
            .ok_or_else(|| AuthError::InvalidToken("JWT header missing 'kid'".into()))?;

        // Verify algorithm is RS256 (WorkOS standard)
        if let Some(ref alg) = header.alg {
            if alg != "RS256" {
                return Err(AuthError::InvalidToken(format!(
                    "unsupported JWT algorithm: {alg} (expected RS256)"
                )));
            }
        }

        // Get the decoding key from JWKS cache
        let decoding_key = jwks_store.get_decoding_key(&kid).await?;

        // Build validation config
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&["https://api.workos.com"]);
        validation.validate_exp = true;

        // Decode and verify the full JWT
        let token_data = decode::<WorkOSJWTPayload>(access_token, &decoding_key, &validation)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                jsonwebtoken::errors::ErrorKind::InvalidIssuer => {
                    AuthError::InvalidToken("invalid issuer".into())
                }
                _ => AuthError::InvalidToken(format!("JWT verification failed: {e}")),
            })?;

        token_data.claims
    } else {
        // Fallback: decode-only (NO signature verification) — development mode only
        tracing::warn!(
            "⚠️  JWT signature verification DISABLED — JWKS not configured. \
             DO NOT use this in production!"
        );

        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| AuthError::InvalidToken("invalid base64 in JWT".into()))?;

        let payload: WorkOSJWTPayload = serde_json::from_slice(&payload_bytes)
            .map_err(|e| AuthError::InvalidToken(format!("invalid JWT payload: {e}")))?;

        // Manual checks when not using jsonwebtoken validation
        let now = Utc::now().timestamp();
        if payload.exp < now {
            return Err(AuthError::TokenExpired);
        }
        if !payload.iss.starts_with("https://api.workos.com") {
            return Err(AuthError::InvalidToken("invalid issuer".into()));
        }

        payload
    };

    let workos_user_id = payload.sub.clone();
    let workos_org_id = payload.org_id.clone().unwrap_or_default();

    // Resolve internal IDs from DB for backward compatibility
    let (internal_user_id, internal_org_id) = resolve_internal_ids(
        db,
        &workos_user_id,
        if workos_org_id.is_empty() { None } else { Some(&workos_org_id) },
    ).await;

    Ok(AuthContext {
        user_id: workos_user_id,
        org_id: workos_org_id,
        internal_user_id,
        internal_org_id,
        auth_method: AuthMethod::Workos,
        role: payload.role,
        permissions: payload.permissions,
        scopes: vec![],
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// API Key verification
// ─────────────────────────────────────────────────────────────────────────────

/// Verify a RunTools API key (rt_live_xxx or rt_test_xxx).
pub async fn verify_api_key(
    api_key: &str,
    db: &PgPool,
) -> Result<AuthContext, AuthError> {
    if !api_key.starts_with("rt_") {
        return Err(AuthError::InvalidToken("not an RT API key".into()));
    }

    // SHA-256 hash the key for lookup
    let mut hasher = Sha256::new();
    hasher.update(api_key.as_bytes());
    let key_hash = hex_encode(hasher.finalize().as_slice());

    let row = sqlx::query(
        r#"
        SELECT
            ak.org_id::text,
            ak.scopes,
            ak.created_by::text,
            ak.expires_at,
            o.workos_org_id
        FROM api_keys ak
        LEFT JOIN organizations o ON o.id = ak.org_id
        WHERE ak.key_hash = $1
          AND ak.revoked_at IS NULL
        LIMIT 1
        "#,
    )
    .bind(&key_hash)
    .fetch_optional(db)
    .await?;

    let row = row.ok_or_else(|| AuthError::InvalidToken("API key not found or revoked".into()))?;

    let org_id: String = row.get(0);
    let scopes: Option<Vec<String>> = row.try_get(1).ok();
    let created_by: Option<String> = row.try_get(2).ok();
    let expires_at: Option<DateTime<Utc>> = row.try_get(3).ok();
    let workos_org_id: Option<String> = row.try_get(4).ok();

    // Check expiry
    if let Some(exp) = expires_at {
        if exp < Utc::now() {
            return Err(AuthError::TokenExpired);
        }
    }

    // Update last_used_at (fire and forget)
    let db2 = db.clone();
    let hash2 = key_hash.clone();
    tokio::spawn(async move {
        let _ = sqlx::query("UPDATE api_keys SET last_used_at = NOW() WHERE key_hash = $1")
            .bind(hash2)
            .execute(&db2)
            .await;
    });

    Ok(AuthContext {
        user_id: created_by.unwrap_or_else(|| "system".into()),
        org_id: workos_org_id.unwrap_or_default(),
        internal_user_id: None,
        internal_org_id: Some(org_id),
        auth_method: AuthMethod::ApiKey,
        role: None,
        permissions: vec![],
        scopes: scopes.unwrap_or_default(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal service-to-service auth
// ─────────────────────────────────────────────────────────────────────────────

/// Verify an internal service call using the shared AUTH_SERVICE_SECRET.
pub fn verify_internal(
    provided_secret: &str,
    expected_secret: &str,
    org_id: &str,
    user_id: &str,
) -> Result<AuthContext, AuthError> {
    if provided_secret != expected_secret || expected_secret.is_empty() {
        return Err(AuthError::Unauthorized);
    }

    Ok(AuthContext {
        user_id: user_id.to_string(),
        org_id: org_id.to_string(),
        internal_user_id: None,
        internal_org_id: Some(org_id.to_string()),
        auth_method: AuthMethod::Internal,
        role: None,
        permissions: vec![],
        scopes: vec!["*".into()],
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// ID Resolution
// ─────────────────────────────────────────────────────────────────────────────

/// Resolve WorkOS IDs to internal UUIDs.
async fn resolve_internal_ids(
    db: &PgPool,
    workos_user_id: &str,
    workos_org_id: Option<&str>,
) -> (Option<String>, Option<String>) {
    let internal_user_id: Option<String> = sqlx::query(
        "SELECT id::text FROM users WHERE workos_user_id = $1 LIMIT 1"
    )
    .bind(workos_user_id)
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
    .map(|row: sqlx::postgres::PgRow| row.get(0));

    let internal_org_id: Option<String> = if let Some(wos_org) = workos_org_id {
        sqlx::query(
            "SELECT id::text FROM organizations WHERE workos_org_id = $1 LIMIT 1"
        )
        .bind(wos_org)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .map(|row: sqlx::postgres::PgRow| row.get(0))
    } else if let Some(ref user_uuid) = internal_user_id {
        sqlx::query(
            "SELECT org_id::text FROM organization_members WHERE user_id = $1::uuid AND status = 'active' LIMIT 1"
        )
        .bind(user_uuid)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .map(|row: sqlx::postgres::PgRow| row.get(0))
    } else {
        None
    };

    (internal_user_id, internal_org_id)
}

/// Explicit ID resolution endpoint — returns both WorkOS and internal IDs.
pub async fn resolve_ids(
    db: &PgPool,
    workos_user_id: Option<&str>,
    workos_org_id: Option<&str>,
    internal_user_id: Option<&str>,
    internal_org_id: Option<&str>,
) -> Result<ResolvedIds, AuthError> {
    let mut result = ResolvedIds::default();

    // WorkOS → Internal
    if let Some(wuid) = workos_user_id {
        result.workos_user_id = Some(wuid.to_string());
        result.internal_user_id = sqlx::query("SELECT id::text FROM users WHERE workos_user_id = $1 LIMIT 1")
            .bind(wuid)
            .fetch_optional(db)
            .await?
            .map(|row: sqlx::postgres::PgRow| row.get(0));
    }

    if let Some(woid) = workos_org_id {
        result.workos_org_id = Some(woid.to_string());
        result.internal_org_id = sqlx::query("SELECT id::text FROM organizations WHERE workos_org_id = $1 LIMIT 1")
            .bind(woid)
            .fetch_optional(db)
            .await?
            .map(|row: sqlx::postgres::PgRow| row.get(0));
    }

    // Internal → WorkOS
    if let Some(iuid) = internal_user_id {
        result.internal_user_id = Some(iuid.to_string());
        result.workos_user_id = sqlx::query("SELECT workos_user_id FROM users WHERE id = $1::uuid LIMIT 1")
            .bind(iuid)
            .fetch_optional(db)
            .await?
            .map(|row: sqlx::postgres::PgRow| row.get(0));
    }

    if let Some(ioid) = internal_org_id {
        result.internal_org_id = Some(ioid.to_string());
        result.workos_org_id = sqlx::query("SELECT workos_org_id FROM organizations WHERE id = $1::uuid LIMIT 1")
            .bind(ioid)
            .fetch_optional(db)
            .await?
            .map(|row: sqlx::postgres::PgRow| row.get(0));
    }

    Ok(result)
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ResolvedIds {
    pub workos_user_id: Option<String>,
    pub workos_org_id: Option<String>,
    pub internal_user_id: Option<String>,
    pub internal_org_id: Option<String>,
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
