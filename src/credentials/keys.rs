//! API key management — CRUD for rt_live_xxx / rt_test_xxx keys.
//!
//! Replaces orchestrator's `src/routes/v1/api-keys.ts`.

use crate::error::AuthError;
use chrono::{DateTime, Utc};
use rand::Rng;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};

/// Generate a new RunTools API key.
///
/// Format: rt_live_[32 random chars] or rt_test_[32 random chars]
/// Returns (full_key, prefix, sha256_hash).
pub fn generate_api_key(is_test: bool) -> (String, String, String) {
    let prefix = if is_test { "rt_test_" } else { "rt_live_" };
    let random_part: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let full_key = format!("{prefix}{random_part}");
    let mut hasher = Sha256::new();
    hasher.update(full_key.as_bytes());
    let hash: String = hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect();

    (full_key, prefix.to_string(), hash)
}

/// Create an API key in the database.
pub async fn create_api_key(
    db: &PgPool,
    org_id: &str, // internal UUID
    name: &str,
    scopes: &[String],
    created_by: Option<&str>, // internal user UUID
    expires_in: Option<&str>,
    is_test: bool,
) -> Result<ApiKeyCreated, AuthError> {
    let (full_key, prefix, hash) = generate_api_key(is_test);
    let expires_at = parse_expiry(expires_in)?;

    let row = sqlx::query(
        r#"
        INSERT INTO api_keys (org_id, name, key_prefix, key_hash, scopes, expires_at, created_by)
        VALUES ($1::uuid, $2, $3, $4, $5, $6, $7::uuid)
        RETURNING id::text, created_at
        "#,
    )
    .bind(org_id)
    .bind(name)
    .bind(&prefix)
    .bind(&hash)
    .bind(scopes)
    .bind(expires_at)
    .bind(created_by)
    .fetch_one(db)
    .await?;

    let id: String = row.get(0);

    Ok(ApiKeyCreated {
        id,
        key: full_key,
        key_prefix: prefix,
        name: name.to_string(),
        scopes: scopes.to_vec(),
        expires_at,
    })
}

/// List API keys for an organization (metadata only, never the actual key).
pub async fn list_api_keys(
    db: &PgPool,
    org_id: &str,
) -> Result<Vec<ApiKeyInfo>, AuthError> {
    let rows = sqlx::query(
        r#"
        SELECT
            id::text,
            name,
            key_prefix,
            scopes,
            expires_at,
            last_used_at,
            revoked_at,
            created_at
        FROM api_keys
        WHERE org_id = $1::uuid AND revoked_at IS NULL
        ORDER BY created_at DESC
        "#,
    )
    .bind(org_id)
    .fetch_all(db)
    .await?;

    let keys = rows
        .iter()
        .map(|row| ApiKeyInfo {
            id: row.get(0),
            name: row.get(1),
            key_prefix: row.get(2),
            scopes: row.try_get(3).ok(),
            expires_at: row.try_get(4).ok(),
            last_used_at: row.try_get(5).ok(),
            revoked_at: row.try_get(6).ok(),
            created_at: row.get(7),
        })
        .collect();

    Ok(keys)
}

/// Get a single API key by ID (metadata only).
pub async fn get_api_key(
    db: &PgPool,
    key_id: &str,
    org_id: &str,
) -> Result<ApiKeyInfo, AuthError> {
    let row = sqlx::query(
        r#"
        SELECT id::text, name, key_prefix, scopes, expires_at, last_used_at, revoked_at, created_at
        FROM api_keys
        WHERE id = $1::uuid AND org_id = $2::uuid
        LIMIT 1
        "#,
    )
    .bind(key_id)
    .bind(org_id)
    .fetch_optional(db)
    .await?;

    let row = row.ok_or_else(|| AuthError::NotFound("API key".into()))?;

    Ok(ApiKeyInfo {
        id: row.get(0),
        name: row.get(1),
        key_prefix: row.get(2),
        scopes: row.try_get(3).ok(),
        expires_at: row.try_get(4).ok(),
        last_used_at: row.try_get(5).ok(),
        revoked_at: row.try_get(6).ok(),
        created_at: row.get(7),
    })
}

/// Update an API key's name and/or scopes.
pub async fn update_api_key(
    db: &PgPool,
    key_id: &str,
    org_id: &str,
    name: Option<&str>,
    scopes: Option<&[String]>,
) -> Result<(), AuthError> {
    // Build update dynamically based on what's provided
    match (name, scopes) {
        (Some(n), Some(s)) => {
            sqlx::query(
                "UPDATE api_keys SET name = $1, scopes = $2 WHERE id = $3::uuid AND org_id = $4::uuid AND revoked_at IS NULL"
            )
            .bind(n)
            .bind(s)
            .bind(key_id)
            .bind(org_id)
            .execute(db)
            .await?;
        }
        (Some(n), None) => {
            sqlx::query(
                "UPDATE api_keys SET name = $1 WHERE id = $2::uuid AND org_id = $3::uuid AND revoked_at IS NULL"
            )
            .bind(n)
            .bind(key_id)
            .bind(org_id)
            .execute(db)
            .await?;
        }
        (None, Some(s)) => {
            sqlx::query(
                "UPDATE api_keys SET scopes = $1 WHERE id = $2::uuid AND org_id = $3::uuid AND revoked_at IS NULL"
            )
            .bind(s)
            .bind(key_id)
            .bind(org_id)
            .execute(db)
            .await?;
        }
        (None, None) => {} // nothing to update
    }

    Ok(())
}

/// Revoke an API key (soft delete).
pub async fn revoke_api_key(
    db: &PgPool,
    key_id: &str,
    org_id: &str,
) -> Result<(), AuthError> {
    let affected = sqlx::query(
        "UPDATE api_keys SET revoked_at = NOW() WHERE id = $1::uuid AND org_id = $2::uuid AND revoked_at IS NULL"
    )
    .bind(key_id)
    .bind(org_id)
    .execute(db)
    .await?
    .rows_affected();

    if affected == 0 {
        return Err(AuthError::NotFound("API key".into()));
    }

    Ok(())
}

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ApiKeyCreated {
    pub id: String,
    pub key: String,
    pub key_prefix: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct ApiKeyInfo {
    pub id: String,
    pub name: String,
    pub key_prefix: String,
    pub scopes: Option<Vec<String>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

fn parse_expiry(expires_in: Option<&str>) -> Result<Option<DateTime<Utc>>, AuthError> {
    match expires_in {
        None | Some("never") => Ok(None),
        Some(s) => {
            let len = s.len();
            if len < 2 {
                return Err(AuthError::BadRequest("invalid expiry format".into()));
            }
            let (num_str, unit) = s.split_at(len - 1);
            let value: i64 = num_str
                .parse()
                .map_err(|_| AuthError::BadRequest("invalid expiry number".into()))?;
            let duration = match unit {
                "d" => chrono::Duration::days(value),
                "m" => chrono::Duration::days(value * 30),
                "y" => chrono::Duration::days(value * 365),
                _ => return Err(AuthError::BadRequest("expiry unit must be d, m, or y".into())),
            };
            Ok(Some(Utc::now() + duration))
        }
    }
}
