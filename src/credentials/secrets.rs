//! Secrets management — encrypted CRUD for secrets.
//!
//! Operates on the `secrets` table in the shared PostgreSQL database.
//! This table has: id, org_id (UUID), name, value_encrypted, encryption_key_id,
//! scope, description, created_at, updated_at, created_by, last_rotated_at.
//!
//! NOTE: The `org_secrets` table (used by tools service) has a different schema
//! (TEXT org_id, additional `category` column). This module only handles `secrets`.

use crate::crypto::CryptoEngine;
use crate::error::AuthError;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{PgPool, Row};

/// Create or update a secret (upsert).
pub async fn upsert_secret(
    db: &PgPool,
    crypto: &CryptoEngine,
    org_id: &str,
    name: &str,
    value: &str,
    scope: &str,
    category: Option<&str>,
    description: Option<&str>,
    created_by: Option<&str>,
) -> Result<SecretUpsertResult, AuthError> {
    // Normalize name: uppercase, alphanumeric + underscore only
    let name = name
        .trim()
        .to_uppercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect::<String>();

    if name.len() < 2 {
        return Err(AuthError::BadRequest(
            "secret name must be at least 2 characters".into(),
        ));
    }

    // Encrypt the value
    let encrypted = crypto
        .encrypt(value)
        .map_err(|e| AuthError::Encryption(e.to_string()))?;

    // Check if secret already exists (org_id is UUID in the real schema)
    let existing = sqlx::query("SELECT id::text FROM secrets WHERE org_id = $1::uuid AND name = $2 LIMIT 1")
        .bind(org_id)
        .bind(&name)
        .fetch_optional(db)
        .await?;

    if let Some(row) = existing {
        let id: String = row.get(0);
        let cat = category.unwrap_or("custom");
        sqlx::query(
            r#"
            UPDATE secrets SET
                value_encrypted = $1,
                scope = $2,
                category = $3,
                description = $4,
                updated_at = NOW(),
                last_rotated_at = NOW()
            WHERE id = $5::uuid
            "#,
        )
        .bind(&encrypted)
        .bind(scope)
        .bind(cat)
        .bind(description)
        .bind(&id)
        .execute(db)
        .await?;

        Ok(SecretUpsertResult {
            id,
            name,
            created: false,
        })
    } else {
        let row = sqlx::query(
            r#"
            INSERT INTO secrets (org_id, name, value_encrypted, scope, category, description, created_by)
            VALUES ($1::uuid, $2, $3, $4, $5, $6, $7::uuid)
            RETURNING id::text
            "#,
        )
        .bind(org_id)
        .bind(&name)
        .bind(&encrypted)
        .bind(scope)
        .bind(category.unwrap_or("custom"))
        .bind(description)
        .bind(created_by)
        .fetch_one(db)
        .await?;

        let id: String = row.get(0);

        Ok(SecretUpsertResult {
            id,
            name,
            created: true,
        })
    }
}

/// List secrets for an organization (metadata only, never values).
pub async fn list_secrets(
    db: &PgPool,
    org_id: &str,
    scope: Option<&str>,
) -> Result<Vec<SecretInfo>, AuthError> {
    let rows = if let Some(scope_filter) = scope {
        sqlx::query(
            r#"
            SELECT id::text, name, scope, category, description, created_by::text,
                   created_at, updated_at, last_rotated_at
            FROM secrets
            WHERE org_id = $1::uuid AND scope = $2
            ORDER BY updated_at DESC
            "#,
        )
        .bind(org_id)
        .bind(scope_filter)
        .fetch_all(db)
        .await?
    } else {
        sqlx::query(
            r#"
            SELECT id::text, name, scope, category, description, created_by::text,
                   created_at, updated_at, last_rotated_at
            FROM secrets
            WHERE org_id = $1::uuid
            ORDER BY updated_at DESC
            "#,
        )
        .bind(org_id)
        .fetch_all(db)
        .await?
    };

    let secrets = rows
        .iter()
        .map(|row| SecretInfo {
            id: row.get(0),
            name: row.get(1),
            scope: row.get(2),
            category: row.try_get(3).ok(),
            description: row.try_get(4).ok(),
            created_by: row.try_get(5).ok(),
            created_at: row.get(6),
            updated_at: row.get(7),
            last_rotated_at: row.try_get(8).ok(),
        })
        .collect();

    Ok(secrets)
}

/// Reveal a secret value (decrypts and returns it). Should be audit-logged.
pub async fn reveal_secret(
    db: &PgPool,
    crypto: &CryptoEngine,
    org_id: &str,
    name: &str,
) -> Result<String, AuthError> {
    let name = name.trim().to_uppercase();

    let row = sqlx::query("SELECT value_encrypted FROM secrets WHERE org_id = $1::uuid AND name = $2 LIMIT 1")
        .bind(org_id)
        .bind(&name)
        .fetch_optional(db)
        .await?;

    let row = row.ok_or_else(|| AuthError::NotFound(format!("secret \"{name}\"")))?;
    let encrypted: String = row.get(0);

    let value = crypto
        .decrypt(&encrypted)
        .map_err(|e| AuthError::Decryption(e.to_string()))?;

    Ok(value)
}

/// Delete a secret.
pub async fn delete_secret(
    db: &PgPool,
    org_id: &str,
    name: &str,
) -> Result<(), AuthError> {
    let name = name.trim().to_uppercase();
    let affected = sqlx::query("DELETE FROM secrets WHERE org_id = $1::uuid AND name = $2")
        .bind(org_id)
        .bind(&name)
        .execute(db)
        .await?
        .rows_affected();

    if affected == 0 {
        return Err(AuthError::NotFound(format!("secret \"{name}\"")));
    }

    Ok(())
}

/// Get a secret value for sandbox injection (internal use).
pub async fn get_secret_for_injection(
    db: &PgPool,
    crypto: &CryptoEngine,
    org_id: &str,
    name: &str,
    scope: &str,
) -> Result<Option<String>, AuthError> {
    let row = sqlx::query(
        r#"
        SELECT value_encrypted FROM secrets 
        WHERE org_id = $1::uuid AND name = $2 AND (scope = $3 OR scope = 'all')
        LIMIT 1
        "#,
    )
    .bind(org_id)
    .bind(name)
    .bind(scope)
    .fetch_optional(db)
    .await?;

    match row {
        Some(r) => {
            let encrypted: String = r.get(0);
            let val = crypto
                .decrypt(&encrypted)
                .map_err(|e| AuthError::Decryption(e.to_string()))?;
            Ok(Some(val))
        }
        None => Ok(None),
    }
}

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct SecretUpsertResult {
    pub id: String,
    pub name: String,
    pub created: bool,
}

#[derive(Debug, serde::Serialize)]
pub struct SecretInfo {
    pub id: String,
    pub name: String,
    pub scope: String,
    pub category: Option<String>,
    pub description: Option<String>,
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_rotated_at: Option<DateTime<Utc>>,
}
