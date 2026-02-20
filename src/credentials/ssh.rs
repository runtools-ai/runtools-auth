//! SSH key management — CRUD for SSH public keys used in sandbox access.
//!
//! Replaces orchestrator's `src/routes/v1/ssh-keys.ts`.

use crate::error::AuthError;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};

/// Create/upload an SSH key.
pub async fn create_ssh_key(
    db: &PgPool,
    org_id: &str,
    name: &str,
    public_key: &str,
) -> Result<SshKeyCreated, AuthError> {
    let public_key = public_key.trim();

    // Parse the key to extract type and compute fingerprint
    let parsed = parse_public_key(public_key)?;
    let fingerprint = generate_fingerprint(&parsed.key_data);

    // Check for duplicate fingerprint within the org
    let existing = sqlx::query("SELECT id::text FROM ssh_keys WHERE org_id = $1::uuid AND fingerprint = $2 LIMIT 1")
        .bind(org_id)
        .bind(&fingerprint)
        .fetch_optional(db)
        .await?;

    if existing.is_some() {
        return Err(AuthError::Conflict(
            "SSH key with this fingerprint already exists".into(),
        ));
    }

    let row = sqlx::query(
        r#"
        INSERT INTO ssh_keys (org_id, name, public_key, fingerprint, key_type)
        VALUES ($1::uuid, $2, $3, $4, $5)
        RETURNING id::text
        "#,
    )
    .bind(org_id)
    .bind(name)
    .bind(public_key)
    .bind(&fingerprint)
    .bind(&parsed.key_type)
    .fetch_one(db)
    .await?;

    let id: String = row.get(0);

    Ok(SshKeyCreated {
        id,
        name: name.to_string(),
        fingerprint,
        key_type: parsed.key_type,
    })
}

/// List SSH keys for an organization.
pub async fn list_ssh_keys(
    db: &PgPool,
    org_id: &str,
) -> Result<Vec<SshKeyInfo>, AuthError> {
    let rows = sqlx::query(
        r#"
        SELECT id::text, name, fingerprint, key_type, created_at, last_used_at
        FROM ssh_keys
        WHERE org_id = $1::uuid
        ORDER BY created_at DESC
        "#,
    )
    .bind(org_id)
    .fetch_all(db)
    .await?;

    let keys = rows
        .iter()
        .map(|row| SshKeyInfo {
            id: row.get(0),
            name: row.get(1),
            fingerprint: row.get(2),
            key_type: row.get(3),
            created_at: row.get(4),
            last_used_at: row.try_get(5).ok(),
        })
        .collect();

    Ok(keys)
}

/// Delete an SSH key.
pub async fn delete_ssh_key(
    db: &PgPool,
    key_id: &str,
    org_id: &str,
) -> Result<(), AuthError> {
    let affected = sqlx::query("DELETE FROM ssh_keys WHERE id = $1::uuid AND org_id = $2::uuid")
        .bind(key_id)
        .bind(org_id)
        .execute(db)
        .await?
        .rows_affected();

    if affected == 0 {
        return Err(AuthError::NotFound("SSH key".into()));
    }

    Ok(())
}

/// Get public keys for sandbox creation (internal use).
pub async fn get_keys_for_sandbox(
    db: &PgPool,
    org_id: &str,
    key_ids: &[String],
) -> Result<Vec<String>, AuthError> {
    if key_ids.is_empty() {
        let rows = sqlx::query("SELECT public_key FROM ssh_keys WHERE org_id = $1::uuid")
            .bind(org_id)
            .fetch_all(db)
            .await?;
        return Ok(rows.iter().map(|r| r.get(0)).collect());
    }

    let mut result = Vec::new();
    for kid in key_ids {
        let row = sqlx::query("SELECT public_key FROM ssh_keys WHERE id = $1::uuid AND org_id = $2::uuid")
            .bind(kid)
            .bind(org_id)
            .fetch_optional(db)
            .await?;
        if let Some(r) = row {
            result.push(r.get(0));
        }
    }

    Ok(result)
}

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct SshKeyCreated {
    pub id: String,
    pub name: String,
    pub fingerprint: String,
    pub key_type: String,
}

#[derive(Debug, Serialize)]
pub struct SshKeyInfo {
    pub id: String,
    pub name: String,
    pub fingerprint: String,
    pub key_type: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

// ── Key Parsing ──────────────────────────────────────────────────────────────

struct ParsedKey {
    key_type: String,
    key_data: String,
}

fn parse_public_key(public_key: &str) -> Result<ParsedKey, AuthError> {
    let parts: Vec<&str> = public_key.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(AuthError::BadRequest("invalid SSH public key format".into()));
    }

    let key_type = parts[0].to_string();
    let valid_types = [
        "ssh-rsa",
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
    ];

    if !valid_types.contains(&key_type.as_str()) {
        return Err(AuthError::BadRequest(format!(
            "unsupported key type: {key_type}"
        )));
    }

    Ok(ParsedKey {
        key_type,
        key_data: parts[1].to_string(),
    })
}

fn generate_fingerprint(key_data: &str) -> String {
    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(key_data)
        .unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&decoded);
    let hash = hasher.finalize();
    let b64 = base64::engine::general_purpose::STANDARD.encode(hash);
    format!("SHA256:{}", b64.trim_end_matches('='))
}
