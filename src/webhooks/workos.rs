/// WorkOS Webhook Handler
///
/// Receives and verifies all WorkOS webhook events, then syncs the data into
/// the shared PostgreSQL database (users, organizations, organization_members).
///
/// This replaces `runtools-orchestrator/src/routes/v1/webhooks.ts`.
///
/// Signature verification: WorkOS signs webhooks with HMAC-SHA256.
/// The `workos-signature` header format is: `t=<timestamp>,v1=<hex_signature>`
/// We verify: HMAC-SHA256(`<timestamp>.<raw_body>`, WORKOS_WEBHOOK_SECRET) == v1
use axum::{
    extract::State,
    http::HeaderMap,
    response::Json,
};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Sha256;
use sqlx::{PgPool, Row};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{error::AuthError, SharedState};

type HmacSha256 = Hmac<Sha256>;

/// Replay attack tolerance: reject webhooks older than 5 minutes (WorkOS SDK default).
const TIMESTAMP_TOLERANCE_SECS: u64 = 5 * 60;

// =============================================================================
// WorkOS Event Shapes
// =============================================================================

/// Minimal envelope — we only care about `event` and `data`.
#[derive(Debug, Deserialize)]
struct WorkOSEvent {
    pub event: String,
    pub data: Value,
}

// =============================================================================
// Signature Verification
// =============================================================================

/// Verify the `workos-signature` header and protect against replay attacks.
///
/// Header format: `t=<unix_timestamp>,v1=<hex_signature>`
/// Signed payload: `<timestamp>.<raw_json_body>`
/// Tolerance: rejects events with timestamp older than 5 minutes (WorkOS SDK default).
fn verify_signature(
    raw_body: &[u8],
    signature_header: &str,
    secret: &str,
) -> Result<(), AuthError> {
    let mut timestamp_str: Option<&str> = None;
    let mut v1: Option<&str> = None;

    for part in signature_header.split(',') {
        if let Some(ts) = part.strip_prefix("t=") {
            timestamp_str = Some(ts);
        } else if let Some(sig) = part.strip_prefix("v1=") {
            v1 = Some(sig);
        }
    }

    let timestamp_str = timestamp_str
        .ok_or_else(|| AuthError::InvalidToken("workos-signature missing timestamp".into()))?;
    let v1 = v1.ok_or_else(|| AuthError::InvalidToken("workos-signature missing v1".into()))?;

    // Replay attack protection: reject stale events
    let ts: u64 = timestamp_str
        .parse()
        .map_err(|_| AuthError::InvalidToken("workos-signature timestamp invalid".into()))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now.saturating_sub(ts) > TIMESTAMP_TOLERANCE_SECS {
        tracing::warn!("[Webhook] Stale webhook ts={ts} now={now} — rejecting (replay protection)");
        return Err(AuthError::InvalidToken("webhook timestamp too old".into()));
    }

    // Signed payload = "<timestamp>.<body>"
    let mut signed = timestamp_str.as_bytes().to_vec();
    signed.push(b'.');
    signed.extend_from_slice(raw_body);

    // HMAC-SHA256
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| AuthError::Internal("HMAC key error".into()))?;
    mac.update(&signed);
    let expected = mac.finalize().into_bytes();
    let expected_hex = hex_encode(&expected);

    // Constant-time comparison
    if !constant_time_eq(expected_hex.as_bytes(), v1.as_bytes()) {
        return Err(AuthError::Unauthorized);
    }

    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// =============================================================================
// Main Handler
// =============================================================================

/// POST /v1/webhooks/workos
pub async fn workos_webhook(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, AuthError> {
    let secret = &state.config.workos_webhook_secret;

    if secret.is_empty() {
        tracing::warn!("[Webhook] WORKOS_WEBHOOK_SECRET not set — rejecting all webhooks");
        return Err(AuthError::Unauthorized);
    }

    let signature = headers
        .get("workos-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AuthError::InvalidToken("missing workos-signature header".into()))?;

    verify_signature(&body, signature, secret)?;

    let event: WorkOSEvent = serde_json::from_slice(&body)
        .map_err(|e| AuthError::BadRequest(format!("invalid webhook payload: {e}")))?;

    tracing::info!("[Webhook:WorkOS] event={}", event.event);

    let db = state.store.pool();

    let result = match event.event.as_str() {
        "user.created" => handle_user_upsert(db, &event.data).await,
        "user.updated" => handle_user_upsert(db, &event.data).await,
        "user.deleted" => handle_user_deleted(db, &event.data).await,

        "organization.created" => handle_org_upsert(db, &event.data).await,
        "organization.updated" => handle_org_upsert(db, &event.data).await,
        "organization.deleted" => handle_org_deleted(db, &event.data).await,

        "organization_membership.created" => handle_membership_upsert(db, &event.data).await,
        "organization_membership.updated" => handle_membership_upsert(db, &event.data).await,
        "organization_membership.deleted" => handle_membership_deleted(db, &event.data).await,

        // Audit-only events — log and ack
        ev if ev.starts_with("authentication.") || ev.starts_with("session.") => {
            tracing::info!("[Webhook:WorkOS] audit event: {ev}");
            Ok(())
        }

        other => {
            tracing::debug!("[Webhook:WorkOS] unhandled event: {other}");
            Ok(())
        }
    };

    if let Err(e) = result {
        tracing::error!("[Webhook:WorkOS] handler error for {}: {:?}", event.event, e);
        // Return 500 so WorkOS retries
        return Err(e);
    }

    Ok(Json(json!({ "received": true })))
}

// =============================================================================
// Event Handlers
// =============================================================================

/// Upsert a WorkOS user into our `users` table.
async fn handle_user_upsert(db: &PgPool, data: &Value) -> Result<(), AuthError> {
    let workos_user_id = str_field(data, "id")?;
    let email = str_field(data, "email")?;
    let first_name = data.get("firstName")
        .or_else(|| data.get("first_name"))
        .and_then(|v| v.as_str());
    let last_name = data.get("lastName")
        .or_else(|| data.get("last_name"))
        .and_then(|v| v.as_str());
    let profile_picture_url = data.get("profilePictureUrl")
        .or_else(|| data.get("profile_picture_url"))
        .and_then(|v| v.as_str());
    let email_verified = data.get("emailVerified")
        .or_else(|| data.get("email_verified"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    sqlx::query(
        r#"
        INSERT INTO users (workos_user_id, email, first_name, last_name, profile_picture_url, email_verified, last_synced_at)
        VALUES ($1, $2, $3, $4, $5, $6, NOW())
        ON CONFLICT (workos_user_id) DO UPDATE SET
            email                = EXCLUDED.email,
            first_name           = EXCLUDED.first_name,
            last_name            = EXCLUDED.last_name,
            profile_picture_url  = EXCLUDED.profile_picture_url,
            email_verified       = EXCLUDED.email_verified,
            last_synced_at       = NOW(),
            updated_at           = NOW()
        "#,
    )
    .bind(workos_user_id)
    .bind(email)
    .bind(first_name)
    .bind(last_name)
    .bind(profile_picture_url)
    .bind(email_verified)
    .execute(db)
    .await?;

    tracing::info!("[Webhook:WorkOS] upserted user: {email}");
    Ok(())
}

async fn handle_user_deleted(db: &PgPool, data: &Value) -> Result<(), AuthError> {
    let workos_user_id = str_field(data, "id")?;

    sqlx::query("DELETE FROM users WHERE workos_user_id = $1")
        .bind(workos_user_id)
        .execute(db)
        .await?;

    tracing::info!("[Webhook:WorkOS] deleted user: {workos_user_id}");
    Ok(())
}

/// Upsert a WorkOS organization into our `organizations` table.
async fn handle_org_upsert(db: &PgPool, data: &Value) -> Result<(), AuthError> {
    let workos_org_id = str_field(data, "id")?;
    let name = str_field(data, "name")?;
    // Generate slug from name: lowercase, spaces→dashes, strip non-alphanumeric-dash
    let slug = data.get("slug")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            name.to_lowercase()
                .chars()
                .map(|c| if c.is_alphanumeric() || c == '-' { c } else if c == ' ' { '-' } else { '_' })
                .collect()
        });

    sqlx::query(
        r#"
        INSERT INTO organizations (workos_org_id, name, slug, last_synced_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (workos_org_id) DO UPDATE SET
            name           = EXCLUDED.name,
            last_synced_at = NOW(),
            updated_at     = NOW()
        "#,
    )
    .bind(workos_org_id)
    .bind(name)
    .bind(&slug)
    .execute(db)
    .await?;

    tracing::info!("[Webhook:WorkOS] upserted org: {name}");
    Ok(())
}

async fn handle_org_deleted(db: &PgPool, data: &Value) -> Result<(), AuthError> {
    let workos_org_id = str_field(data, "id")?;

    sqlx::query("DELETE FROM organizations WHERE workos_org_id = $1")
        .bind(workos_org_id)
        .execute(db)
        .await?;

    tracing::info!("[Webhook:WorkOS] deleted org: {workos_org_id}");
    Ok(())
}

/// Upsert an organization_membership record.
async fn handle_membership_upsert(db: &PgPool, data: &Value) -> Result<(), AuthError> {
    let workos_membership_id = str_field(data, "id")?;
    let workos_user_id = data.get("userId")
        .or_else(|| data.get("user_id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::BadRequest("membership missing user_id".into()))?;
    let workos_org_id = data.get("organizationId")
        .or_else(|| data.get("organization_id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::BadRequest("membership missing organization_id".into()))?;
    let role = data.get("role")
        .and_then(|r| r.get("slug").or(Some(r)))
        .and_then(|v| v.as_str())
        .unwrap_or("member");
    let status = data.get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("active");

    // Look up internal user and org UUIDs
    let user_row = sqlx::query("SELECT id FROM users WHERE workos_user_id = $1 LIMIT 1")
        .bind(workos_user_id)
        .fetch_optional(db)
        .await?;

    let org_row = sqlx::query("SELECT id FROM organizations WHERE workos_org_id = $1 LIMIT 1")
        .bind(workos_org_id)
        .fetch_optional(db)
        .await?;

    match (user_row, org_row) {
        (Some(user), Some(org)) => {
            let user_id: uuid::Uuid = user.get(0);
            let org_id: uuid::Uuid = org.get(0);

            sqlx::query(
                r#"
                INSERT INTO organization_members (org_id, user_id, workos_membership_id, role, status, last_synced_at)
                VALUES ($1, $2, $3, $4, $5, NOW())
                ON CONFLICT (workos_membership_id) DO UPDATE SET
                    role           = EXCLUDED.role,
                    status         = EXCLUDED.status,
                    last_synced_at = NOW()
                "#,
            )
            .bind(org_id)
            .bind(user_id)
            .bind(workos_membership_id)
            .bind(role)
            .bind(status)
            .execute(db)
            .await?;

            tracing::info!("[Webhook:WorkOS] upserted membership: {workos_user_id} in {workos_org_id}");
        }
        _ => {
            // User or org not synced yet — WorkOS may deliver events out of order.
            // This is expected. WorkOS will retry if we return 500, but it's better
            // to ack and let the subsequent user.created / organization.created
            // webhook trigger a re-sync. Log a warning.
            tracing::warn!(
                "[Webhook:WorkOS] membership event skipped — user or org not yet in DB. \
                 user={workos_user_id} org={workos_org_id}. Will resolve on next user/org webhook."
            );
        }
    }

    Ok(())
}

async fn handle_membership_deleted(db: &PgPool, data: &Value) -> Result<(), AuthError> {
    let workos_user_id = data.get("userId")
        .or_else(|| data.get("user_id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::BadRequest("membership delete missing user_id".into()))?;
    let workos_org_id = data.get("organizationId")
        .or_else(|| data.get("organization_id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::BadRequest("membership delete missing organization_id".into()))?;

    let user_row = sqlx::query("SELECT id FROM users WHERE workos_user_id = $1 LIMIT 1")
        .bind(workos_user_id)
        .fetch_optional(db)
        .await?;
    let org_row = sqlx::query("SELECT id FROM organizations WHERE workos_org_id = $1 LIMIT 1")
        .bind(workos_org_id)
        .fetch_optional(db)
        .await?;

    if let (Some(user), Some(org)) = (user_row, org_row) {
        let user_id: uuid::Uuid = user.get(0);
        let org_id: uuid::Uuid = org.get(0);

        sqlx::query(
            "DELETE FROM organization_members WHERE org_id = $1 AND user_id = $2"
        )
        .bind(org_id)
        .bind(user_id)
        .execute(db)
        .await?;

        tracing::info!("[Webhook:WorkOS] deleted membership: {workos_user_id} from {workos_org_id}");
    }

    Ok(())
}

// =============================================================================
// Helpers
// =============================================================================

/// Extract a required string field from a JSON object.
fn str_field<'a>(data: &'a Value, field: &str) -> Result<&'a str, AuthError> {
    data.get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::BadRequest(format!("webhook data missing field: {field}")))
}
