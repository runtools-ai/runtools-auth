//! PostgreSQL-backed token store for OAuth connections and audit events.
//!
//! Migrated from SQLite to PostgreSQL. Tables:
//! - `oauth_connections`: encrypted OAuth tokens per (org_id, user_id, provider)
//! - `auth_events`: audit log for all auth-related operations

use crate::crypto::CryptoEngine;
use crate::error::AuthError;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{PgPool, Row};

/// Token store backed by PostgreSQL.
pub struct TokenStore {
    pub pool: PgPool,
}

impl TokenStore {
    pub async fn new(db_url: &str) -> Result<Self, AuthError> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(20)
            .connect(db_url)
            .await
            .map_err(|e| AuthError::Database(format!("Failed to connect to PostgreSQL: {e}")))?;

        Ok(Self { pool })
    }

    /// Run schema migrations.
    pub async fn migrate(&self) -> Result<(), AuthError> {
        // OAuth connections table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS oauth_connections (
                id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                org_id          TEXT NOT NULL,
                user_id         TEXT NOT NULL DEFAULT '',
                provider        TEXT NOT NULL,
                access_token    TEXT NOT NULL,
                refresh_token   TEXT,
                token_type      TEXT DEFAULT 'Bearer',
                scopes          TEXT DEFAULT '',
                expires_at      TIMESTAMPTZ,
                platform_user_id   TEXT DEFAULT '',
                platform_username  TEXT DEFAULT '',
                display_name       TEXT DEFAULT '',
                profile_image_url  TEXT DEFAULT '',
                raw_profile        JSONB,
                failure_count   INT DEFAULT 0,
                created_at      TIMESTAMPTZ DEFAULT NOW(),
                updated_at      TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(org_id, user_id, provider, platform_user_id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Audit events table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS auth_events (
                id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                org_id      TEXT NOT NULL,
                user_id     TEXT DEFAULT '',
                event_type  TEXT NOT NULL,
                provider    TEXT DEFAULT '',
                metadata    JSONB DEFAULT '{}',
                ip_address  TEXT DEFAULT '',
                user_agent  TEXT DEFAULT '',
                created_at  TIMESTAMPTZ DEFAULT NOW()
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Secrets table — matches the production schema managed by Drizzle in the orchestrator.
        // NOTE: This CREATE TABLE IF NOT EXISTS will not modify an existing table,
        // so this is safe to run against production. It only applies when bootstrapping
        // a fresh database (e.g., local dev).
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS secrets (
                id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                org_id          UUID NOT NULL,
                name            TEXT NOT NULL,
                value_encrypted TEXT NOT NULL,
                encryption_key_id TEXT,
                scope           TEXT NOT NULL DEFAULT 'all',
                category        TEXT NOT NULL DEFAULT 'custom',
                description     TEXT,
                created_by      UUID,
                created_at      TIMESTAMPTZ DEFAULT NOW(),
                updated_at      TIMESTAMPTZ DEFAULT NOW(),
                last_rotated_at TIMESTAMPTZ,
                UNIQUE(org_id, name)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // For existing production databases: add columns that may have been added
        // after initial deployment. These are safe no-ops if columns already exist.
        sqlx::query(
            "ALTER TABLE secrets ADD COLUMN IF NOT EXISTS category TEXT NOT NULL DEFAULT 'custom'"
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "ALTER TABLE secrets ADD COLUMN IF NOT EXISTS encryption_key_id TEXT"
        )
        .execute(&self.pool)
        .await?;

        // Indexes
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_oauth_connections_lookup ON oauth_connections(org_id, user_id, provider)"
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_oauth_connections_expiry ON oauth_connections(expires_at) WHERE failure_count < 3"
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_secrets_org ON secrets(org_id)"
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_auth_events_org ON auth_events(org_id, created_at DESC)"
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Upsert an OAuth connection (stores encrypted tokens).
    pub async fn upsert_connection(
        &self,
        crypto: &CryptoEngine,
        conn: &ConnectionUpsert,
    ) -> Result<String, AuthError> {
        let enc_access = crypto
            .encrypt(&conn.access_token)
            .map_err(|e| AuthError::Encryption(e.to_string()))?;

        let enc_refresh = match &conn.refresh_token {
            Some(rt) => Some(
                crypto
                    .encrypt(rt)
                    .map_err(|e| AuthError::Encryption(e.to_string()))?,
            ),
            None => None,
        };

        let row = sqlx::query(
            r#"
            INSERT INTO oauth_connections
                (org_id, user_id, provider, access_token, refresh_token, token_type, scopes,
                 expires_at, platform_user_id, platform_username, display_name,
                 profile_image_url, raw_profile, failure_count)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 0)
            ON CONFLICT (org_id, user_id, provider, platform_user_id)
            DO UPDATE SET
                access_token = EXCLUDED.access_token,
                refresh_token = COALESCE(EXCLUDED.refresh_token, oauth_connections.refresh_token),
                token_type = EXCLUDED.token_type,
                scopes = EXCLUDED.scopes,
                expires_at = EXCLUDED.expires_at,
                platform_username = EXCLUDED.platform_username,
                display_name = EXCLUDED.display_name,
                profile_image_url = EXCLUDED.profile_image_url,
                raw_profile = EXCLUDED.raw_profile,
                failure_count = 0,
                updated_at = NOW()
            RETURNING id::text
            "#,
        )
        .bind(&conn.org_id)
        .bind(&conn.user_id)
        .bind(&conn.provider)
        .bind(&enc_access)
        .bind(&enc_refresh)
        .bind(&conn.token_type)
        .bind(&conn.scopes)
        .bind(conn.expires_at)
        .bind(&conn.platform_user_id)
        .bind(&conn.platform_username)
        .bind(&conn.display_name)
        .bind(&conn.profile_image_url)
        .bind(&conn.raw_profile)
        .fetch_one(&self.pool)
        .await?;

        let id: String = row.get(0);
        Ok(id)
    }

    /// Get a decrypted access token for a connection.
    pub async fn get_token(
        &self,
        crypto: &CryptoEngine,
        org_id: &str,
        user_id: &str,
        provider: &str,
    ) -> Result<Option<ConnectionToken>, AuthError> {
        let row = sqlx::query(
            r#"
            SELECT id::text, access_token, refresh_token, expires_at
            FROM oauth_connections
            WHERE org_id = $1 AND user_id = $2 AND provider = $3
            ORDER BY updated_at DESC
            LIMIT 1
            "#,
        )
        .bind(org_id)
        .bind(user_id)
        .bind(provider)
        .fetch_optional(&self.pool)
        .await?;

        let row = match row {
            Some(r) => r,
            None => return Ok(None),
        };

        let id: String = row.get(0);
        let enc_access: String = row.get(1);
        let enc_refresh: Option<String> = row.try_get(2).ok();
        let expires_at: Option<DateTime<Utc>> = row.try_get(3).ok();

        let access_token = crypto
            .decrypt(&enc_access)
            .map_err(|e| AuthError::Decryption(e.to_string()))?;

        let refresh_token = match enc_refresh {
            Some(ref rt) if !rt.is_empty() => Some(
                crypto
                    .decrypt(rt)
                    .map_err(|e| AuthError::Decryption(e.to_string()))?,
            ),
            _ => None,
        };

        Ok(Some(ConnectionToken {
            id,
            access_token,
            refresh_token,
            expires_at,
            is_expired: expires_at.map(|e| e < Utc::now()).unwrap_or(false),
        }))
    }

    /// List connections for an org (metadata only, no tokens).
    pub async fn list_connections(
        &self,
        org_id: &str,
        user_id: Option<&str>,
    ) -> Result<Vec<ConnectionInfo>, AuthError> {
        let rows = if let Some(uid) = user_id {
            sqlx::query(
                r#"
                SELECT id::text, provider, platform_user_id, platform_username,
                       display_name, profile_image_url, scopes, expires_at,
                       failure_count, created_at, updated_at
                FROM oauth_connections
                WHERE org_id = $1 AND user_id = $2
                ORDER BY updated_at DESC
                "#,
            )
            .bind(org_id)
            .bind(uid)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                r#"
                SELECT id::text, provider, platform_user_id, platform_username,
                       display_name, profile_image_url, scopes, expires_at,
                       failure_count, created_at, updated_at
                FROM oauth_connections
                WHERE org_id = $1
                ORDER BY updated_at DESC
                "#,
            )
            .bind(org_id)
            .fetch_all(&self.pool)
            .await?
        };

        let conns = rows
            .iter()
            .map(|row| ConnectionInfo {
                id: row.get(0),
                provider: row.get(1),
                platform_user_id: row.get(2),
                platform_username: row.get(3),
                display_name: row.get(4),
                profile_image_url: row.get(5),
                scopes: row.get(6),
                expires_at: row.try_get(7).ok(),
                failure_count: row.get(8),
                created_at: row.get(9),
                updated_at: row.get(10),
            })
            .collect();

        Ok(conns)
    }

    /// Delete a connection.
    pub async fn delete_connection(
        &self,
        connection_id: &str,
        org_id: &str,
    ) -> Result<(), AuthError> {
        let affected = sqlx::query(
            "DELETE FROM oauth_connections WHERE id = $1::uuid AND org_id = $2",
        )
        .bind(connection_id)
        .bind(org_id)
        .execute(&self.pool)
        .await?
        .rows_affected();

        if affected == 0 {
            return Err(AuthError::NotFound("connection".into()));
        }

        Ok(())
    }

    /// Get connections that are expiring soon (for the refresh daemon).
    pub async fn get_expiring_connections(
        &self,
        within_minutes: i64,
    ) -> Result<Vec<ExpiringConnection>, AuthError> {
        let rows = sqlx::query(
            r#"
            SELECT id::text, org_id, user_id, provider, refresh_token
            FROM oauth_connections
            WHERE expires_at < NOW() + ($1 || ' minutes')::interval
              AND failure_count < 3
              AND refresh_token IS NOT NULL
            "#,
        )
        .bind(within_minutes.to_string())
        .fetch_all(&self.pool)
        .await?;

        let conns = rows
            .iter()
            .map(|row| ExpiringConnection {
                id: row.get(0),
                org_id: row.get(1),
                user_id: row.get(2),
                provider: row.get(3),
                refresh_token: row.try_get(4).ok(),
            })
            .collect();

        Ok(conns)
    }

    /// Update a connection's tokens after a refresh.
    pub async fn update_refreshed_tokens(
        &self,
        crypto: &CryptoEngine,
        connection_id: &str,
        access_token: &str,
        refresh_token: Option<&str>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<(), AuthError> {
        let enc_access = crypto
            .encrypt(access_token)
            .map_err(|e| AuthError::Encryption(e.to_string()))?;

        let enc_refresh = match refresh_token {
            Some(rt) => Some(
                crypto
                    .encrypt(rt)
                    .map_err(|e| AuthError::Encryption(e.to_string()))?,
            ),
            None => None,
        };

        sqlx::query(
            r#"
            UPDATE oauth_connections
            SET access_token = $1,
                refresh_token = COALESCE($2, refresh_token),
                expires_at = $3,
                failure_count = 0,
                updated_at = NOW()
            WHERE id = $4::uuid
            "#,
        )
        .bind(&enc_access)
        .bind(&enc_refresh)
        .bind(expires_at)
        .bind(connection_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Increment failure count for a connection.
    pub async fn increment_failure(&self, connection_id: &str) -> Result<(), AuthError> {
        sqlx::query(
            "UPDATE oauth_connections SET failure_count = failure_count + 1, updated_at = NOW() WHERE id = $1::uuid",
        )
        .bind(connection_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Log an audit event.
    pub async fn log_event(
        &self,
        org_id: &str,
        user_id: &str,
        event_type: &str,
        provider: &str,
        metadata: serde_json::Value,
    ) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            INSERT INTO auth_events (org_id, user_id, event_type, provider, metadata)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(org_id)
        .bind(user_id)
        .bind(event_type)
        .bind(provider)
        .bind(metadata)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Expose the pool for direct use by other modules (eg: auth/verify).
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct ConnectionUpsert {
    pub org_id: String,
    pub user_id: String,
    pub provider: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub scopes: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub platform_user_id: String,
    pub platform_username: String,
    pub display_name: String,
    pub profile_image_url: String,
    pub raw_profile: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct ConnectionToken {
    pub id: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_expired: bool,
}

#[derive(Debug, Serialize)]
pub struct ConnectionInfo {
    pub id: String,
    pub provider: String,
    pub platform_user_id: String,
    pub platform_username: String,
    pub display_name: String,
    pub profile_image_url: String,
    pub scopes: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub failure_count: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct ExpiringConnection {
    pub id: String,
    pub org_id: String,
    pub user_id: String,
    pub provider: String,
    pub refresh_token: Option<String>,
}
