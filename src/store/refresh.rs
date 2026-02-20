//! Background token refresh daemon for OAuth connections.
//!
//! Runs every 5 minutes. Finds tokens expiring within 10 minutes,
//! attempts to refresh them, and tracks consecutive failures.

use chrono::Utc;
use std::sync::Arc;
use tracing::{error, info, warn};

/// Start the refresh daemon loop.
pub async fn refresh_daemon(state: Arc<crate::AppState>) {
    let interval = tokio::time::Duration::from_secs(5 * 60);
    info!("Token refresh daemon started (interval: 5m)");

    loop {
        tokio::time::sleep(interval).await;
        if let Err(e) = refresh_cycle(&state).await {
            error!("Refresh cycle error: {e}");
        }
    }
}

async fn refresh_cycle(state: &crate::AppState) -> Result<(), Box<dyn std::error::Error>> {
    let expiring = state.store.get_expiring_connections(10).await?;

    if expiring.is_empty() {
        return Ok(());
    }

    info!("Found {} connections to refresh", expiring.len());

    for conn in expiring {
        let refresh_token = match &conn.refresh_token {
            Some(rt) => {
                state
                    .crypto
                    .decrypt(rt)
                    .map_err(|e| format!("decrypt error: {e}"))?
            }
            None => continue,
        };

        let provider = state.registry.get(&conn.provider);
        let provider = match provider {
            Some(p) => p,
            None => {
                warn!("Provider {} not found for connection {}", conn.provider, conn.id);
                continue;
            }
        };

        match provider.refresh_token(&refresh_token).await {
            Ok(tokens) => {
                let expires_at = tokens
                    .expires_in
                    .map(|secs| Utc::now() + chrono::Duration::seconds(secs as i64));

                state
                    .store
                    .update_refreshed_tokens(
                        &state.crypto,
                        &conn.id,
                        &tokens.access_token,
                        tokens.refresh_token.as_deref(),
                        expires_at,
                    )
                    .await?;

                info!("Refreshed {} token for {}/{}", conn.provider, conn.org_id, conn.user_id);
            }
            Err(e) => {
                error!("Failed to refresh {} for {}: {e}", conn.provider, conn.id);
                state.store.increment_failure(&conn.id).await?;
            }
        }
    }

    Ok(())
}
