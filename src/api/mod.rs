//! Unified API router for runtools-auth.
//!
//! Mounts all endpoint groups under /v1/:
//! - /v1/auth     — JWT verify, session management, ID resolution
//! - /v1/api-keys — RunTools API key CRUD
//! - /v1/ssh-keys — SSH key CRUD
//! - /v1/secrets  — Encrypted secrets CRUD
//! - /v1/oauth    — OAuth flow + connection management
//! - /v1/status   — Health check

pub mod routes;

use crate::SharedState;
use axum::Router;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

pub fn router(state: SharedState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .nest("/v1", routes::v1_router(state))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
}
