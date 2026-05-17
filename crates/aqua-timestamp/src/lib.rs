//! aqua-timestamp library entry point. The binary in `main.rs` is a thin
//! wrapper around the items re-exported here so integration tests can
//! drive the same code paths in-process.

pub mod auth;
pub mod config;
pub mod identity;
pub mod landing;
pub mod routes;
pub mod state;

use std::sync::Arc;

use anyhow::Result;
use axum::{
    routing::{get, post},
    Router,
};
use tower_http::trace::TraceLayer;

use crate::{
    auth::{build_stores, challenge, session},
    config::Config,
    identity::{build_identity_tree, build_response, IdentityClaimOverrides, ServiceIdentity},
    routes::{aqua_identity, health, landing_page, not_found, submit_leaves},
    state::AppState,
};

/// Build the full Axum router and the state behind it. Used by the
/// binary's `main()` and the integration tests.
///
/// `overrides` lets tests pin `valid_from` so a snapshot golden is stable.
pub async fn build_app(
    cfg: Config,
    identity: ServiceIdentity,
    overrides: IdentityClaimOverrides,
) -> Result<(Router, Arc<AppState>)> {
    let identity_tree = build_identity_tree(&identity, &overrides).await?;
    let identity_response_json = build_response(&identity, &identity_tree)?;

    let (challenges, sessions) = build_stores(
        cfg.auth.challenge_ttl_secs,
        cfg.auth.session_ttl_secs,
        cfg.identity.dns.clone(),
        format!("https://{}", cfg.identity.dns),
    );

    // Spawn the background cleanup loop.
    sessions.start_cleanup(Arc::clone(&challenges), 60);

    let state = Arc::new(AppState {
        started_at: std::time::Instant::now(),
        config: cfg,
        identity,
        identity_response_json,
        challenges,
        sessions,
    });

    let router = Router::new()
        .route("/health", get(health))
        .route("/", get(landing_page))
        .route("/.well-known/aqua-identity", get(aqua_identity))
        .route("/auth/challenge", get(challenge))
        .route("/auth/session", post(session))
        .route("/v1/leaves", post(submit_leaves))
        .fallback(not_found)
        .layer(TraceLayer::new_for_http())
        .with_state(Arc::clone(&state));

    Ok((router, state))
}
