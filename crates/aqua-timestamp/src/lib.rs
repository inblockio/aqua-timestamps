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

use anyhow::{Context, Result};
use aqua_timestamp_core::{
    accumulator::Accumulator,
    sealer::{run_sealer_with_channel, run_sealer_with_interval, SealTick},
    storage::Store,
    time::{Clock, SystemClock},
};
use axum::{
    routing::{get, post},
    Router,
};
use tokio::sync::mpsc;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::{
    auth::{build_stores, challenge, session},
    config::Config,
    identity::{build_identity_tree, build_response, IdentityClaimOverrides, ServiceIdentity},
    routes::{
        aqua_identity, health, landing_page, list_epochs, not_found, schedule, submit_leaves,
    },
    state::AppState,
};

/// How the M2 seal task is driven. Production code uses
/// [`SealDriver::Interval`]; integration tests use [`SealDriver::Channel`]
/// to seal deterministically without `tokio::time::advance`.
pub enum SealDriver {
    /// Real tokio-time interval, ticking every `epoch.duration_secs`.
    Interval,
    /// Test channel. Each `send(SealTick { now })` causes one seal cycle.
    Channel(mpsc::Receiver<SealTick>),
    /// Don't spawn a seal task at all. The accumulator still works; only
    /// the timer is suppressed. Useful for tests that exercise pure
    /// accumulator behaviour.
    Off,
}

/// Build the full Axum router and the state behind it. Used by the
/// binary's `main()` and the integration tests.
///
/// `overrides` lets the identity-snapshot test pin `valid_from` so the
/// golden bytes stay stable across runs. `seal_driver` chooses between
/// the production interval-based sealer and the deterministic channel
/// sealer used by tests.
pub async fn build_app(
    cfg: Config,
    identity: ServiceIdentity,
    overrides: IdentityClaimOverrides,
    seal_driver: SealDriver,
) -> Result<(Router, Arc<AppState>)> {
    let identity_tree = build_identity_tree(&identity, &overrides).await?;
    let identity_response_json = build_response(&identity, &identity_tree)?;

    let (challenges, sessions) = build_stores(
        cfg.auth.challenge_ttl_secs,
        cfg.auth.session_ttl_secs,
        cfg.identity.dns.clone(),
        format!("https://{}", cfg.identity.dns),
    );

    sessions.start_cleanup(Arc::clone(&challenges), 60);

    let store = Store::open(&cfg.storage.path)
        .with_context(|| format!("opening fjall keyspace at {}", cfg.storage.path.display()))?;

    let clock = SystemClock;
    let now = clock.now_secs();

    // Epoch ids are monotonic across restarts: pick up at
    // `last_sealed_epoch_id + 1`, or start at 1 on a fresh install.
    let next_epoch_id = match store
        .last_sealed_epoch_id()
        .context("reading last_sealed_epoch_id")?
    {
        Some(id) => id.saturating_add(1),
        None => 1,
    };
    let accumulator = Arc::new(Accumulator::new(
        next_epoch_id,
        now,
        cfg.epoch.duration_secs,
    ));
    info!(
        next_epoch_id,
        opened_at = now,
        duration_secs = cfg.epoch.duration_secs,
        "accumulator opened"
    );

    // Spawn the seal task.
    match seal_driver {
        SealDriver::Interval => {
            run_sealer_with_interval(
                Arc::clone(&accumulator),
                store.clone(),
                clock,
                cfg.epoch.duration_secs,
            );
        }
        SealDriver::Channel(rx) => {
            run_sealer_with_channel(
                Arc::clone(&accumulator),
                store.clone(),
                rx,
                cfg.epoch.duration_secs,
            );
        }
        SealDriver::Off => {}
    }

    let state = Arc::new(AppState {
        started_at: std::time::Instant::now(),
        config: cfg,
        identity,
        identity_response_json,
        challenges,
        sessions,
        accumulator,
        store,
    });

    let router = Router::new()
        .route("/health", get(health))
        .route("/", get(landing_page))
        .route("/.well-known/aqua-identity", get(aqua_identity))
        .route("/auth/challenge", get(challenge))
        .route("/auth/session", post(session))
        .route("/v1/leaves", post(submit_leaves))
        .route("/v1/schedule", get(schedule))
        .route("/v1/epochs", get(list_epochs))
        .fallback(not_found)
        .layer(TraceLayer::new_for_http())
        .with_state(Arc::clone(&state));

    Ok((router, state))
}
