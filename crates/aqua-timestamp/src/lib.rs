//! aqua-timestamp library entry point. The binary in `main.rs` is a thin
//! wrapper around the items re-exported here so integration tests can
//! drive the same code paths in-process.

pub mod auth;
pub mod config;
pub mod docs;
pub mod identity;
pub mod landing;
pub mod oracle;
pub mod routes;
pub mod state;

use std::sync::Arc;

use anyhow::{Context, Result};
use aqua_rs_sdk::{web::tsa::TsaTimestamper, CliEthTimestamper, Secp256k1Signer};
use aqua_timestamp_core::{
    accumulator::Accumulator,
    anchors::AnchorProvider,
    bonding_curve::BalanceOracle,
    sealer::{
        run_sealer_with_bonding_curve, run_sealer_with_channel, run_sealer_with_interval,
        BondingCurveParams, SealTick, WitnessContext,
    },
    storage::Store,
    time::{Clock, SystemClock},
    witness::AnchorMethod,
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
        aqua_identity, docs_page, get_tree_by_leaf, get_tree_by_tip, health, landing_page,
        list_epochs, list_or_query_trees, not_found, schedule, submit_leaves,
        well_known_skill_auth_md, well_known_skill_md,
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

    // The sealer (M3) signs every minted witness with the service key.
    // We construct the EIP-191 signer once at boot and share it via Arc
    // so both the sealer task and any future on-demand minter paths reuse
    // the same in-memory key material.
    let signer = Arc::new(Secp256k1Signer::new(identity.private_key.as_ref().clone()));
    // M4: if `[anchors.evm].enabled = true` (the default), construct a
    // real `CliEthTimestamper` against Sepolia and let the sealer call
    // it once per non-empty epoch. On any failure the sealer falls back
    // to stub witness data and keeps sealing; sealing never fails
    // because the anchor failed. See `sealer::resolve_evm_outcome`.
    let evm_anchor_cfg = cfg.effective_evm_anchor();
    let evm_anchor: Option<Arc<dyn AnchorProvider>> = if evm_anchor_cfg.enabled {
        let chain = evm_anchor_cfg
            .evm_chain()
            .context("parsing anchors.evm.chain")?;
        info!(
            chain = %chain,
            rpc_url = %evm_anchor_cfg.rpc_url,
            network_label = %evm_anchor_cfg.network_label,
            "evm anchor enabled (CliEthTimestamper)"
        );
        let timestamper = CliEthTimestamper::new(
            identity.mnemonic.as_ref().clone(),
            evm_anchor_cfg.rpc_url.clone(),
            chain,
        );
        Some(Arc::new(timestamper) as Arc<dyn AnchorProvider>)
    } else {
        info!("evm anchor disabled: minting stub witnesses for evm method");
        None
    };
    // M5: parallel wiring for qTSA. Same shape as EVM, just a different
    // SDK provider. `TsaTimestamper::new(url, Some(duration))` honours
    // the rate-limit guidance the SDK's own docstring gives for
    // eIDAS-qualified endpoints; `None` disables the throttle.
    let qtsa_anchor_cfg = cfg.anchors.qtsa.clone();
    let qtsa_anchor: Option<Arc<dyn AnchorProvider>> = if qtsa_anchor_cfg.enabled {
        info!(
            url = %qtsa_anchor_cfg.url,
            min_request_interval_secs = qtsa_anchor_cfg.min_request_interval_secs,
            network_label = %qtsa_anchor_cfg.network_label,
            "qtsa anchor enabled (TsaTimestamper)"
        );
        let timestamper =
            TsaTimestamper::new(qtsa_anchor_cfg.url.clone(), qtsa_anchor_cfg.throttle());
        Some(Arc::new(timestamper) as Arc<dyn AnchorProvider>)
    } else {
        info!("qtsa anchor disabled: minting stub witnesses for qtsa method");
        None
    };

    let mut witness_ctx = WitnessContext::new(
        Arc::clone(&signer),
        format!("0x{}", identity.address_eip55.trim_start_matches("0x")),
        evm_anchor_cfg.network_label.clone(),
        vec![AnchorMethod::Evm, AnchorMethod::Qtsa],
    );
    if let Some(anchor) = evm_anchor {
        witness_ctx = witness_ctx.with_evm_anchor(anchor);
    }
    if let Some(anchor) = qtsa_anchor {
        witness_ctx = witness_ctx.with_qtsa_anchor(anchor);
    }

    // Spawn the seal task.
    match seal_driver {
        SealDriver::Interval if cfg.bonding_curve.enabled => {
            let wallet_addr: alloy::primitives::Address =
                identity.address_eip55.parse().with_context(|| {
                    format!(
                        "parsing service wallet address {:?}",
                        identity.address_eip55
                    )
                })?;
            let oracle: Arc<dyn BalanceOracle> = Arc::new(oracle::AlloyOracle::new(
                evm_anchor_cfg.rpc_url.clone(),
                wallet_addr,
            ));
            let params = BondingCurveParams {
                n_half: cfg.bonding_curve.n_half,
                poll_interval_secs: cfg.bonding_curve.poll_interval_secs,
                min_balance_multiplier: cfg.bonding_curve.min_balance_multiplier,
            };
            info!(
                n_half = params.n_half,
                poll_interval_secs = params.poll_interval_secs,
                rpc_url = %evm_anchor_cfg.rpc_url,
                "bonding curve sealer enabled"
            );
            run_sealer_with_bonding_curve(
                Arc::clone(&accumulator),
                store.clone(),
                clock,
                oracle,
                params,
                Some(witness_ctx.clone()),
                None,
            );
        }
        SealDriver::Interval => {
            run_sealer_with_interval(
                Arc::clone(&accumulator),
                store.clone(),
                clock,
                cfg.epoch.duration_secs,
                Some(witness_ctx.clone()),
                None,
            );
        }
        SealDriver::Channel(rx) => {
            run_sealer_with_channel(
                Arc::clone(&accumulator),
                store.clone(),
                rx,
                cfg.epoch.duration_secs,
                Some(witness_ctx.clone()),
                None,
            );
        }
        SealDriver::Off => {}
    }

    let rendered_docs_html = docs::render_html(&identity);
    let rendered_skill_md = docs::render_skill_md(&identity);
    let rendered_skill_auth_md = docs::render_skill_auth_md(&identity);

    let state = Arc::new(AppState {
        started_at: std::time::Instant::now(),
        config: cfg,
        identity,
        identity_response_json,
        challenges,
        sessions,
        accumulator,
        store,
        signer,
        witness_ctx,
        docs_html: rendered_docs_html,
        well_known_skill_md: rendered_skill_md,
        well_known_skill_auth_md: rendered_skill_auth_md,
    });

    let router = Router::new()
        .route("/health", get(health))
        .route("/", get(landing_page))
        .route("/docs", get(docs_page))
        .route("/.well-known/aqua-skill.md", get(well_known_skill_md))
        .route(
            "/.well-known/aqua-skill-auth.md",
            get(well_known_skill_auth_md),
        )
        .route("/.well-known/aqua-identity", get(aqua_identity))
        .route("/auth/challenge", get(challenge))
        .route("/auth/session", post(session))
        .route("/v1/leaves", post(submit_leaves))
        .route("/v1/schedule", get(schedule))
        .route("/v1/epochs", get(list_epochs))
        .route("/trees", get(list_or_query_trees))
        .route("/trees/{tip_hex}", get(get_tree_by_tip))
        .route("/trees/by-leaf/{leaf_hex}", get(get_tree_by_leaf))
        .fallback(not_found)
        .layer(TraceLayer::new_for_http())
        .with_state(Arc::clone(&state));

    Ok((router, state))
}
