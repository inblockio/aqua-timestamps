//! aqua-timestamp library entry point. The binary in `main.rs` is a thin
//! wrapper around the items re-exported here so integration tests can
//! drive the same code paths in-process.

pub mod auth;
pub mod blueprint;
pub mod config;
pub mod docs;
pub mod identity;
pub mod landing;
pub mod oracle;
pub mod routes;
pub mod state;
pub mod watcher;

use std::sync::Arc;

use anyhow::{Context, Result};
use aqua_evm_provider::CliEthTimestamper;
use aqua_rs_sdk::Secp256k1Signer;
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
use aqua_tsa_provider::TsaTimestamper;
use axum::{
    routing::{get, post},
    Router,
};
use tokio::sync::mpsc;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

use crate::{
    auth::{build_stores, challenge, session},
    config::Config,
    identity::{build_identity_tree, build_response, IdentityClaimOverrides, ServiceIdentity},
    routes::{
        apple_touch_icon, aqua_identity, aqua_orl, blueprint_page, docs_page, favicon_ico,
        get_tree_by_leaf, get_tree_by_tip, health, landing_page, leaderboard, list_epochs,
        list_or_query_trees, not_found, pool_status, schedule, sse_events, submit_leaves, version,
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
/// Anchor providers injected in place of the ones `build_app` builds from
/// the config (tests, offline tooling). An override serves an ENABLED method
/// only; a disabled method mints nothing whatever is injected.
#[derive(Clone, Default)]
pub struct AnchorOverrides {
    pub evm: Option<Arc<dyn AnchorProvider>>,
    pub qtsa: Option<Arc<dyn AnchorProvider>>,
    /// Chain host the pre-serve self-check judges EVM witnesses against, in
    /// place of `EthBlockchainHost` on `[anchors.evm].rpc_url`.
    pub evm_check_host: Option<Arc<dyn aqua_rs_sdk::BlockchainHost>>,
    /// TSA host the pre-serve self-check judges qTSA tokens with, in place of
    /// `TsaWebHost::new()` (the reader's default EU trust list validation).
    pub tsa_check_host: Option<Arc<dyn aqua_rs_sdk::WebHost>>,
}

pub async fn build_app(
    cfg: Config,
    identity: ServiceIdentity,
    overrides: IdentityClaimOverrides,
    seal_driver: SealDriver,
) -> Result<(Router, Arc<AppState>)> {
    build_app_with_anchors(
        cfg,
        identity,
        overrides,
        seal_driver,
        AnchorOverrides::default(),
    )
    .await
}

/// [`build_app`] with injected anchor providers ([`AnchorOverrides`]).
pub async fn build_app_with_anchors(
    cfg: Config,
    identity: ServiceIdentity,
    overrides: IdentityClaimOverrides,
    seal_driver: SealDriver,
    anchors: AnchorOverrides,
) -> Result<(Router, Arc<AppState>)> {
    // D51: an enabled method without a provider refuses to start. An
    // injected provider stands in for the configured one.
    if anchors.evm.is_none() || anchors.qtsa.is_none() {
        let mut check = cfg.clone();
        check.anchors.evm.enabled &= anchors.evm.is_none();
        check.anchors.qtsa.enabled &= anchors.qtsa.is_none();
        check
            .check_enabled_anchors(identity.mnemonic.as_str())
            .context("anchor configuration (decision D51: no placeholder witnesses)")?;
    }
    // OW1.6 F1/M1: one chain source, checked even for injected providers.
    cfg.check_evm_chain_source()
        .context("anchor configuration (one EVM chain source)")?;
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
    // Anchor providers (decision D51). An enabled method gets its live
    // provider (`CliEthTimestamper` for EVM, `TsaTimestamper` for qTSA, or
    // the injected override); a failed anchor call leaves that method's
    // witnesses pending and the sealer retries the same epoch root on every
    // tick. A disabled method is an explicit opt-out: it mints nothing.
    let evm_anchor_cfg = cfg.anchors.evm.clone();
    let mut methods = Vec::new();
    let evm_anchor: Option<Arc<dyn AnchorProvider>> = if !evm_anchor_cfg.enabled {
        warn!("evm anchor disabled by config: no evm witnesses are minted");
        None
    } else if let Some(injected) = anchors.evm {
        info!("evm anchor enabled (injected provider)");
        methods.push(AnchorMethod::Evm);
        Some(injected)
    } else {
        let chain = evm_anchor_cfg
            .evm_chain()
            .context("parsing anchors.evm.chain")?;
        info!(
            chain = %chain,
            rpc_url = %evm_anchor_cfg.rpc_url,
            "evm anchor enabled (CliEthTimestamper)"
        );
        methods.push(AnchorMethod::Evm);
        Some(Arc::new(CliEthTimestamper::new(
            identity.mnemonic.as_ref().clone(),
            evm_anchor_cfg.rpc_url.clone(),
            chain,
        )) as Arc<dyn AnchorProvider>)
    };
    // `TsaTimestamper::with_min_request_interval` honours the rate-limit
    // guidance the SDK gives for eIDAS-qualified endpoints; every call,
    // retries included, goes through it.
    let qtsa_anchor_cfg = cfg.anchors.qtsa.clone();
    let qtsa_anchor: Option<Arc<dyn AnchorProvider>> = if !qtsa_anchor_cfg.enabled {
        warn!("qtsa anchor disabled by config: no qtsa witnesses are minted");
        None
    } else if let Some(injected) = anchors.qtsa {
        info!("qtsa anchor enabled (injected provider)");
        methods.push(AnchorMethod::Qtsa);
        Some(injected)
    } else {
        info!(
            url = %qtsa_anchor_cfg.url,
            min_request_interval_secs = qtsa_anchor_cfg.min_request_interval_secs,
            "qtsa anchor enabled (TsaTimestamper)"
        );
        let timestamper = match qtsa_anchor_cfg.throttle() {
            Some(interval) => {
                TsaTimestamper::new(qtsa_anchor_cfg.url.clone()).with_min_request_interval(interval)
            }
            None => TsaTimestamper::new(qtsa_anchor_cfg.url.clone()),
        };
        methods.push(AnchorMethod::Qtsa);
        Some(Arc::new(timestamper) as Arc<dyn AnchorProvider>)
    };

    let mut witness_ctx = WitnessContext::new(
        Arc::clone(&signer),
        format!("0x{}", identity.address_eip55.trim_start_matches("0x")),
        methods,
    );
    witness_ctx.evm_not_found_timeout_secs = evm_anchor_cfg.not_found_timeout_secs;
    if let Some(anchor) = evm_anchor {
        witness_ctx = witness_ctx.with_evm_anchor(anchor);
    }
    if let Some(anchor) = qtsa_anchor {
        witness_ctx = witness_ctx.with_qtsa_anchor(anchor);
    }
    // Pre-serve self-check (OW1.4): every minted witness is verified with
    // the SDK, against the reader's default hosts, before it is served.
    let evm_check_host: Option<Arc<dyn aqua_rs_sdk::BlockchainHost>> = match (
        witness_ctx.methods.contains(&AnchorMethod::Evm),
        anchors.evm_check_host,
    ) {
        (false, _) => None,
        (true, Some(host)) => Some(host),
        (true, None) => {
            // OW1.6 F1/M1: the chain the provider writes into the payload.
            let chain_id = evm_anchor_cfg
                .evm_chain()
                .context("parsing anchors.evm.chain")?
                .chain_id();
            Some(Arc::new(
                aqua_evm_provider::EthBlockchainHost::new(tokio::runtime::Handle::current())
                    .with_endpoint(chain_id, evm_anchor_cfg.rpc_url.clone()),
            ))
        }
    };
    let tsa_check_host: Option<Arc<dyn aqua_rs_sdk::WebHost>> = match (
        witness_ctx.methods.contains(&AnchorMethod::Qtsa),
        anchors.tsa_check_host,
    ) {
        (false, _) => None,
        (true, Some(host)) => Some(host),
        (true, None) => Some(Arc::new(aqua_tsa_provider::TsaWebHost::new())),
    };
    info!(
        evm_finality = ?evm_anchor_cfg.self_check_finality,
        "pre-serve self-check enabled"
    );
    witness_ctx = witness_ctx.with_self_check(aqua_timestamp_core::selfcheck::SelfCheckHosts {
        blockchain: evm_check_host,
        tsa: tsa_check_host,
        evm_finality: evm_anchor_cfg.self_check_finality,
    });
    witness_ctx
        .validate()
        .context("anchor providers and self-check hosts (decision D51, OW1.4)")?;

    // EventBus: fan-out broadcast channel for SSE subscribers. Created once
    // here so both the sealer task and the AppState share the same sender.
    let event_bus = aqua_timestamp_core::events::EventBus::new(256);

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
                Some(event_bus.clone()),
            );
        }
        SealDriver::Interval => {
            run_sealer_with_interval(
                Arc::clone(&accumulator),
                store.clone(),
                clock,
                cfg.epoch.duration_secs,
                Some(witness_ctx.clone()),
                Some(event_bus.clone()),
            );
        }
        SealDriver::Channel(rx) => {
            run_sealer_with_channel(
                Arc::clone(&accumulator),
                store.clone(),
                rx,
                cfg.epoch.duration_secs,
                Some(witness_ctx.clone()),
                Some(event_bus.clone()),
            );
        }
        SealDriver::Off => {}
    }

    // Leaderboard: spawn the block watcher if enabled.
    if cfg.leaderboard.enabled {
        let wallet_str = &cfg.leaderboard.wallet_address;
        match wallet_str.parse::<alloy::primitives::Address>() {
            Ok(addr) => {
                let chain_id = cfg.leaderboard_chain_id();
                let bw =
                    watcher::BlockWatcher::new(cfg.leaderboard.rpc_url.clone(), addr, chain_id);
                let interval = std::time::Duration::from_secs(cfg.leaderboard.poll_interval_secs);
                watcher::spawn_watcher(store.clone(), bw, interval);
                info!(
                    rpc_url = %cfg.leaderboard.rpc_url,
                    wallet = %wallet_str,
                    chain_id,
                    poll_secs = cfg.leaderboard.poll_interval_secs,
                    "leaderboard watcher spawned"
                );
            }
            Err(e) => {
                warn!(
                    wallet = %wallet_str,
                    error = %e,
                    "leaderboard watcher disabled: invalid wallet address"
                );
            }
        }
    }

    let rendered_docs_html = docs::render_html(&identity);
    let rendered_skill_md = docs::render_skill_md(&identity);
    let rendered_skill_auth_md = docs::render_skill_auth_md(&identity);

    // Health tick: periodic SSE event with cumulative totals so the landing
    // page always shows the correct "Leaves timestamped" count, even for
    // clients that connect between epoch seals.
    {
        let bus = event_bus.clone();
        let store_for_tick = store.clone();
        let started = std::time::Instant::now();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                let (epochs_total, leaves_total) = match store_for_tick.totals() {
                    Ok(t) => t,
                    Err(_) => continue,
                };
                bus.send(aqua_timestamp_core::events::SseEvent::HealthTick {
                    uptime_secs: started.elapsed().as_secs(),
                    epochs_total,
                    leaves_total,
                });
            }
        });
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
        signer,
        witness_ctx,
        docs_html: rendered_docs_html,
        well_known_skill_md: rendered_skill_md,
        well_known_skill_auth_md: rendered_skill_auth_md,
        event_bus,
    });

    let router = Router::new()
        .route("/health", get(health))
        .route("/version", get(version))
        .route("/favicon.ico", get(favicon_ico))
        .route("/apple-touch-icon.png", get(apple_touch_icon))
        .route("/", get(landing_page))
        .route("/blueprint", get(blueprint_page))
        .route("/docs", get(docs_page))
        .route("/.well-known/aqua-skill.md", get(well_known_skill_md))
        .route(
            "/.well-known/aqua-skill-auth.md",
            get(well_known_skill_auth_md),
        )
        .route("/.well-known/aqua-identity", get(aqua_identity))
        .route("/.well-known/aqua-orl", get(aqua_orl))
        .route("/events", get(sse_events))
        .route("/auth/challenge", get(challenge))
        .route("/auth/session", post(session))
        .route("/v1/leaves", post(submit_leaves))
        .route("/v1/schedule", get(schedule))
        .route("/v1/epochs", get(list_epochs))
        .route("/v1/leaderboard", get(leaderboard))
        .route("/v1/pool/status", get(pool_status))
        .route("/trees", get(list_or_query_trees))
        .route("/trees/{tip_hex}", get(get_tree_by_tip))
        .route("/trees/by-leaf/{leaf_hex}", get(get_tree_by_leaf))
        .fallback(not_found)
        .layer(TraceLayer::new_for_http())
        .with_state(Arc::clone(&state));

    Ok((router, state))
}
