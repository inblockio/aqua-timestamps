//! In-process selfcheck: boot a `build_app` server on a free port, drive
//! the same M-E2E flow against it, and tear it down.
//!
//! The selfcheck has two jobs:
//!
//! 1. Catch regressions in the verifier logic in [`crate::flow`] without
//!    needing a deployed instance (`cargo test selfcheck`).
//! 2. Make the binary self-contained: `cargo run --bin aqua-timestamp-e2e
//!    -- selfcheck` runs a complete end-to-end loop with zero external
//!    dependencies. Useful as a smoke test on a fresh checkout.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use aqua_timestamp::{
    build_app,
    config::{
        AnchorConfig, AnchorsConfig, AuthConfig, Config, EpochConfig, EvmAnchorConfig,
        IdentityConfig, ServerConfig, StorageConfig,
    },
    identity::{IdentityClaimOverrides, ServiceIdentity},
    SealDriver,
};
use aqua_timestamp_core::sealer::SealTick;
use tempfile::TempDir;
use tokio::sync::mpsc;

use crate::flow::{run_full_flow, ClientKey, E2eOutcome, PollBudget, SealTrigger, StepLogger};

/// The same Hardhat / Foundry default mnemonic used in
/// `crates/aqua-timestamp/tests/witness_flow.rs` for the service identity.
/// Its 12 words are public and tied to addresses the SDK has wired up for
/// determinism, never used in production.
const SERVICE_MNEMONIC: &str = "test test test test test test test test test test test junk";

/// Distinct BIP39 mnemonic for the selfcheck *client* (not derivable from
/// SERVICE_MNEMONIC's first account, so the client DID is genuinely
/// different from the server identity). Also a public test vector.
const TEST_CLIENT_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

pub async fn run(log: StepLogger<'_>) -> Result<E2eOutcome> {
    let tmp = tempfile::tempdir().context("tempdir")?;

    // Bind to an ephemeral port first so we know the URL before the app
    // starts serving. axum::serve takes a `TcpListener` directly.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind ephemeral")?;
    let addr: SocketAddr = listener.local_addr().context("local_addr")?;
    let base_url = format!("http://{addr}");

    let (router, _state, seal_tx, _tmp_keep) = build_in_process(tmp).await?;

    // Spin up the server task. We swallow its return value; the test
    // tears it down via `abort()` once the flow completes.
    let server_handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router.into_make_service()).await;
    });

    let seal_tx_inner = seal_tx.clone();
    let seal_trigger = SealTrigger::Driver(Box::new(move || {
        let tx = seal_tx_inner.clone();
        Box::pin(async move {
            // Best-effort: if the receiver was dropped (shouldn't happen
            // mid-flow), swallow the error rather than panicking the
            // selfcheck.
            let _ = tx.send(SealTick { now: 1_700_000_000 }).await;
            // Yield enough times for the seal task to drain and persist
            // before the flow polls /v1/schedule. Matches the witness_flow
            // tests' 40-yield drain.
            for _ in 0..40 {
                tokio::task::yield_now().await;
            }
        }) as crate::flow::SealTriggerFuture
    }));

    // In-process: seal fires on demand, so a short budget is fine.
    let budget = PollBudget::fast(15);

    let primary = ClientKey::from_mnemonic(TEST_CLIENT_MNEMONIC)
        .await
        .context("derive selfcheck client key")?;
    let outcome_result = run_full_flow(&base_url, &primary, seal_trigger, budget, log).await;

    server_handle.abort();
    let _ = server_handle.await;
    drop(seal_tx);

    outcome_result
}

/// Multi-method variant: spins up one in-process server, then runs the
/// full flow three times against it, once per [`SignatureMethod`]. Each
/// pass uses a freshly-generated random keypair for that method. Returns
/// one outcome per method on success; surfaces the first failure.
pub async fn run_all_methods(
    log: StepLogger<'_>,
) -> Result<Vec<(crate::flow::SignatureMethod, E2eOutcome)>> {
    use crate::flow::SignatureMethod;
    let tmp = tempfile::tempdir().context("tempdir")?;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind ephemeral")?;
    let addr: SocketAddr = listener.local_addr().context("local_addr")?;
    let base_url = format!("http://{addr}");

    let (router, _state, seal_tx, _tmp_keep) = build_in_process(tmp).await?;
    let server_handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router.into_make_service()).await;
    });

    let methods = [
        SignatureMethod::Secp256k1Eip191,
        SignatureMethod::Ed25519,
        SignatureMethod::P256,
    ];

    let mut outcomes = Vec::with_capacity(methods.len());
    let mut first_error: Option<anyhow::Error> = None;

    for method in methods {
        let key = match method {
            SignatureMethod::Secp256k1Eip191 => ClientKey::from_mnemonic(TEST_CLIENT_MNEMONIC)
                .await
                .context("selfcheck secp256k1 client")?,
            _ => ClientKey::random(method).context("selfcheck random client")?,
        };
        let trigger_tx = seal_tx.clone();
        let trigger = SealTrigger::Driver(Box::new(move || {
            let tx = trigger_tx.clone();
            Box::pin(async move {
                let _ = tx.send(SealTick { now: 1_700_000_000 }).await;
                for _ in 0..40 {
                    tokio::task::yield_now().await;
                }
            }) as crate::flow::SealTriggerFuture
        }));
        let budget = PollBudget::fast(15);
        match run_full_flow(&base_url, &key, trigger, budget, log).await {
            Ok(o) => outcomes.push((method, o)),
            Err(e) => {
                first_error = Some(e.context(format!("method {} failed", method.label())));
                break;
            }
        }
    }

    server_handle.abort();
    let _ = server_handle.await;
    drop(seal_tx);

    if let Some(e) = first_error {
        return Err(e);
    }
    Ok(outcomes)
}

async fn build_in_process(
    tmp: TempDir,
) -> Result<(
    axum::Router,
    Arc<aqua_timestamp::state::AppState>,
    mpsc::Sender<SealTick>,
    TempDir,
)> {
    let cfg = Config {
        server: ServerConfig {
            listen: "127.0.0.1:0".into(),
        },
        identity: IdentityConfig {
            chain_id: 1,
            trust_domain: "timestamp".into(),
            dns: "timestamp.test".into(),
            ip: "127.0.0.1".into(),
        },
        auth: AuthConfig {
            challenge_ttl_secs: 60,
            // Long enough that two SIWE handshakes (primary + secondary
            // negative-test client) both stay valid through the polling
            // window.
            session_ttl_secs: 600,
            // Empty allowlist == open allowlist (matches the deployed
            // server's config; see crates/aqua-timestamp/src/state.rs).
            allowed_dids: vec![],
        },
        storage: StorageConfig {
            path: tmp.path().to_path_buf(),
        },
        epoch: EpochConfig {
            duration_secs: 60,
            max_leaves_per_request: 10_000,
        },
        anchor_legacy: AnchorConfig::default(),
        anchors: AnchorsConfig {
            evm: EvmAnchorConfig {
                enabled: false,
                ..EvmAnchorConfig::default()
            },
        },
    };

    let identity = ServiceIdentity::from_mnemonic(SERVICE_MNEMONIC, &cfg.identity)
        .await
        .context("ServiceIdentity::from_mnemonic")?;

    let (seal_tx, seal_rx) = mpsc::channel::<SealTick>(8);
    let (router, state) = build_app(
        cfg,
        identity,
        IdentityClaimOverrides::default(),
        SealDriver::Channel(seal_rx),
    )
    .await
    .context("build_app")?;

    Ok((router, state, seal_tx, tmp))
}
