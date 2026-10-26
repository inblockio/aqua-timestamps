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
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use aqua_rs_sdk::schema::timestamp::TimestampValue;
use aqua_timestamp::{
    build_app_with_anchors,
    config::{
        AnchorConfig, AnchorsConfig, AuthConfig, BondingCurveConfig, Config, EpochConfig,
        EvmAnchorConfig, IdentityConfig, LeaderboardConfig, QtsaAnchorConfig, ServerConfig,
        StorageConfig,
    },
    identity::{IdentityClaimOverrides, ServiceIdentity},
    AnchorOverrides, SealDriver,
};
use aqua_timestamp_core::sealer::SealTick;
use aqua_timestamp_core::selfcheck::doubles::{SimChain, SimTsa};
use tempfile::TempDir;
use tokio::sync::mpsc;

use crate::flow::{
    run_full_flow, ClientKey, E2eOutcome, FlowOptions, PollBudget, ReaderConfig, SealTrigger,
    StepLogger,
};
use crate::identity;
use crate::witness::ReaderHosts;

/// The same Hardhat / Foundry default mnemonic used in
/// `crates/aqua-timestamp/tests/witness_flow.rs` for the service identity.
/// Its 12 words are public and tied to addresses the SDK has wired up for
/// determinism, never used in production.
const SERVICE_MNEMONIC: &str = "test test test test test test test test test test test junk";

/// The secp256k1 client of an in-process run: the standing-identity loader on `identity_dir`
/// (a throwaway temporary directory when none is given; never the standing directory unless
/// the caller names it).
async fn secp256k1_client(identity_dir: Option<&Path>) -> Result<(ClientKey, Option<TempDir>)> {
    match identity_dir {
        Some(d) => Ok((identity::load_or_create(d)?.client_key()?, None)),
        None => {
            let t = tempfile::tempdir().context("identity tempdir")?;
            let key = identity::load_or_create(&t.path().join("identity"))?.client_key()?;
            Ok((key, Some(t)))
        }
    }
}

pub async fn run(log: StepLogger<'_>, identity_dir: Option<&Path>) -> Result<E2eOutcome> {
    run_with_reader(log, identity_dir, None).await
}

/// `run`, optionally with other reader hosts than the aggregator's own doubles (the negative
/// tests: a reader that does not know the anchors must fail the run).
async fn run_with_reader(
    log: StepLogger<'_>,
    identity_dir: Option<&Path>,
    reader: Option<ReaderHosts>,
) -> Result<E2eOutcome> {
    let tmp = tempfile::tempdir().context("tempdir")?;
    let (primary, _identity_tmp) = secp256k1_client(identity_dir).await?;

    // Bind to an ephemeral port first so we know the URL before the app
    // starts serving. axum::serve takes a `TcpListener` directly.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind ephemeral")?;
    let addr: SocketAddr = listener.local_addr().context("local_addr")?;
    let base_url = format!("http://{addr}");

    let (router, _state, seal_tx, _tmp_keep, hosts) = build_in_process(tmp).await?;

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
    let opts = options(reader.unwrap_or(hosts));

    let outcome_result = run_full_flow(&base_url, &primary, seal_trigger, &opts, log).await;

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
    identity_dir: Option<&Path>,
) -> Result<Vec<(crate::flow::SignatureMethod, E2eOutcome)>> {
    use crate::flow::SignatureMethod;
    let tmp = tempfile::tempdir().context("tempdir")?;
    let (secp_key, _identity_tmp) = secp256k1_client(identity_dir).await?;
    let mut secp_key = Some(secp_key);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind ephemeral")?;
    let addr: SocketAddr = listener.local_addr().context("local_addr")?;
    let base_url = format!("http://{addr}");

    let (router, _state, seal_tx, _tmp_keep, hosts) = build_in_process(tmp).await?;
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
            SignatureMethod::Secp256k1Eip191 => secp_key.take().expect("one secp256k1 pass"),
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
        let opts = options(hosts.clone());
        match run_full_flow(&base_url, &key, trigger, &opts, log).await {
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

/// In-process: the seal fires on demand and the doubles answer at once, so waits are short.
fn options(hosts: ReaderHosts) -> FlowOptions {
    FlowOptions {
        seal_wait: PollBudget::fast(15),
        witness_timeout: std::time::Duration::from_secs(15),
        witness_interval: std::time::Duration::from_millis(50),
        foreign_did_negative: true,
        reader: ReaderConfig::Injected(hosts),
    }
}

async fn build_in_process(
    tmp: TempDir,
) -> Result<(
    axum::Router,
    Arc<aqua_timestamp::state::AppState>,
    mpsc::Sender<SealTick>,
    TempDir,
    ReaderHosts,
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
        // Both methods enabled (D51: a disabled method mints nothing); the
        // providers are injected offline stand-ins (`offline_anchors`).
        anchors: AnchorsConfig {
            evm: EvmAnchorConfig::default(),
            qtsa: QtsaAnchorConfig::default(),
        },
        bonding_curve: BondingCurveConfig::default(),
        leaderboard: LeaderboardConfig::default(),
    };

    let identity = ServiceIdentity::from_mnemonic(SERVICE_MNEMONIC, &cfg.identity)
        .await
        .context("ServiceIdentity::from_mnemonic")?;

    let (seal_tx, seal_rx) = mpsc::channel::<SealTick>(8);
    let (anchors, hosts) = offline_anchors();
    let (router, state) = build_app_with_anchors(
        cfg,
        identity,
        IdentityClaimOverrides::default(),
        SealDriver::Channel(seal_rx),
        anchors,
    )
    .await
    .context("build_app")?;

    Ok((router, state, seal_tx, tmp, hosts))
}

/// Offline anchor providers for the in-process selfcheck: fixed anchor facts,
/// no RPC and no TSA. The selfcheck checks the server's flow (revision
/// rehash, batch inclusion, service signature), not an anchor; these
/// witnesses do not verify against a chain or a TSA. Never used by the
/// server binary.
fn offline_anchors() -> (AnchorOverrides, ReaderHosts) {
    let fact = |sender: &str, provider: &str, tx: String, contract: &str, network: &str| {
        TimestampValue::new(
            vec![],
            sender.to_string(),
            provider.to_string(),
            tx,
            contract.to_string(),
            network.to_string(),
            String::new(),
            1_000,
            1,
            0,
            String::new(),
        )
    };
    // OW1.4: each simulated anchor is also the host the pre-serve self-check
    // judges it by.
    let chain = Arc::new(SimChain::new(fact(
        "0xCAFE000000000000000000000000000000000000",
        "",
        format!("0x{}", "ab".repeat(32)),
        "0xDEAD000000000000000000000000000000000000",
        "sepolia",
    )));
    let tsa = Arc::new(SimTsa::new(fact(
        "",
        "Offline Selfcheck TSA",
        "AAAA".into(),
        "http://tsa.test/",
        "tsa",
    )));
    // The reader of the dry run asks the same simulated chain and TSA the server's pre-serve
    // self-check asks (a real chain or TSA would not know these anchors).
    let hosts = ReaderHosts {
        blockchain: chain.clone(),
        web: tsa.clone(),
        tsa_facts_expected: false,
    };
    (
        AnchorOverrides {
            evm: Some(chain.clone()),
            qtsa: Some(tsa.clone()),
            evm_check_host: Some(chain),
            tsa_check_host: Some(tsa),
        },
        hosts,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use aqua_rs_sdk::schema::timestamp::TimestampValue;
    use aqua_timestamp_core::selfcheck::doubles::{SimChain, SimTsa};

    fn blank() -> TimestampValue {
        TimestampValue::new(
            vec![],
            String::new(),
            String::new(),
            "x".into(),
            String::new(),
            "sepolia".into(),
            String::new(),
            1_000,
            1,
            0,
            String::new(),
        )
    }

    async fn run_quiet(reader: Option<ReaderHosts>) -> Result<E2eOutcome> {
        run_with_reader(&|_, _| {}, None, reader).await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_dry_run_passes_with_the_aggregators_own_hosts() {
        let o = run_quiet(None).await.expect("dry run");
        assert_eq!(o.witnesses.len(), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_reader_whose_tsa_did_not_issue_the_token_fails_the_run() {
        // The chain half of the reader stays the aggregator's; only the TSA is a stranger.
        let (_, hosts) = offline_anchors();
        let stranger = ReaderHosts {
            web: Arc::new(SimTsa::new(blank())),
            ..hosts
        };
        let err = run_quiet(Some(stranger)).await.expect_err("must fail");
        assert!(
            format!("{err:#}").to_lowercase().contains("tsa"),
            "the failure names the TSA: {err:#}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_reader_whose_chain_does_not_know_the_transaction_fails_the_run() {
        let (_, hosts) = offline_anchors();
        let stranger = ReaderHosts {
            blockchain: Arc::new(SimChain::new(blank())),
            ..hosts
        };
        let err = run_quiet(Some(stranger)).await.expect_err("must fail");
        assert!(
            format!("{err:#}").to_lowercase().contains("evm"),
            "the failure names the EVM anchor: {err:#}"
        );
    }
}
