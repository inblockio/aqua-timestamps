//! Live + selfcheck e2e client for aqua-timestamp.
//!
//! Two subcommands:
//!
//! * `live`: runs the full M-E2E flow against `BASE_URL`
//!   (default `https://timestamp.inblock.io`). Reads the test client
//!   BIP39 mnemonic from `AQUA_TIMESTAMP_TEST_CLIENT_MNEMONIC`. Exits 0
//!   on full success; nonzero on any failure (with a clear per-step
//!   error).
//! * `selfcheck`: spins up an in-process server (mirroring
//!   `crates/aqua-timestamp/tests/witness_flow.rs`) on a free localhost
//!   port, drives the same flow against it using a fast
//!   `SealDriver::Channel` so seals are deterministic. This is what
//!   `cargo test selfcheck` exercises in `tests/selfcheck.rs`.
//!
//! The verification logic lives in [`flow`]; both subcommands call the
//! same function so any regression in the verifier surfaces in both.

mod flow;
mod selfcheck;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};

use crate::flow::{run_full_flow, ClientKey, PollBudget, SealTrigger, SignatureMethod};

/// Public env var the shell wrapper exports before launching the binary.
const ENV_TEST_CLIENT_MNEMONIC: &str = "AQUA_TIMESTAMP_TEST_CLIENT_MNEMONIC";

#[derive(Debug, Parser)]
#[command(
    name = "aqua-timestamp-e2e",
    about = "Live + selfcheck end-to-end test client for the aqua-timestamp aggregator."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Run the live M-E2E flow against `BASE_URL`. Reads the test client
    /// mnemonic from `AQUA_TIMESTAMP_TEST_CLIENT_MNEMONIC`. Default
    /// `BASE_URL` is `https://timestamp.inblock.io`.
    Live {
        /// Override base URL.
        #[arg(long, env = "BASE_URL", default_value = "https://timestamp.inblock.io")]
        base_url: String,
        /// Maximum wall-clock seconds to wait for the epoch to seal,
        /// independent of the server's reported `epoch_closes_at`.
        #[arg(long, default_value_t = 1500)]
        max_wait_secs: u64,
    },
    /// Run the live flow three times, once per DID method that
    /// `aqua-rs-auth` supports (secp256k1+EIP-191, Ed25519, P-256). The
    /// secp256k1 run uses the keyring-stored test mnemonic; the other two
    /// use fresh random keypairs generated in-process. Each run uses its
    /// own epoch, so this command takes up to `3 * 600s` against a 600s
    /// production epoch. Exits 0 only if all three runs succeed.
    LiveAll {
        #[arg(long, env = "BASE_URL", default_value = "https://timestamp.inblock.io")]
        base_url: String,
        #[arg(long, default_value_t = 1500)]
        max_wait_secs: u64,
    },
    /// Run the same flow against an in-process server. Used by
    /// `cargo test --test selfcheck`.
    Selfcheck,
    /// Run the in-process flow three times, once per DID method
    /// (secp256k1+EIP-191, Ed25519, P-256). Used by
    /// `cargo test --test multi_method`.
    SelfcheckAll,
}

fn print_step(n: usize, msg: &str) {
    println!("[step {n}] OK   {msg}");
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Live {
            base_url,
            max_wait_secs,
        } => {
            let key = secp256k1_client_from_env().await?;
            println!("aqua-timestamp e2e :: live");
            println!("base_url = {base_url}");
            let budget = make_budget(max_wait_secs);
            let outcome = run_full_flow(&base_url, &key, SealTrigger::None, budget, &print_step)
                .await
                .context("live flow failed")?;
            print_summary(&outcome);
            Ok(())
        }
        Cmd::LiveAll {
            base_url,
            max_wait_secs,
        } => {
            println!("aqua-timestamp e2e :: live-all (secp256k1 + ed25519 + p256)");
            println!("base_url = {base_url}");

            let keys: Vec<(SignatureMethod, ClientKey)> = vec![
                (
                    SignatureMethod::Secp256k1Eip191,
                    secp256k1_client_from_env().await?,
                ),
                (
                    SignatureMethod::Ed25519,
                    ClientKey::random(SignatureMethod::Ed25519)?,
                ),
                (
                    SignatureMethod::P256,
                    ClientKey::random(SignatureMethod::P256)?,
                ),
            ];

            let mut summaries: Vec<(SignatureMethod, crate::flow::E2eOutcome)> = Vec::new();
            let mut failures: Vec<(SignatureMethod, anyhow::Error)> = Vec::new();
            for (method, key) in keys {
                println!();
                println!("===== method = {} =====", method.label());
                let budget = make_budget(max_wait_secs);
                let labelled = move |n: usize, msg: &str| {
                    println!("[{} step {n}] OK   {msg}", method.label());
                };
                match run_full_flow(&base_url, &key, SealTrigger::None, budget, &labelled).await {
                    Ok(o) => summaries.push((method, o)),
                    Err(e) => {
                        eprintln!("[{} FAIL] {e:#}", method.label());
                        failures.push((method, e));
                    }
                }
            }

            println!();
            println!("====== live-all summary ======");
            for (method, outcome) in &summaries {
                println!(
                    "[{}] STATUS=OK  client_did={}",
                    method.label(),
                    outcome.client_did
                );
                println!(
                    "    leaf={}  epoch={}  tx_anchor={}",
                    outcome.leaf_hex, outcome.epoch_id, outcome.merkle_root_hex
                );
            }
            for (method, err) in &failures {
                println!("[{}] STATUS=FAIL {err}", method.label());
            }
            if failures.is_empty() {
                println!("OVERALL = OK ({} methods)", summaries.len());
                Ok(())
            } else {
                Err(anyhow!(
                    "{} of {} methods failed",
                    failures.len(),
                    summaries.len() + failures.len()
                ))
            }
        }
        Cmd::Selfcheck => {
            println!("aqua-timestamp e2e :: selfcheck");
            let outcome = selfcheck::run(&print_step).await?;
            print_summary(&outcome);
            Ok(())
        }
        Cmd::SelfcheckAll => {
            println!("aqua-timestamp e2e :: selfcheck-all (secp256k1 + ed25519 + p256)");
            let outcomes = selfcheck::run_all_methods(&print_step).await?;
            println!();
            println!("====== selfcheck-all summary ======");
            for (method, outcome) in &outcomes {
                println!(
                    "[{}] STATUS=OK  client_did={}  epoch={}  root={}",
                    method.label(),
                    outcome.client_did,
                    outcome.epoch_id,
                    outcome.merkle_root_hex,
                );
            }
            assert_eq!(outcomes.len(), 3, "expected one outcome per DID method");
            println!("OVERALL = OK ({} methods)", outcomes.len());
            Ok(())
        }
    }
}

fn make_budget(max_wait_secs: u64) -> PollBudget {
    PollBudget {
        deadline: std::time::Instant::now() + std::time::Duration::from_secs(max_wait_secs),
        interval: std::time::Duration::from_secs(5),
    }
}

async fn secp256k1_client_from_env() -> Result<ClientKey> {
    let mnemonic = std::env::var(ENV_TEST_CLIENT_MNEMONIC).with_context(|| {
        format!(
            "{ENV_TEST_CLIENT_MNEMONIC} not set; the wrapper script should look it up from the keyring"
        )
    })?;
    let mnemonic = mnemonic.trim();
    if mnemonic.is_empty() {
        return Err(anyhow!(
            "{ENV_TEST_CLIENT_MNEMONIC} is empty; keyring lookup likely returned nothing"
        ));
    }
    ClientKey::from_mnemonic(mnemonic).await
}

fn print_summary(outcome: &crate::flow::E2eOutcome) {
    println!();
    println!("------ e2e summary ------");
    println!("base_url       = {}", outcome.base_url);
    println!("server_did     = {}", outcome.server_did);
    println!("client_did     = {}", outcome.client_did);
    println!("epoch_id       = {}", outcome.epoch_id);
    println!("leaf           = {}", outcome.leaf_hex);
    println!("merkle_root    = {}", outcome.merkle_root_hex);
    println!("object_hash    = {}", outcome.object_hash_hex);
    println!("signature_hash = {}", outcome.signature_hash_hex);
    println!("signer_recover = {}", outcome.recovered_signer_address);
    println!("STATUS         = OK");
}
