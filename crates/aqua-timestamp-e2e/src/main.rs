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

use crate::flow::{run_full_flow, PollBudget, SealTrigger};

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
    /// Run the same flow against an in-process server. Used by
    /// `cargo test --test selfcheck`.
    Selfcheck,
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

            println!("aqua-timestamp e2e :: live");
            println!("base_url = {base_url}");

            let budget = PollBudget {
                deadline: std::time::Instant::now() + std::time::Duration::from_secs(max_wait_secs),
                interval: std::time::Duration::from_secs(5),
            };

            let outcome =
                run_full_flow(&base_url, mnemonic, SealTrigger::None, budget, &print_step)
                    .await
                    .context("live flow failed")?;
            print_summary(&outcome);
            Ok(())
        }
        Cmd::Selfcheck => {
            println!("aqua-timestamp e2e :: selfcheck");
            let outcome = selfcheck::run(&print_step).await?;
            print_summary(&outcome);
            Ok(())
        }
    }
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
