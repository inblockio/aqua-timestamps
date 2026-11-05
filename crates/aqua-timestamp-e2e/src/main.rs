//! Command line of the aqua-timestamp e2e client; the logic is the library.
//!
//! Subcommands:
//!
//! * `live --base-url <URL>`: the main path against a deployed aggregator. The base URL has
//!   no default (a bare run must never reach production) and is printed. Signs in with the ONE
//!   standing secp256k1 identity from `~/.local/state/openwitness-seal-e2e/` (never rotated, and
//!   on a non-loopback URL never created), submits the tip of a fresh client tree, waits for the
//!   seal, fetches BOTH witnesses (EVM and qTSA) and has the SDK verifier judge the client tree
//!   with both merged in. 404, a stub or a timeout is a failure. The production host needs
//!   `--allow-production`.
//! * `seal --base-url <URL>`: the Set Seal v1 reference e2e, seven steps, every served body
//!   persisted in a run directory; see `aqua_timestamp_e2e::seal`.
//! * `seal-replay <DIR>`: steps 2 to 7 from a run directory. No key, no session, nothing sent to
//!   the aggregator.
//! * `selfcheck`: the same main path against an in-process aggregator on localhost whose
//!   anchors are the offline test doubles; the reader asks the same doubles (see README).
//! * `selfcheck-all`: `selfcheck` plus ed25519 and p256 clients with ephemeral in-process keys
//!   (those key types have no standing identity and never run against a remote).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use aqua_timestamp_e2e::flow::{
    run_full_flow, E2eOutcome, FlowOptions, PollBudget, ReaderConfig, SealTrigger,
};
use aqua_timestamp_e2e::seal::live::{require_server_did_pin, run_seal, SealConfig};
use aqua_timestamp_e2e::seal::log::StepLog;
use aqua_timestamp_e2e::seal::policy::Reader;
use aqua_timestamp_e2e::seal::replay::{run_replay, ReplayConfig};
use aqua_timestamp_e2e::target::check_base_url;
use aqua_timestamp_e2e::{identity, selfcheck};

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
    /// Run the main path against a deployed aggregator. `--base-url` is required.
    Live {
        /// Base URL of the aggregator under test (no default; printed at the start).
        #[arg(long, env = "OPENWITNESS_E2E_BASE_URL")]
        base_url: String,
        /// Allow the production host (openwitness.org).
        #[arg(long)]
        allow_production: bool,
        /// Directory of the standing identity (default ~/.local/state/openwitness-seal-e2e).
        /// A non-loopback --base-url only loads it: a missing identity is refused.
        #[arg(long, env = "OPENWITNESS_E2E_IDENTITY_DIR")]
        identity_dir: Option<PathBuf>,
        /// Seconds to wait for the epoch to seal.
        #[arg(long, default_value_t = 1500)]
        seal_wait_secs: u64,
        /// Seconds, after the seal, to wait for BOTH witnesses (EVM serves at finality).
        #[arg(long, default_value_t = 1200)]
        witness_timeout_secs: u64,
        /// Seconds between polls.
        #[arg(long, default_value_t = 5)]
        poll_interval_secs: u64,
        /// EVM RPC URL of the reader's chain host. Default for a `sepolia` witness:
        /// https://ethereum-sepolia-rpc.publicnode.com; any other network needs this flag.
        #[arg(long, env = "OPENWITNESS_E2E_EVM_RPC_URL")]
        evm_rpc_url: Option<String>,
    },
    /// The Set Seal v1 reference e2e against a deployed aggregator: seven steps, every served
    /// body persisted in a run directory. `--base-url` is required.
    Seal {
        /// Base URL of the aggregator under test (no default; printed at the start).
        #[arg(long, env = "OPENWITNESS_E2E_BASE_URL")]
        base_url: String,
        /// Allow the production host (openwitness.org).
        #[arg(long)]
        allow_production: bool,
        /// Directory of the standing identity (default ~/.local/state/openwitness-seal-e2e).
        /// A non-loopback --base-url only loads it: a missing identity is refused.
        #[arg(long, env = "OPENWITNESS_E2E_IDENTITY_DIR")]
        identity_dir: Option<PathBuf>,
        /// The run directory (default seal-run-<UTC> under the working directory). Never in the
        /// identity directory; a directory that is not empty is refused.
        #[arg(long)]
        run_dir: Option<PathBuf>,
        /// When given, `/version`'s revision must equal this before anything is posted. Without
        /// it any version passes; /version before must equal /version after in any case.
        #[arg(long)]
        expect_version: Option<String>,
        /// The served server_did must equal this before anything is posted, and step 2 asserts
        /// it. Required on a non-loopback --base-url; there is no default.
        #[arg(long)]
        expect_server_did: Option<String>,
        /// Seconds after the epoch's close to wait for its seal.
        #[arg(long, default_value_t = 900)]
        seal_grace_secs: u64,
        /// Seconds after the epoch's close to wait for the witnesses (EVM serves at finality).
        #[arg(long, default_value_t = 1800)]
        witness_grace_secs: u64,
        /// Seconds between polls.
        #[arg(long, default_value_t = 15)]
        poll_interval_secs: u64,
        /// Seconds step 1 retries a witness set whose EVM anchor is not final yet, or whose EVM
        /// host did not answer.
        #[arg(long, default_value_t = 1200)]
        finality_budget_secs: u64,
        /// EVM RPC URL of the reader's chain host. Default:
        /// https://ethereum-sepolia-rpc.publicnode.com.
        #[arg(long, env = "OPENWITNESS_E2E_EVM_RPC_URL")]
        evm_rpc_url: Option<String>,
    },
    /// Steps 2 to 7 from a run directory of `seal`: no key, no session, nothing sent to the
    /// aggregator. The run directory stays untouched.
    SealReplay {
        /// The run directory of a finished `seal` run.
        dir: PathBuf,
        /// Write the step logs and derived files here (default: stdout only, nothing written).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Step 2 asserts the persisted server_did equals this. Required; there is no default.
        #[arg(long)]
        expect_server_did: String,
        /// EVM RPC URL of the reader's chain host. Default:
        /// https://ethereum-sepolia-rpc.publicnode.com.
        #[arg(long, env = "OPENWITNESS_E2E_EVM_RPC_URL")]
        evm_rpc_url: Option<String>,
    },
    /// Run the main path against an in-process aggregator on localhost (offline test doubles).
    Selfcheck {
        /// Identity directory to use (default: a throwaway temporary directory).
        #[arg(long)]
        identity_dir: Option<PathBuf>,
    },
    /// `selfcheck` for secp256k1, then ed25519 and p256 with ephemeral in-process keys.
    SelfcheckAll {
        #[arg(long)]
        identity_dir: Option<PathBuf>,
    },
}

fn print_step(n: usize, msg: &str) {
    println!("[step {n}] OK   {msg}");
}

fn identity_dir_or_default(given: Option<PathBuf>) -> Result<PathBuf> {
    match given {
        Some(d) => Ok(d),
        None => identity::default_dir(),
    }
}

fn print_identity(id: &identity::StandingIdentity, dir: &Path) {
    println!(
        "identity = {} ({}, alias {}, created_at {}){}",
        id.record.did,
        dir.display(),
        id.record.alias,
        id.record.created_at,
        if id.created { "  [CREATED NOW]" } else { "" }
    );
}

/// One PASS or FAIL per step and one for the run. A failed step is a failed exit.
fn finish_steps(what: &str, logs: &[StepLog], passed: bool) -> Result<()> {
    println!();
    for log in logs {
        println!("{}", log.verdict());
    }
    if passed {
        println!("{what} PASS");
        Ok(())
    } else {
        println!("{what} FAIL");
        bail!("{what} failed");
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Live {
            base_url,
            allow_production,
            identity_dir,
            seal_wait_secs,
            witness_timeout_secs,
            poll_interval_secs,
            evm_rpc_url,
        } => {
            let base_url = check_base_url(&base_url, allow_production)?;
            println!("aqua-timestamp e2e :: live");
            println!("base_url = {base_url}");
            let dir = identity_dir_or_default(identity_dir)?;
            let id = identity::for_base_url(&base_url, &dir)?;
            print_identity(&id, &dir);
            let key = id.client_key()?;
            let interval = Duration::from_secs(poll_interval_secs.max(1));
            let opts = FlowOptions {
                seal_wait: PollBudget {
                    deadline: Instant::now() + Duration::from_secs(seal_wait_secs),
                    interval,
                },
                witness_timeout: Duration::from_secs(witness_timeout_secs),
                witness_interval: interval,
                foreign_did_negative: false,
                reader: ReaderConfig::Live { evm_rpc_url },
            };
            let outcome = run_full_flow(&base_url, &key, SealTrigger::None, &opts, &print_step)
                .await
                .context("live flow failed")?;
            print_summary(&outcome);
            Ok(())
        }
        Cmd::Seal {
            base_url,
            allow_production,
            identity_dir,
            run_dir,
            expect_version,
            expect_server_did,
            seal_grace_secs,
            witness_grace_secs,
            poll_interval_secs,
            finality_budget_secs,
            evm_rpc_url,
        } => {
            let base_url = check_base_url(&base_url, allow_production)?;
            require_server_did_pin(&base_url, expect_server_did.as_deref())?;
            println!("aqua-timestamp e2e :: seal");
            println!("base_url = {base_url}");
            let dir = identity_dir_or_default(identity_dir)?;
            let id = identity::for_base_url(&base_url, &dir)?;
            print_identity(&id, &dir);
            let run_dir = run_dir.unwrap_or_else(|| {
                let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
                PathBuf::from(format!("seal-run-{stamp}"))
            });
            let report = run_seal(
                SealConfig {
                    base_url,
                    run_dir,
                    identity_dir: dir,
                    reader: Reader::live(evm_rpc_url)?,
                    seal_trigger: SealTrigger::None,
                    expect_version,
                    expect_server_did,
                    seal_grace: Duration::from_secs(seal_grace_secs),
                    witness_grace: Duration::from_secs(witness_grace_secs),
                    poll_interval: Duration::from_secs(poll_interval_secs.max(1)),
                    finality_budget: Duration::from_secs(finality_budget_secs),
                },
                &id,
            )
            .await?;
            println!("run directory = {}", report.run_dir.display());
            println!("server /version before = {}", report.version_before);
            println!("server /version after  = {}", report.version_after);
            finish_steps("SEAL RUN", &report.logs, report.passed())
        }
        Cmd::SealReplay {
            dir,
            out,
            expect_server_did,
            evm_rpc_url,
        } => {
            println!("aqua-timestamp e2e :: seal-replay {}", dir.display());
            let report = run_replay(ReplayConfig {
                run_dir: dir,
                out,
                reader: Reader::live(evm_rpc_url)?,
                expect_server_did,
            })
            .await?;
            finish_steps("SEAL REPLAY", &report.logs, report.passed())
        }
        Cmd::Selfcheck { identity_dir } => {
            println!("aqua-timestamp e2e :: selfcheck (in-process aggregator, offline doubles)");
            let outcome = selfcheck::run(&print_step, identity_dir.as_deref()).await?;
            print_summary(&outcome);
            Ok(())
        }
        Cmd::SelfcheckAll { identity_dir } => {
            println!("aqua-timestamp e2e :: selfcheck-all (secp256k1 + ed25519 + p256)");
            let outcomes = selfcheck::run_all_methods(&print_step, identity_dir.as_deref()).await?;
            println!();
            println!("====== selfcheck-all summary ======");
            for (method, outcome) in &outcomes {
                println!(
                    "[{}] STATUS=OK  client_did={}  epoch={}  anchors={}",
                    method.label(),
                    outcome.client_did,
                    outcome.epoch_id,
                    outcome
                        .witnesses
                        .iter()
                        .map(|w| w.method.as_str())
                        .collect::<Vec<_>>()
                        .join("+"),
                );
            }
            assert_eq!(outcomes.len(), 3, "expected one outcome per DID method");
            println!("OVERALL = OK ({} methods)", outcomes.len());
            Ok(())
        }
    }
}

fn print_summary(outcome: &E2eOutcome) {
    println!();
    println!("------ e2e summary ------");
    println!("base_url       = {}", outcome.base_url);
    println!("server_rev     = {}", outcome.server_revision);
    println!("server_did     = {}", outcome.server_did);
    println!("client_did     = {}", outcome.client_did);
    println!("epoch_id       = {}", outcome.epoch_id);
    println!("leaf           = {}", outcome.leaf_hex);
    for w in &outcome.witnesses {
        println!(
            "[{}] merkle_root={} timestamp_revision={} signature_revision={}",
            w.method.as_str(),
            w.merkle_root_hex,
            w.timestamp_revision,
            w.signature_revision
        );
        println!(
            "[{}] sdk anchor verdict = {}",
            w.method.as_str(),
            w.anchor_verdict
        );
    }
    println!("STATUS         = OK");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_has_no_default_base_url() {
        // SAFETY of the test: the env var must not leak in from the shell.
        std::env::remove_var("OPENWITNESS_E2E_BASE_URL");
        assert!(Cli::try_parse_from(["e2e", "live"]).is_err());
        assert!(Cli::try_parse_from(["e2e", "live", "--base-url", "http://127.0.0.1:1"]).is_ok());
    }

    #[test]
    fn seal_has_no_default_base_url_and_replay_takes_no_identity() {
        std::env::remove_var("OPENWITNESS_E2E_BASE_URL");
        assert!(Cli::try_parse_from(["e2e", "seal"]).is_err());
        assert!(Cli::try_parse_from(["e2e", "seal", "--base-url", "http://127.0.0.1:1"]).is_ok());
        let replay = ["e2e", "seal-replay", "d", "--expect-server-did", "did:x"];
        assert!(Cli::try_parse_from(["e2e", "seal-replay", "d"]).is_err());
        assert!(Cli::try_parse_from(replay).is_ok());
        assert!(Cli::try_parse_from([&replay[..], &["--identity-dir", "x"]].concat()).is_err());
        assert!(Cli::try_parse_from([&replay[..], &["--base-url", "x"]].concat()).is_err());
    }
}
