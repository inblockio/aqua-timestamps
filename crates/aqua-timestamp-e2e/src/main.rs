//! Live + selfcheck e2e client for aqua-timestamp (OW1.5).
//!
//! Subcommands:
//!
//! * `live --base-url <URL>`: the main path against a deployed aggregator. The base URL has
//!   no default (a bare run must never reach production) and is printed. Signs in with the ONE
//!   standing secp256k1 identity from `~/.local/state/openwitness-seal-e2e/` (created once,
//!   never rotated), submits the tip of a fresh client tree, waits for the seal, fetches BOTH
//!   witnesses (EVM and qTSA) and has the SDK verifier judge the client tree with both merged
//!   in. 404, a stub or a timeout is a failure. The production host needs
//!   `--allow-production`; that run belongs to OW2 / SP3, not to OW1.
//! * `selfcheck`: the same main path against an in-process aggregator on localhost whose
//!   anchors are the offline test doubles; the reader asks the same doubles (see README).
//! * `selfcheck-all`: `selfcheck` plus ed25519 and p256 clients with ephemeral in-process keys
//!   (those key types have no standing identity and never run against a remote).
//!
//! The verification logic lives in [`witness`] (SDK) and [`flow`]; every subcommand calls the
//! same flow function.

mod flow;
mod identity;
mod selfcheck;
mod witness;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};

use crate::flow::{run_full_flow, FlowOptions, PollBudget, ReaderConfig, SealTrigger};

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
        /// Allow the production host (openwitness.org). Not for OW1: that run is OW2 / SP3.
        #[arg(long)]
        allow_production: bool,
        /// Directory of the standing identity (default ~/.local/state/openwitness-seal-e2e).
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
        /// EVM RPC URL of the reader's chain host (default: the SDK host's own endpoint).
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

/// Refuse the production host unless asked, and any URL that does not parse.
fn check_base_url(raw: &str, allow_production: bool) -> Result<String> {
    let url = reqwest::Url::parse(raw).with_context(|| format!("--base-url {raw:?}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("--base-url must be http or https, got {raw:?}");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("--base-url {raw:?} has no host"))?
        .to_ascii_lowercase();
    let production = host == "openwitness.org" || host.ends_with(".openwitness.org");
    if production && !allow_production {
        bail!(
            "{host} is production: refusing without --allow-production (the live production run \
             belongs to OW2 / SP3, not to OW1)"
        );
    }
    Ok(raw.trim_end_matches('/').to_string())
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
            let dir = match identity_dir {
                Some(d) => d,
                None => identity::default_dir()?,
            };
            let id = identity::load_or_create(&dir)?;
            println!(
                "identity = {} ({}, alias {}, created_at {}){}",
                id.record.did,
                dir.display(),
                id.record.alias,
                id.record.created_at,
                if id.created { "  [CREATED NOW]" } else { "" }
            );
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

fn print_summary(outcome: &crate::flow::E2eOutcome) {
    println!();
    println!("------ e2e summary ------");
    println!("base_url       = {}", outcome.base_url);
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
    fn production_host_needs_the_flag() {
        for url in [
            "https://openwitness.org",
            "https://openwitness.org/",
            "https://OpenWitness.org:443/x",
            "https://api.openwitness.org",
        ] {
            assert!(check_base_url(url, false).is_err(), "{url}");
            assert!(check_base_url(url, true).is_ok(), "{url}");
        }
    }

    #[test]
    fn other_hosts_pass_and_are_normalised() {
        assert_eq!(
            check_base_url("http://127.0.0.1:8080/", false).unwrap(),
            "http://127.0.0.1:8080"
        );
        assert!(check_base_url("https://staging.example.org", false).is_ok());
        assert!(check_base_url("https://notopenwitness.org", false).is_ok());
    }

    #[test]
    fn junk_urls_are_refused() {
        assert!(check_base_url("openwitness.org", true).is_err());
        assert!(check_base_url("ftp://example.org", false).is_err());
    }

    #[test]
    fn live_has_no_default_base_url() {
        // SAFETY of the test: the env var must not leak in from the shell.
        std::env::remove_var("OPENWITNESS_E2E_BASE_URL");
        assert!(Cli::try_parse_from(["e2e", "live"]).is_err());
        assert!(Cli::try_parse_from(["e2e", "live", "--base-url", "http://127.0.0.1:1"]).is_ok());
    }
}
