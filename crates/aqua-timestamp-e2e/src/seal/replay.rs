//! `seal-replay <dir>`: steps 2 to 7 from a run directory alone. It loads no signing key, opens
//! no session and sends nothing to the aggregator; a test in [`super`] holds this module and the
//! ones it reads to that. The persisted run stays untouched: what a step derives is compared
//! with the persisted bytes and goes only to `--out`, if given.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;

use super::log::{all_passed, StepLog};
use super::policy::Reader;
use super::run_dir::{ensure_outside, verify_complete, RunState, Store, StoreMode};
use super::sdk_rev;
use super::steps::{self, Ctx, Steps};

pub struct ReplayConfig {
    pub run_dir: PathBuf,
    /// Where step logs and derived files go. `None` writes nothing, anywhere.
    pub out: Option<PathBuf>,
    pub reader: Reader,
    /// What step 2 compares the persisted server DID with. Required: a replay has no other pin.
    pub expect_server_did: String,
}

pub struct ReplayReport {
    pub logs: Vec<StepLog>,
}

impl ReplayReport {
    pub fn passed(&self) -> bool {
        all_passed(&self.logs)
    }
}

/// Replay the run directory. A missing or malformed file is a named error before any step runs.
pub async fn run_replay(cfg: ReplayConfig) -> Result<ReplayReport> {
    if let Some(out) = &cfg.out {
        ensure_outside(out, &cfg.run_dir, "--out", "the run directory")?;
    }
    verify_complete(&cfg.run_dir)?;
    let state = RunState::load(&cfg.run_dir, &cfg.reader.aq).await?;
    let header = vec![
        format!(
            "# mode = replay of {}: no key, no session, nothing sent to the aggregator; reads are the persisted bodies and the EVM host's chain reads",
            cfg.run_dir.display()
        ),
        format!("# SDK rev of this binary (Cargo.lock) = {}", sdk_rev()?),
        format!("# SDK rev of the run (run.json) = {}", state.meta["sdk_rev"]),
        format!(
            "# server /version recorded by the run: {}",
            state.meta["server_version_before"]
        ),
    ];
    println!("step 1 is not replayed: it built the container the replay re-reads");
    let ctx = Ctx {
        store: Store::new(
            &cfg.run_dir,
            StoreMode::Replay {
                out: cfg.out.clone(),
            },
        ),
        reader: cfg.reader,
        state,
        header,
        expect_server_did: Some(cfg.expect_server_did),
        finality_budget: Duration::ZERO,
    };
    let logs = steps::run(&ctx, Steps::FromPersisted, "replay").await?;
    Ok(ReplayReport { logs })
}
