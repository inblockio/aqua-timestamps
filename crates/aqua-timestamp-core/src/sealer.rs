//! Epoch sealing task: closes the current epoch, builds its Merkle root,
//! and persists the `EpochRecord`, its leaf set, AND every per-leaf
//! witness revision pair (M3).
//!
//! Production uses [`run_sealer_with_interval`], which ticks
//! `epoch_duration_secs` on the tokio runtime clock. Tests use
//! [`run_sealer_with_channel`], which seals once per message on the
//! supplied [`SealTick`] channel; this keeps tests deterministic without
//! needing `tokio::time::advance`.

use std::sync::Arc;
use std::time::Duration;

use aqua_rs_sdk::Secp256k1Signer;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::accumulator::{Accumulator, SealedSnapshot};
use crate::epoch::{EpochRecord, HASH_TYPE_LABEL};
use crate::merkle::{merkle_root_for_leaves, Hash32};
use crate::storage::{Store, StoreError};
use crate::time::Clock;
use crate::witness::{mint_witnesses_for_epoch, AnchorMethod, MintedWitness, WitnessError};

/// Per-process configuration the sealer needs in addition to its
/// already-required `(accumulator, store, clock, duration)` quad: which
/// methods to mint and what static labels to put in the witness payloads.
///
/// Cloned cheaply (only owned strings + an `Arc` to the signer).
#[derive(Clone)]
pub struct WitnessContext {
    pub signer: Arc<Secp256k1Signer>,
    /// EIP-55 ethereum address of the service key, prefixed with `0x`.
    pub service_eth_address: String,
    /// Network name written into the EVM witness payload (e.g. `"sepolia"`).
    pub evm_network: String,
    /// Methods to mint per leaf. Production uses both; tests can mint one.
    pub methods: Vec<AnchorMethod>,
}

impl WitnessContext {
    pub fn new(
        signer: Arc<Secp256k1Signer>,
        service_eth_address: String,
        evm_network: String,
        methods: Vec<AnchorMethod>,
    ) -> Self {
        Self {
            signer,
            service_eth_address,
            evm_network,
            methods,
        }
    }
}

#[derive(Debug, Error)]
pub enum SealError {
    #[error("storage: {0}")]
    Store(#[from] StoreError),
    #[error("witness: {0}")]
    Witness(#[from] WitnessError),
}

/// A test-driven seal request. The contained `now` value is used as the
/// `closed_at` timestamp for the sealed epoch and as the opening time for
/// the next epoch. Production code never constructs these directly.
#[derive(Debug, Clone, Copy)]
pub struct SealTick {
    pub now: u64,
}

/// Run a single seal cycle and return the persisted record together with
/// every witness minted during the cycle.
///
/// `closed_at` is the moment the seal observed; the next epoch opens at
/// `closed_at` and closes `duration_secs` later. When `witness_ctx` is
/// `None`, the seal still produces an `EpochRecord` but skips witness
/// minting (used by accumulator-only tests and by the M2-shape callers
/// that have not yet plumbed in a signer).
pub async fn seal_once(
    accumulator: &Accumulator,
    store: &Store,
    closed_at: u64,
    duration_secs: u64,
    witness_ctx: Option<&WitnessContext>,
) -> Result<(EpochRecord, Vec<MintedWitness>), SealError> {
    let snapshot = accumulator.swap_and_open_next(closed_at, closed_at, duration_secs);
    let (record, sorted_leaves) = build_record_and_sorted_leaves(&snapshot);

    let witnesses = if let Some(ctx) = witness_ctx {
        let minted = mint_witnesses_for_epoch(
            &snapshot,
            &record.merkle_root,
            &sorted_leaves,
            &ctx.methods,
            Arc::clone(&ctx.signer),
            &ctx.service_eth_address,
            &ctx.evm_network,
            closed_at,
        )
        .await?;
        for w in &minted {
            info!(
                leaf = %format!("0x{}", hex::encode(w.leaf)),
                method = %w.method.as_str(),
                tip = %format!("0x{}", hex::encode(w.signature_hash)),
                epoch = w.epoch_id,
                "witness minted"
            );
        }
        minted
    } else {
        Vec::new()
    };

    store.persist_sealed_epoch(&record, &snapshot.leaves, &witnesses)?;

    info!(
        id = record.id,
        root = %record.merkle_root_hex(),
        leaves = record.leaf_count,
        witnesses = witnesses.len(),
        "epoch sealed"
    );
    Ok((record, witnesses))
}

/// Pure helper: convert an in-memory [`SealedSnapshot`] into the on-disk
/// [`EpochRecord`] and the sorted leaf list used both for the Merkle root
/// and the per-leaf inclusion proofs. Leaves are sorted lexicographically
/// by raw bytes before being fed to the SDK Merkle builder, so the root
/// is independent of submission order (the property the test suite
/// asserts).
fn build_record_and_sorted_leaves(snapshot: &SealedSnapshot) -> (EpochRecord, Vec<Hash32>) {
    let mut sorted: Vec<Hash32> = snapshot.leaves.iter().map(|e| e.leaf).collect();
    sorted.sort_unstable();
    let root = merkle_root_for_leaves(&sorted);
    let record = EpochRecord {
        id: snapshot.epoch_id,
        opened_at: snapshot.opened_at,
        closed_at: snapshot.closed_at,
        merkle_root: root,
        leaf_count: snapshot.leaves.len() as u64,
        hash_type: HASH_TYPE_LABEL.to_string(),
    };
    (record, sorted)
}

/// Spawn the production seal loop on the current tokio runtime. Returns
/// the join handle so the supervisor (or test) can await shutdown.
pub fn run_sealer_with_interval<C: Clock + 'static>(
    accumulator: Arc<Accumulator>,
    store: Store,
    clock: C,
    duration_secs: u64,
    witness_ctx: Option<WitnessContext>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(duration_secs.max(1)));
        // First tick fires immediately; skip it so the first seal happens
        // one duration after startup, not on boot.
        interval.tick().await;
        loop {
            interval.tick().await;
            let now = clock.now_secs();
            if let Err(e) = seal_once(
                &accumulator,
                &store,
                now,
                duration_secs,
                witness_ctx.as_ref(),
            )
            .await
            {
                error!(error = %e, "seal cycle failed");
            }
        }
    })
}

/// Test alternative to the real timer: seal once per message received.
pub fn run_sealer_with_channel(
    accumulator: Arc<Accumulator>,
    store: Store,
    mut rx: mpsc::Receiver<SealTick>,
    duration_secs: u64,
    witness_ctx: Option<WitnessContext>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(tick) = rx.recv().await {
            if let Err(e) = seal_once(
                &accumulator,
                &store,
                tick.now,
                duration_secs,
                witness_ctx.as_ref(),
            )
            .await
            {
                error!(error = %e, "seal cycle failed");
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::FixedClock;
    use tempfile::tempdir;

    const DID_A: &str = "did:pkh:eip155:1:0xaaaa000000000000000000000000000000000000";
    const DID_B: &str = "did:pkh:eip155:1:0xbbbb000000000000000000000000000000000000";

    #[tokio::test]
    async fn seal_once_persists_record_and_leaves() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let acc = Accumulator::new(1, 0, 60);
        let l1 = [1u8; 32];
        let l2 = [2u8; 32];
        acc.append_batch(&[l1], DID_A);
        acc.append_batch(&[l2], DID_B);

        let (rec, witnesses) = seal_once(&acc, &store, 60, 60, None).await.expect("seal");
        assert_eq!(rec.id, 1);
        assert_eq!(rec.leaf_count, 2);
        assert!(witnesses.is_empty(), "no witness ctx → no witnesses");

        let mut leaves_sorted = vec![l1, l2];
        leaves_sorted.sort_unstable();
        let expected_root = merkle_root_for_leaves(&leaves_sorted);
        assert_eq!(rec.merkle_root, expected_root);

        // Next epoch is open.
        let view = acc.current_view();
        assert_eq!(view.epoch_id, 2);
    }

    #[tokio::test]
    async fn empty_epoch_seals_with_empty_root() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let acc = Accumulator::new(1, 0, 60);
        let (rec, _) = seal_once(&acc, &store, 60, 60, None).await.expect("seal");
        assert_eq!(rec.leaf_count, 0);
        assert_eq!(rec.merkle_root, crate::merkle::empty_merkle_root());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn channel_sealer_advances_epoch() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let acc = Arc::new(Accumulator::new(1, 0, 60));
        let (tx, rx) = mpsc::channel::<SealTick>(8);

        let _clock = FixedClock::new(0);
        let handle = run_sealer_with_channel(Arc::clone(&acc), store.clone(), rx, 60, None);

        acc.append_batch(&[[7u8; 32]], DID_A);
        tx.send(SealTick { now: 60 }).await.unwrap();

        // Give the task one yield to process; close the channel to let it
        // exit cleanly.
        tokio::task::yield_now().await;
        drop(tx);
        let _ = handle.await;

        let rec = store.get_epoch(1).unwrap().expect("sealed");
        assert_eq!(rec.id, 1);
        assert_eq!(rec.leaf_count, 1);
    }
}
