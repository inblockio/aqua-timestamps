//! In-memory leaf accumulator for the currently-open epoch.
//!
//! The accumulator answers two concurrent requests:
//!
//! 1. **Submission** (any number of allowlisted clients in parallel): appends
//!    leaves to the open epoch with first-submitter-wins dedup.
//! 2. **Seal** (single timer task): atomically swaps the current epoch's
//!    leaf set for an empty one and returns the swapped contents so the
//!    sealer can build a Merkle root and persist the [`EpochRecord`].
//!
//! Both operations take a single `Mutex<AccumulatorInner>`. The lock is
//! held only long enough to mutate a `HashSet` / `Vec`; no IO and no
//! cryptography runs under the lock, so contention stays bounded.
//!
//! The invariant the rest of M2 leans on:
//!
//! > A submission that observes the lock with epoch id `N` is guaranteed
//! > to land in epoch `N`. The seal task observes the same lock to perform
//! > the swap, so there is no window in which a submitted leaf disappears
//! > between accept and seal.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::merkle::Hash32;

/// Most leaves one epoch may hold: 2^20 (1 048 576).
///
/// The SDK timestamp templates (`timestamp_base.json`, `timestamp_evm.json`,
/// `timestamp_tsa.json` at the pinned rev) cap `batch_tree_size` at
/// 1 048 576. One epoch is one batch tree, so an epoch over this count would
/// mint witnesses that pass the aggregator's own inclusion check but fail a
/// reader's schema check. [`Accumulator::append_batch`] refuses a batch that
/// would cross it, and the self-check refuses any witness over it.
pub const MAX_LEAVES_PER_EPOCH: usize = 1 << 20;

/// [`Accumulator::append_batch`] refused the whole batch: its new leaves do
/// not fit under the epoch's leaf cap. Nothing of the batch was accepted;
/// the client retries after `epoch_closes_at`, when the next epoch opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochFull {
    pub epoch_id: u64,
    pub epoch_closes_at: u64,
    pub cap: usize,
}

/// One entry in the accumulator. Stored as a vector so the seal task can
/// hand the sorted leaves to the Merkle builder without extra allocation
/// per entry, while still keeping the submitter DID alongside each leaf
/// for the `epoch_leaves` partition write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafEntry {
    pub leaf: Hash32,
    pub submitter_did: String,
}

#[derive(Debug)]
struct AccumulatorInner {
    /// Currently-open epoch id.
    epoch_id: u64,
    /// Unix timestamp when the open epoch was opened.
    opened_at: u64,
    /// Unix timestamp when the open epoch is scheduled to close. Computed
    /// at open time so `GET /v1/schedule` is a constant-time lookup.
    closes_at: u64,
    /// Insertion-ordered list of accepted leaves (used by the sealer).
    leaves: Vec<LeafEntry>,
    /// First-submitter-wins dedup index. Maps leaf bytes to the index of
    /// the winning entry in `leaves`; kept in sync on every append.
    seen: HashMap<Hash32, usize>,
    /// Most leaves one epoch may hold ([`MAX_LEAVES_PER_EPOCH`] in
    /// production).
    leaf_cap: usize,
}

/// The thread-safe accumulator handed to the route handlers.
pub struct Accumulator {
    inner: Mutex<AccumulatorInner>,
}

/// Result of [`Accumulator::append_batch`]: tells the handler how many
/// leaves were new, how many were duplicates, and which epoch the new
/// leaves were placed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptOutcome {
    pub epoch_id: u64,
    pub epoch_closes_at: u64,
    pub accepted: u64,
    pub duplicates: u64,
}

/// Snapshot of the open epoch, returned by [`Accumulator::current_view`].
#[derive(Debug, Clone, Copy)]
pub struct CurrentView {
    pub epoch_id: u64,
    pub opened_at: u64,
    pub closes_at: u64,
}

/// What the sealer takes out of the accumulator: the closed epoch's
/// metadata plus its leaf set.
#[derive(Debug, Clone)]
pub struct SealedSnapshot {
    pub epoch_id: u64,
    pub opened_at: u64,
    pub closed_at: u64,
    pub leaves: Vec<LeafEntry>,
}

impl Accumulator {
    /// Start a new accumulator with `epoch_id` open from `opened_at` until
    /// `opened_at + duration_secs`.
    pub fn new(epoch_id: u64, opened_at: u64, duration_secs: u64) -> Self {
        Self::with_leaf_cap(epoch_id, opened_at, duration_secs, MAX_LEAVES_PER_EPOCH)
    }

    /// [`Accumulator::new`] with a leaf cap below [`MAX_LEAVES_PER_EPOCH`]
    /// (a test seam: a cap above the template maximum is clamped to it).
    pub fn with_leaf_cap(epoch_id: u64, opened_at: u64, duration_secs: u64, cap: usize) -> Self {
        Self {
            inner: Mutex::new(AccumulatorInner {
                epoch_id,
                opened_at,
                closes_at: opened_at.saturating_add(duration_secs),
                leaves: Vec::new(),
                seen: HashMap::new(),
                leaf_cap: cap.min(MAX_LEAVES_PER_EPOCH),
            }),
        }
    }

    /// Append a batch of pre-decoded leaves with a single submitter DID.
    ///
    /// The whole batch lands in the currently-open epoch (no batch is
    /// split across an epoch boundary). Duplicates are reported in the
    /// response but never overwrite the first submitter.
    ///
    /// A batch whose new (non-duplicate) leaves would take the epoch over
    /// its leaf cap is refused whole with [`EpochFull`]: nothing of it is
    /// accepted, so the client can resubmit it unchanged to the next epoch.
    pub fn append_batch(
        &self,
        batch: &[Hash32],
        submitter_did: &str,
    ) -> Result<AcceptOutcome, EpochFull> {
        let mut inner = self.inner.lock().expect("accumulator mutex poisoned");
        let fresh: std::collections::HashSet<&Hash32> = batch
            .iter()
            .filter(|leaf| !inner.seen.contains_key(*leaf))
            .collect();
        if inner.leaves.len().saturating_add(fresh.len()) > inner.leaf_cap {
            return Err(EpochFull {
                epoch_id: inner.epoch_id,
                epoch_closes_at: inner.closes_at,
                cap: inner.leaf_cap,
            });
        }
        let mut accepted = 0u64;
        let mut duplicates = 0u64;
        for leaf in batch {
            if inner.seen.contains_key(leaf) {
                duplicates = duplicates.saturating_add(1);
                continue;
            }
            let idx = inner.leaves.len();
            inner.leaves.push(LeafEntry {
                leaf: *leaf,
                submitter_did: submitter_did.to_string(),
            });
            inner.seen.insert(*leaf, idx);
            accepted = accepted.saturating_add(1);
        }
        Ok(AcceptOutcome {
            epoch_id: inner.epoch_id,
            epoch_closes_at: inner.closes_at,
            accepted,
            duplicates,
        })
    }

    /// Atomically swap the open epoch's contents for an empty bucket for
    /// the next epoch. Returns the sealed snapshot for the caller to
    /// persist.
    ///
    /// `closed_at` is whatever the sealer's clock reports for "now" when
    /// the swap happens; `next_opened_at` and `duration_secs` define the
    /// fresh epoch.
    pub fn swap_and_open_next(
        &self,
        closed_at: u64,
        next_opened_at: u64,
        duration_secs: u64,
    ) -> SealedSnapshot {
        let mut inner = self.inner.lock().expect("accumulator mutex poisoned");
        let old_id = inner.epoch_id;
        let old_opened = inner.opened_at;
        let old_leaves = std::mem::take(&mut inner.leaves);
        inner.seen.clear();
        inner.epoch_id = old_id.saturating_add(1);
        inner.opened_at = next_opened_at;
        inner.closes_at = next_opened_at.saturating_add(duration_secs);
        SealedSnapshot {
            epoch_id: old_id,
            opened_at: old_opened,
            closed_at,
            leaves: old_leaves,
        }
    }

    /// Read the open epoch's metadata (for `GET /v1/schedule`).
    pub fn current_view(&self) -> CurrentView {
        let inner = self.inner.lock().expect("accumulator mutex poisoned");
        CurrentView {
            epoch_id: inner.epoch_id,
            opened_at: inner.opened_at,
            closes_at: inner.closes_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID_A: &str = "did:pkh:eip155:1:0xaaaa000000000000000000000000000000000000";
    const DID_B: &str = "did:pkh:eip155:1:0xbbbb000000000000000000000000000000000000";

    #[test]
    fn dedup_keeps_first_submitter() {
        let acc = Accumulator::new(1, 100, 60);
        let leaf = [9u8; 32];

        let r1 = acc.append_batch(&[leaf], DID_A).unwrap();
        assert_eq!(r1.accepted, 1);
        assert_eq!(r1.duplicates, 0);

        let r2 = acc.append_batch(&[leaf], DID_B).unwrap();
        assert_eq!(r2.accepted, 0);
        assert_eq!(r2.duplicates, 1);

        let snap = acc.swap_and_open_next(200, 200, 60);
        assert_eq!(snap.leaves.len(), 1);
        assert_eq!(snap.leaves[0].submitter_did, DID_A);
    }

    #[test]
    fn intra_batch_dedup_counts_correctly() {
        let acc = Accumulator::new(1, 100, 60);
        let leaf = [1u8; 32];
        let outcome = acc.append_batch(&[leaf, leaf, leaf], DID_A).unwrap();
        assert_eq!(outcome.accepted, 1);
        assert_eq!(outcome.duplicates, 2);
    }

    #[test]
    fn swap_opens_next_epoch_and_returns_old() {
        let acc = Accumulator::new(5, 100, 60);
        acc.append_batch(&[[1u8; 32]], DID_A).unwrap();
        let snap = acc.swap_and_open_next(160, 160, 60);
        assert_eq!(snap.epoch_id, 5);
        assert_eq!(snap.leaves.len(), 1);

        let view = acc.current_view();
        assert_eq!(view.epoch_id, 6);
        assert_eq!(view.opened_at, 160);
        assert_eq!(view.closes_at, 220);

        // A submission after swap lands in the next epoch.
        let outcome = acc.append_batch(&[[2u8; 32]], DID_A).unwrap();
        assert_eq!(outcome.epoch_id, 6);
    }

    #[test]
    fn production_cap_is_the_template_maximum() {
        // timestamp_*.json: batch_tree_size "maximum": 1048576.
        assert_eq!(MAX_LEAVES_PER_EPOCH, 1_048_576);
        let acc = Accumulator::with_leaf_cap(1, 0, 60, usize::MAX);
        assert_eq!(
            acc.inner.lock().unwrap().leaf_cap,
            MAX_LEAVES_PER_EPOCH,
            "a cap above the template maximum is clamped"
        );
    }

    #[test]
    fn batch_over_cap_is_refused_whole_and_next_epoch_accepts() {
        let acc = Accumulator::with_leaf_cap(1, 100, 60, 3);
        acc.append_batch(&[[1u8; 32], [2u8; 32]], DID_A).unwrap();
        let full = acc
            .append_batch(&[[1u8; 32], [3u8; 32], [4u8; 32]], DID_B)
            .unwrap_err();
        assert_eq!(full.epoch_id, 1);
        assert_eq!(full.epoch_closes_at, 160);
        assert_eq!(full.cap, 3);
        // Duplicates do not count against the cap; one new leaf still fits.
        let ok = acc.append_batch(&[[2u8; 32], [3u8; 32]], DID_B).unwrap();
        assert_eq!((ok.accepted, ok.duplicates), (1, 1));
        assert!(acc.append_batch(&[[4u8; 32]], DID_B).is_err());
        let snap = acc.swap_and_open_next(160, 160, 60);
        assert_eq!(snap.leaves.len(), 3);
        let next = acc.append_batch(&[[4u8; 32]], DID_B).unwrap();
        assert_eq!((next.epoch_id, next.accepted), (2, 1));
    }
}
