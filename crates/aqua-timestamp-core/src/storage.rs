//! fjall-backed persistence for sealed epoch records and their leaf sets.
//!
//! Two partitions:
//!
//! * `epochs`: key = epoch id as 8 big-endian bytes, value = `postcard`-
//!   encoded [`EpochRecord`]. Big-endian so the natural byte order of fjall
//!   keys matches the natural numeric order of epoch ids; that lets the
//!   `GET /v1/epochs` handler iterate descending via `range(..).rev()`
//!   without an extra sort.
//! * `epoch_leaves`: key = `epoch_id_be (8 bytes) || leaf_bytes (32 bytes)`,
//!   value = submitter DID as UTF-8 bytes. The composite key lets M3 (and
//!   the persistence test in M2) scan per-epoch with a single
//!   `prefix(epoch_id_be)` call.
//!
//! Persistence policy: every seal commits its `EpochRecord` and the full
//! leaf-set batch through a single `Batch`, then forces a SyncAll
//! `persist` so the epoch is durable before the seal task returns. The
//! "fail-stop" guarantee (we never claim to have sealed an epoch we did
//! not durably write) is more valuable than the small latency cost.

use std::path::Path;

use fjall::{Config, Keyspace, PartitionCreateOptions, PartitionHandle, PersistMode};
use thiserror::Error;

use crate::accumulator::LeafEntry;
use crate::epoch::EpochRecord;

pub const EPOCHS_PARTITION: &str = "epochs";
pub const EPOCH_LEAVES_PARTITION: &str = "epoch_leaves";

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("fjall: {0}")]
    Fjall(#[from] fjall::Error),
    #[error("postcard encode: {0}")]
    Encode(postcard::Error),
    #[error("postcard decode: {0}")]
    Decode(postcard::Error),
    #[error("epoch_leaves key has wrong length {0}, expected {EPOCH_LEAVES_KEY_LEN}")]
    BadLeavesKey(usize),
}

/// Length of a composite `epoch_leaves` key: 8 (epoch id) + 32 (leaf hash).
pub const EPOCH_LEAVES_KEY_LEN: usize = 8 + 32;

/// Handle to the on-disk state. Cloneable; internally just `Arc`s.
#[derive(Clone)]
pub struct Store {
    keyspace: Keyspace,
    epochs: PartitionHandle,
    epoch_leaves: PartitionHandle,
}

impl Store {
    /// Open (or create) the keyspace at `path` and return a `Store`
    /// pointing at the two M2 partitions. The directory is created on
    /// demand by fjall.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let keyspace = Config::new(path).open()?;
        let epochs =
            keyspace.open_partition(EPOCHS_PARTITION, PartitionCreateOptions::default())?;
        let epoch_leaves =
            keyspace.open_partition(EPOCH_LEAVES_PARTITION, PartitionCreateOptions::default())?;
        Ok(Self {
            keyspace,
            epochs,
            epoch_leaves,
        })
    }

    /// Persist a sealed epoch + its leaf set atomically.
    ///
    /// All writes go through a single `Batch` so a crash mid-seal either
    /// reveals the epoch record together with every leaf or nothing at all.
    /// After commit the keyspace journal is fsynced.
    pub fn persist_sealed_epoch(
        &self,
        record: &EpochRecord,
        leaves: &[LeafEntry],
    ) -> Result<(), StoreError> {
        let mut batch = self.keyspace.batch();

        let epoch_key = record.id.to_be_bytes().to_vec();
        let encoded = postcard::to_stdvec(record).map_err(StoreError::Encode)?;
        batch.insert(&self.epochs, epoch_key, encoded);

        for entry in leaves {
            let key = compose_leaves_key(record.id, &entry.leaf);
            batch.insert(
                &self.epoch_leaves,
                key.to_vec(),
                entry.submitter_did.as_bytes().to_vec(),
            );
        }

        batch.commit()?;
        self.keyspace.persist(PersistMode::SyncAll)?;
        Ok(())
    }

    /// Load a single `EpochRecord` by id.
    pub fn get_epoch(&self, id: u64) -> Result<Option<EpochRecord>, StoreError> {
        let key = id.to_be_bytes();
        match self.epochs.get(key)? {
            Some(bytes) => {
                let rec: EpochRecord = postcard::from_bytes(&bytes).map_err(StoreError::Decode)?;
                Ok(Some(rec))
            }
            None => Ok(None),
        }
    }

    /// Highest persisted epoch id, or `None` if the store is empty.
    pub fn last_sealed_epoch_id(&self) -> Result<Option<u64>, StoreError> {
        let last = self.epochs.last_key_value()?;
        match last {
            Some((k, _)) => Ok(Some(u64_from_be_slice(&k)?)),
            None => Ok(None),
        }
    }

    /// Return up to `limit` epoch records with id `<=` start (descending).
    /// When `start` is `None`, begins from the highest stored id.
    ///
    /// Returns `(records, next_cursor)` where `next_cursor` is `Some(id)`
    /// to resume from, or `None` if the iteration reached id 1 / the start
    /// of storage.
    pub fn list_epochs_desc(
        &self,
        start: Option<u64>,
        limit: usize,
    ) -> Result<(Vec<EpochRecord>, Option<u64>), StoreError> {
        if limit == 0 {
            return Ok((Vec::new(), start));
        }
        let upper: [u8; 8] = match start {
            Some(s) => s.to_be_bytes(),
            None => u64::MAX.to_be_bytes(),
        };
        let mut out = Vec::with_capacity(limit);
        // Pull `limit + 1` to know whether another page exists without a
        // second range scan. We hand back at most `limit` records; the
        // extra one (if present) just tells us the cursor.
        let mut peeked_next: Option<u64> = None;
        for kv in self.epochs.range(..=upper).rev() {
            let (_, v) = kv?;
            let rec: EpochRecord = postcard::from_bytes(&v).map_err(StoreError::Decode)?;
            if out.len() == limit {
                peeked_next = Some(rec.id);
                break;
            }
            out.push(rec);
        }
        Ok((out, peeked_next))
    }

    /// Returns all `(leaf_hash, submitter_did)` entries persisted for a
    /// given epoch id. Used by the persistence test and by M3's witness
    /// minter.
    pub fn list_epoch_leaves(&self, id: u64) -> Result<Vec<(Vec<u8>, String)>, StoreError> {
        let prefix = id.to_be_bytes();
        let mut out = Vec::new();
        for kv in self.epoch_leaves.prefix(prefix) {
            let (k, v) = kv?;
            if k.len() != EPOCH_LEAVES_KEY_LEN {
                return Err(StoreError::BadLeavesKey(k.len()));
            }
            let leaf = k[8..].to_vec();
            let did = String::from_utf8_lossy(&v).to_string();
            out.push((leaf, did));
        }
        Ok(out)
    }

    /// Flush the journal. Exposed for tests; production callers go through
    /// `persist_sealed_epoch`.
    pub fn persist_now(&self) -> Result<(), StoreError> {
        self.keyspace.persist(PersistMode::SyncAll)?;
        Ok(())
    }
}

/// Build an `epoch_leaves` composite key.
pub fn compose_leaves_key(epoch_id: u64, leaf: &[u8; 32]) -> [u8; EPOCH_LEAVES_KEY_LEN] {
    let mut key = [0u8; EPOCH_LEAVES_KEY_LEN];
    key[..8].copy_from_slice(&epoch_id.to_be_bytes());
    key[8..].copy_from_slice(leaf);
    key
}

fn u64_from_be_slice(slice: &[u8]) -> Result<u64, StoreError> {
    if slice.len() != 8 {
        return Err(StoreError::BadLeavesKey(slice.len()));
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(slice);
    Ok(u64::from_be_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample_record(id: u64) -> EpochRecord {
        EpochRecord {
            id,
            opened_at: 1_000 + id,
            closed_at: 1_060 + id,
            merkle_root: [id as u8; 32],
            leaf_count: 2,
            hash_type: "FIPS_202-SHA3-256".into(),
        }
    }

    fn sample_leaves() -> Vec<LeafEntry> {
        vec![
            LeafEntry {
                leaf: [1u8; 32],
                submitter_did: "did:pkh:eip155:1:0xaaaa".into(),
            },
            LeafEntry {
                leaf: [2u8; 32],
                submitter_did: "did:pkh:eip155:1:0xbbbb".into(),
            },
        ]
    }

    #[test]
    fn round_trip_persist_and_load() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        let rec = sample_record(7);
        let leaves = sample_leaves();
        store.persist_sealed_epoch(&rec, &leaves).unwrap();

        let loaded = store.get_epoch(7).unwrap().expect("record present");
        assert_eq!(loaded, rec);

        let listed = store.list_epoch_leaves(7).unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.iter().any(|(_, d)| d == "did:pkh:eip155:1:0xaaaa"));
        assert!(listed.iter().any(|(_, d)| d == "did:pkh:eip155:1:0xbbbb"));

        assert_eq!(store.last_sealed_epoch_id().unwrap(), Some(7));
    }

    #[test]
    fn list_epochs_desc_paginates() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        for i in 1..=5u64 {
            store.persist_sealed_epoch(&sample_record(i), &[]).unwrap();
        }
        let (first_page, next) = store.list_epochs_desc(None, 3).unwrap();
        let ids: Vec<u64> = first_page.iter().map(|r| r.id).collect();
        assert_eq!(ids, vec![5, 4, 3]);
        assert_eq!(next, Some(2));

        let (second_page, next2) = store.list_epochs_desc(next, 3).unwrap();
        let ids: Vec<u64> = second_page.iter().map(|r| r.id).collect();
        assert_eq!(ids, vec![2, 1]);
        assert!(next2.is_none());
    }

    #[test]
    fn reopen_keyspace_recovers_records() {
        let dir = tempdir().unwrap();
        {
            let store = Store::open(dir.path()).unwrap();
            store
                .persist_sealed_epoch(&sample_record(42), &sample_leaves())
                .unwrap();
        }
        // Drop the keyspace, then reopen the same directory.
        let store = Store::open(dir.path()).unwrap();
        let loaded = store.get_epoch(42).unwrap().expect("persisted record");
        assert_eq!(loaded.id, 42);
        assert_eq!(store.list_epoch_leaves(42).unwrap().len(), 2);
    }
}
