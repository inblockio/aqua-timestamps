//! fjall-backed persistence for sealed epoch records, their leaf sets,
//! and the per-leaf witness revisions minted on seal.
//!
//! Partitions:
//!
//! * `epochs`: key = epoch id as 8 big-endian bytes, value = `postcard`-
//!   encoded [`EpochRecord`]. Big-endian so the natural byte order of fjall
//!   keys matches the natural numeric order of epoch ids; that lets the
//!   `GET /v1/epochs` handler iterate descending via `range(..).rev()`
//!   without an extra sort.
//! * `epoch_leaves`: key = `epoch_id_be (8 bytes) || leaf_bytes (32 bytes)`,
//!   value = submitter DID as UTF-8 bytes. The composite key lets the
//!   persistence test and the witness minter scan per-epoch with a single
//!   `prefix(epoch_id_be)` call.
//! * `witness_revisions` (M3): key = 32-byte revision hash, value =
//!   `serde_json::to_vec(&AnyRevision)`. JSON instead of postcard so the
//!   bytes are byte-identical to what an `/trees/{tip}` response would
//!   emit; the route handler just `from_slice`s back into `AnyRevision`
//!   and re-serialises into the larger response document.
//! * `leaf_to_tips` (M3): key = `leaf_bytes (32) || method_byte (1)`,
//!   value = signature revision hash (32 bytes). Fixed-width composite key
//!   keeps `/trees/by-leaf/{leaf}?method=evm` to one fjall `get`.
//! * `leaf_owner` (M3): key = leaf bytes (32), value = submitter DID as
//!   UTF-8. Mirrors the DID already present in `epoch_leaves`; this index
//!   answers "who owns this leaf?" in O(1) without scanning the per-epoch
//!   prefix.
//! * `tip_to_pair` (M3): key = signature revision hash (32), value =
//!   `postcard`-encoded [`TipPairIndex`]. Lets `/trees/{tip}` resolve the
//!   underlying object hash, leaf, method, and epoch with a single `get`
//!   so the witness-pair body doesn't require any scanning.
//!
//! Persistence policy: every seal commits its `EpochRecord`, the full
//! leaf-set batch, AND every freshly minted witness revision through a
//! single `Batch`, then forces a SyncAll `persist` so the epoch is durable
//! before the seal task returns. The "fail-stop" guarantee (we never
//! claim to have sealed an epoch we did not durably write) is more
//! valuable than the small latency cost.

use std::path::Path;

use fjall::{Config, Keyspace, PartitionCreateOptions, PartitionHandle, PersistMode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::accumulator::LeafEntry;
use crate::epoch::EpochRecord;
use crate::witness::{AnchorMethod, MintedWitness};

pub const EPOCHS_PARTITION: &str = "epochs";
pub const EPOCH_LEAVES_PARTITION: &str = "epoch_leaves";
pub const WITNESS_REVISIONS_PARTITION: &str = "witness_revisions";
pub const LEAF_TO_TIPS_PARTITION: &str = "leaf_to_tips";
pub const LEAF_OWNER_PARTITION: &str = "leaf_owner";
pub const TIP_TO_PAIR_PARTITION: &str = "tip_to_pair";

/// Length of a composite `leaf_to_tips` key: 32 (leaf hash) + 1 (method byte).
pub const LEAF_TO_TIPS_KEY_LEN: usize = 32 + 1;

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
    #[error("leaf_to_tips key has wrong length {0}, expected {LEAF_TO_TIPS_KEY_LEN}")]
    BadLeafTipsKey(usize),
    #[error("witness revision JSON encode/decode: {0}")]
    WitnessJson(#[from] serde_json::Error),
    #[error("witness lookup found an unknown method byte: {0:#x}")]
    UnknownMethodByte(u8),
}

/// Length of a composite `epoch_leaves` key: 8 (epoch id) + 32 (leaf hash).
pub const EPOCH_LEAVES_KEY_LEN: usize = 8 + 32;

/// Index value stored at `tip_to_pair[signature_hash]`.
///
/// All fields are needed by `/trees/{tip}` to assemble a response without
/// touching any other partition: the object hash points at the second
/// half of the witness pair, the leaf decides DID isolation, the method
/// reconstructs the synthetic file_index name, and the epoch lets the
/// caller correlate with `/v1/epochs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TipPairIndex {
    pub object_hash: [u8; 32],
    pub signature_hash: [u8; 32],
    pub leaf: [u8; 32],
    pub method_byte: u8,
    pub epoch_id: u64,
    pub submitter_did: String,
    pub object_file_name: String,
    pub signature_file_name: String,
}

/// Handle to the on-disk state. Cloneable; internally just `Arc`s.
#[derive(Clone)]
pub struct Store {
    keyspace: Keyspace,
    epochs: PartitionHandle,
    epoch_leaves: PartitionHandle,
    witness_revisions: PartitionHandle,
    leaf_to_tips: PartitionHandle,
    leaf_owner: PartitionHandle,
    tip_to_pair: PartitionHandle,
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
        let witness_revisions = keyspace.open_partition(
            WITNESS_REVISIONS_PARTITION,
            PartitionCreateOptions::default(),
        )?;
        let leaf_to_tips =
            keyspace.open_partition(LEAF_TO_TIPS_PARTITION, PartitionCreateOptions::default())?;
        let leaf_owner =
            keyspace.open_partition(LEAF_OWNER_PARTITION, PartitionCreateOptions::default())?;
        let tip_to_pair =
            keyspace.open_partition(TIP_TO_PAIR_PARTITION, PartitionCreateOptions::default())?;
        Ok(Self {
            keyspace,
            epochs,
            epoch_leaves,
            witness_revisions,
            leaf_to_tips,
            leaf_owner,
            tip_to_pair,
        })
    }

    /// Persist a sealed epoch, its leaf set, AND every minted witness
    /// revision atomically.
    ///
    /// All writes go through a single `Batch` so a crash mid-seal either
    /// reveals (epoch record, leaf set, witnesses) together or none of it.
    /// After commit the keyspace journal is fsynced.
    ///
    /// The witness list may be empty (e.g. an empty epoch); the M2 path
    /// effectively passes `&[]` and produces the same shape as before.
    pub fn persist_sealed_epoch(
        &self,
        record: &EpochRecord,
        leaves: &[LeafEntry],
        witnesses: &[MintedWitness],
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
            batch.insert(
                &self.leaf_owner,
                entry.leaf.to_vec(),
                entry.submitter_did.as_bytes().to_vec(),
            );
        }

        for w in witnesses {
            let obj_json = serde_json::to_vec(&w.object_revision)?;
            let sig_json = serde_json::to_vec(&w.signature_revision)?;
            batch.insert(&self.witness_revisions, w.object_hash.to_vec(), obj_json);
            batch.insert(&self.witness_revisions, w.signature_hash.to_vec(), sig_json);

            let leaf_tip_key = compose_leaf_to_tips_key(&w.leaf, w.method.method_byte());
            batch.insert(
                &self.leaf_to_tips,
                leaf_tip_key.to_vec(),
                w.signature_hash.to_vec(),
            );

            let index = TipPairIndex {
                object_hash: w.object_hash,
                signature_hash: w.signature_hash,
                leaf: w.leaf,
                method_byte: w.method.method_byte(),
                epoch_id: w.epoch_id,
                submitter_did: w.submitter_did.clone(),
                object_file_name: w.object_file_name.clone(),
                signature_file_name: w.signature_file_name.clone(),
            };
            let index_bytes = postcard::to_stdvec(&index).map_err(StoreError::Encode)?;
            batch.insert(&self.tip_to_pair, w.signature_hash.to_vec(), index_bytes);
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

    // ── M3 witness lookup helpers ───────────────────────────────────────

    /// Fetch one persisted revision (Object or Signature) by its 32-byte
    /// hash. Returns the raw JSON bytes so the caller can deserialise
    /// directly into `aqua_rs_sdk::schema::AnyRevision`.
    pub fn get_revision_json(&self, hash: &[u8; 32]) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.witness_revisions.get(hash)?.map(|s| s.to_vec()))
    }

    /// Fetch the witness `TipPairIndex` for a given signature revision
    /// hash. `None` if the tip is unknown.
    pub fn get_tip_pair(
        &self,
        signature_hash: &[u8; 32],
    ) -> Result<Option<TipPairIndex>, StoreError> {
        match self.tip_to_pair.get(signature_hash)? {
            Some(bytes) => {
                let idx: TipPairIndex = postcard::from_bytes(&bytes).map_err(StoreError::Decode)?;
                Ok(Some(idx))
            }
            None => Ok(None),
        }
    }

    /// Look up the signature-revision hash (the witness "tip") for the
    /// given leaf and anchor method. `None` if the leaf has no witness
    /// for that method yet.
    pub fn get_tip_for_leaf(
        &self,
        leaf: &[u8; 32],
        method: AnchorMethod,
    ) -> Result<Option<[u8; 32]>, StoreError> {
        let key = compose_leaf_to_tips_key(leaf, method.method_byte());
        match self.leaf_to_tips.get(key)? {
            Some(bytes) => {
                if bytes.len() != 32 {
                    return Err(StoreError::BadLeafTipsKey(bytes.len()));
                }
                let mut out = [0u8; 32];
                out.copy_from_slice(&bytes);
                Ok(Some(out))
            }
            None => Ok(None),
        }
    }

    /// Look up the submitter DID for a given leaf. `None` if the leaf
    /// was never accepted.
    pub fn get_leaf_owner(&self, leaf: &[u8; 32]) -> Result<Option<String>, StoreError> {
        match self.leaf_owner.get(leaf)? {
            Some(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).to_string())),
            None => Ok(None),
        }
    }

    /// Return every witness tip a given DID owns across all epochs, with
    /// the epoch id alongside so the caller can sort descending.
    ///
    /// Implementation note: this scans the full `tip_to_pair` partition.
    /// At M3 the volume is small (<= leaves/epoch * methods * epochs);
    /// a dedicated `did_to_tips` index can land later if profiling shows
    /// this hot.
    pub fn list_witness_tips_for_did(&self, did: &str) -> Result<Vec<(u64, [u8; 32])>, StoreError> {
        let mut out: Vec<(u64, [u8; 32])> = Vec::new();
        for kv in self.tip_to_pair.iter() {
            let (k, v) = kv?;
            if k.len() != 32 {
                continue;
            }
            let idx: TipPairIndex = postcard::from_bytes(&v).map_err(StoreError::Decode)?;
            if idx.submitter_did == did {
                let mut tip = [0u8; 32];
                tip.copy_from_slice(&k);
                out.push((idx.epoch_id, tip));
            }
        }
        // Descending by epoch, stable on tip bytes for determinism.
        out.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        Ok(out)
    }

    /// Return all witness tips for a given `(epoch_id, method)` whose
    /// underlying leaf was submitted by `did`. Returns each tip's full
    /// `TipPairIndex` so the route handler can rebuild the response in
    /// one pass.
    pub fn list_witnesses_for_did_in_epoch(
        &self,
        did: &str,
        epoch_id: u64,
        method: AnchorMethod,
    ) -> Result<Vec<TipPairIndex>, StoreError> {
        let mb = method.method_byte();
        let mut out: Vec<TipPairIndex> = Vec::new();
        for kv in self.tip_to_pair.iter() {
            let (_, v) = kv?;
            let idx: TipPairIndex = postcard::from_bytes(&v).map_err(StoreError::Decode)?;
            if idx.epoch_id == epoch_id && idx.method_byte == mb && idx.submitter_did == did {
                out.push(idx);
            }
        }
        // Deterministic ordering so the JSON response is stable across
        // restarts (callers iterate a `BTreeMap<RevisionLink, _>` keyed
        // by the rendered hex hash, which is what the SDK's `Tree` does).
        out.sort_by(|a, b| a.signature_file_name.cmp(&b.signature_file_name));
        Ok(out)
    }
}

/// Build a `leaf_to_tips` composite key.
pub fn compose_leaf_to_tips_key(leaf: &[u8; 32], method_byte: u8) -> [u8; LEAF_TO_TIPS_KEY_LEN] {
    let mut key = [0u8; LEAF_TO_TIPS_KEY_LEN];
    key[..32].copy_from_slice(leaf);
    key[32] = method_byte;
    key
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
        store.persist_sealed_epoch(&rec, &leaves, &[]).unwrap();

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
            store
                .persist_sealed_epoch(&sample_record(i), &[], &[])
                .unwrap();
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
                .persist_sealed_epoch(&sample_record(42), &sample_leaves(), &[])
                .unwrap();
        }
        // Drop the keyspace, then reopen the same directory.
        let store = Store::open(dir.path()).unwrap();
        let loaded = store.get_epoch(42).unwrap().expect("persisted record");
        assert_eq!(loaded.id, 42);
        assert_eq!(store.list_epoch_leaves(42).unwrap().len(), 2);
    }
}
