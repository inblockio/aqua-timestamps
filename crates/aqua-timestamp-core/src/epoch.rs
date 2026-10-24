//! Epoch record: the post-seal artefact persisted per epoch.
//!
//! The record is canonical (deterministic byte representation for a given
//! input) so that storage, replay, and future anchor proofs all agree on
//! the same identity for an epoch.

use serde::{Deserialize, Serialize};

/// Display value of the SDK hash type (`HashType::Sha3_256`). Persisted as a
/// string so future hash agility (BLAKE3, KangarooTwelve, ...) can land in
/// the same record without a schema migration.
pub const HASH_TYPE_LABEL: &str = "FIPS_202-SHA3-256";

/// Persisted summary of a sealed epoch.
///
/// `merkle_root` is the digest of the SDK batch root the epoch's anchors
/// carry (`prepare_batch_timestamp`: the PCA-0015 shielded RFC 9162 tree,
/// one shielded leaf per accepted leaf; wire form `0x1620` + this digest).
/// Records sealed before OW1 hold the legacy raw-leaf root instead, which no
/// SDK verifier accepts. For epochs with zero leaves nothing is anchored and
/// the root is `sha3_256(b"")` (see
/// [`empty_merkle_root`](crate::merkle::empty_merkle_root)).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochRecord {
    pub id: u64,
    pub opened_at: u64,
    pub closed_at: u64,
    pub merkle_root: [u8; 32],
    pub leaf_count: u64,
    pub hash_type: String,
}

impl EpochRecord {
    pub fn merkle_root_hex(&self) -> String {
        format!("0x{}", hex::encode(self.merkle_root))
    }
}
