//! Thin adapters around the SDK Merkle primitive.
//!
//! All real Merkle work happens in [`aqua_rs_sdk::primitives::merkle`]; this
//! module exists so the empty-tree convention and leaf-decoding rules are
//! defined in one place rather than scattered through the route handlers
//! and the sealer.

use aqua_rs_sdk::primitives::{merkle::merkle_root as sdk_merkle_root, HashType};
use sha3::{Digest, Sha3_256};
use thiserror::Error;

/// 32-byte SHA3-256 leaf or root.
pub type Hash32 = [u8; 32];

/// Errors that can occur while parsing a submitted hex leaf.
#[derive(Debug, Error)]
pub enum LeafParseError {
    #[error("leaf must be 64 hex chars (optionally prefixed with 0x), got {0}")]
    BadLength(usize),
    #[error("leaf contains non-hex characters: {0}")]
    BadHex(#[from] hex::FromHexError),
}

/// Parse a user-submitted leaf string (`0x` + 64 hex, or 64 hex bare) into
/// 32 raw bytes. The accumulator stores leaves in this binary form so the
/// Merkle build skips hex decoding inside the seal hot path.
pub fn parse_leaf_hex(input: &str) -> Result<Hash32, LeafParseError> {
    let trimmed = input.strip_prefix("0x").unwrap_or(input);
    if trimmed.len() != 64 {
        return Err(LeafParseError::BadLength(trimmed.len()));
    }
    let bytes = hex::decode(trimmed)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Hex-encode a 32-byte hash in the canonical `0x` + lowercase form used in
/// API responses.
pub fn hex_lower(bytes: &Hash32) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Merkle root for an empty epoch.
///
/// RFC 9162 leaves the empty-tree case to the implementer (Section 2.1
/// only defines roots for `n >= 1`). The SDK's `merkle_root` panics on an
/// empty slice. We need a stable, well-defined value so the schedule stays
/// monotonic when nobody submits, so we pick `SHA3-256(b"")`. This is the
/// same convention the SDK's hash function would produce for an empty
/// pre-image, and it is distinct from any non-empty epoch root because no
/// 32-byte leaf can hash to the empty-string SHA3-256.
pub fn empty_merkle_root() -> Hash32 {
    let mut h = Sha3_256::new();
    h.update(b"");
    let out: [u8; 32] = h.finalize().into();
    out
}

/// Build the Merkle root over an already-sorted slice of pre-hashed
/// 32-byte leaves. Delegates to the SDK for any non-empty input; falls
/// back to [`empty_merkle_root`] for the zero-leaf case so callers never
/// have to special-case it.
pub fn merkle_root_for_leaves(leaves: &[Hash32]) -> Hash32 {
    if leaves.is_empty() {
        return empty_merkle_root();
    }
    let owned: Vec<Vec<u8>> = leaves.iter().map(|h| h.to_vec()).collect();
    let root = sdk_merkle_root(&owned, &HashType::Sha3_256);
    let mut out = [0u8; 32];
    out.copy_from_slice(&root);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_leaf_accepts_with_and_without_prefix() {
        let bare = "11".repeat(32);
        let prefixed = format!("0x{bare}");
        assert_eq!(parse_leaf_hex(&bare).unwrap(), [0x11; 32]);
        assert_eq!(parse_leaf_hex(&prefixed).unwrap(), [0x11; 32]);
    }

    #[test]
    fn parse_leaf_rejects_short_input() {
        assert!(matches!(
            parse_leaf_hex("0xabcd"),
            Err(LeafParseError::BadLength(_))
        ));
    }

    #[test]
    fn parse_leaf_rejects_non_hex() {
        assert!(matches!(
            parse_leaf_hex(&"z".repeat(64)),
            Err(LeafParseError::BadHex(_))
        ));
    }

    #[test]
    fn empty_root_matches_sha3_of_empty_string() {
        let mut h = Sha3_256::new();
        h.update(b"");
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(empty_merkle_root(), expected);
    }

    #[test]
    fn single_leaf_root_is_the_leaf() {
        let leaf = [0x42u8; 32];
        let root = merkle_root_for_leaves(&[leaf]);
        assert_eq!(root, leaf);
    }

    #[test]
    fn inclusion_round_trip_five_leaves() {
        use aqua_rs_sdk::primitives::merkle::{inclusion_proof, verify_inclusion};
        let leaves: Vec<Hash32> = (1u8..=5).map(|i| [i; 32]).collect();
        let leaves_vec: Vec<Vec<u8>> = leaves.iter().map(|h| h.to_vec()).collect();
        let root = merkle_root_for_leaves(&leaves);
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = inclusion_proof(&leaves_vec, i, &HashType::Sha3_256);
            assert!(
                verify_inclusion(leaf, i, leaves.len(), &proof, &root, &HashType::Sha3_256),
                "inclusion proof must verify for leaf {i}"
            );
        }
    }
}
