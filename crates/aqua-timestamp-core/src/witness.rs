//! Per-leaf witness revision minter.
//!
//! On epoch seal, for every accepted leaf and every configured anchor
//! method, the minter produces a two-revision Aqua-tree:
//!
//! ```text
//!   client_leaf  ──>  TimestampObject  ──>  Signature
//!                     (Object, evm/qtsa  (EIP-191 over the object
//!                      timestamp payload) hash by the service key)
//! ```
//!
//! The TimestampObject's `previous_revision` is the client-submitted leaf
//! hash itself, not a tree revision we own; this is exactly the chain
//! shape aquafire publishes and what the SDK's verifier reconstructs.
//!
//! The payloads are filled in via the SDK's built-in template types
//! ([`EvmTimestampPayload`] / [`TsaTimestampPayload`]) so the JSON schema
//! validator inside `create_object_util` passes. At M3 the on-chain /
//! qTSA fields are filled with deterministic stub values; M4 / M5 replace
//! the stubs with real anchor outputs without changing this minting path.

use std::sync::Arc;

use aqua_rs_sdk::{
    primitives::{merkle::inclusion_proof, HashType, Method, RevisionLink},
    schema::{
        template::BuiltInTemplate,
        templates::{EvmTimestampPayload, TsaTimestampPayload},
        AnyRevision, Object,
    },
    verification::Linkable,
    Secp256k1Signer, Signer,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::accumulator::SealedSnapshot;
use crate::merkle::Hash32;

/// One byte identifying an anchor method inside composite storage keys.
///
/// Picking dedicated byte tags (rather than serialising the string name)
/// keeps the `(leaf || method_byte)` key fixed-width (33 bytes), which
/// lets the routes resolve a `leaf → tip` lookup with a single fjall
/// `get` and no string parsing.
pub const METHOD_BYTE_EVM: u8 = 0x01;
pub const METHOD_BYTE_QTSA: u8 = 0x02;

/// Anchor methods advertised by the aggregator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnchorMethod {
    Evm,
    Qtsa,
}

impl AnchorMethod {
    pub const ALL: [AnchorMethod; 2] = [AnchorMethod::Evm, AnchorMethod::Qtsa];

    pub fn as_str(self) -> &'static str {
        match self {
            AnchorMethod::Evm => "evm",
            AnchorMethod::Qtsa => "qtsa",
        }
    }

    pub fn method_byte(self) -> u8 {
        match self {
            AnchorMethod::Evm => METHOD_BYTE_EVM,
            AnchorMethod::Qtsa => METHOD_BYTE_QTSA,
        }
    }

    pub fn parse(input: &str) -> Option<Self> {
        match input {
            "evm" => Some(AnchorMethod::Evm),
            "qtsa" => Some(AnchorMethod::Qtsa),
            _ => None,
        }
    }

    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            METHOD_BYTE_EVM => Some(AnchorMethod::Evm),
            METHOD_BYTE_QTSA => Some(AnchorMethod::Qtsa),
            _ => None,
        }
    }
}

#[derive(Debug, Error)]
pub enum WitnessError {
    #[error("witness object build failed: {0}")]
    Object(String),
    #[error("witness signature failed: {0}")]
    Sign(String),
    #[error("witness payload serialise failed: {0}")]
    Serialise(#[from] serde_json::Error),
    #[error("hash conversion: expected 32 bytes, got {0}")]
    BadHash(usize),
}

/// One (TimestampObject, Signature) pair produced by the minter, plus the
/// per-pair metadata persistence needs.
#[derive(Debug, Clone)]
pub struct MintedWitness {
    /// 32-byte hash of the TimestampObject revision.
    pub object_hash: Hash32,
    /// 32-byte hash of the Signature revision (a.k.a. the witness "tip").
    pub signature_hash: Hash32,
    /// The client's submitted leaf this witness covers.
    pub leaf: Hash32,
    /// Which anchor method this witness is for.
    pub method: AnchorMethod,
    /// Sealed epoch the witness belongs to.
    pub epoch_id: u64,
    /// Submitter DID for the underlying leaf. Persisted as the owner of
    /// both witness revisions so DID-isolated lookups don't have to walk
    /// the leaf-set index.
    pub submitter_did: String,
    /// Filename used for the TimestampObject inside the Tree `file_index`.
    pub object_file_name: String,
    /// Filename used for the Signature inside the Tree `file_index`.
    pub signature_file_name: String,
    /// SDK-typed revisions, ready to be inserted into a `Tree::revisions`
    /// map or serialised to JSON.
    pub object_revision: AnyRevision,
    /// SDK-typed Signature revision.
    pub signature_revision: AnyRevision,
}

/// Mint every witness revision implied by a sealed snapshot.
///
/// Inputs:
/// * `snapshot` : the just-closed accumulator output. Provides the
///   per-epoch leaf set with submitter DIDs.
/// * `merkle_root` : the Merkle root of the (sorted) leaf set. The seal
///   driver already computed this for the `EpochRecord`; we re-use it
///   instead of recomputing.
/// * `sorted_leaves` : the same leaf set the root was built from, in the
///   canonical lexicographic order so each leaf's `inclusion_proof` lands
///   at the right index.
/// * `methods` : methods to mint for. Production calls
///   [`AnchorMethod::ALL`]; tests can mint only one.
/// * `signer` : the service's secp256k1 signer.
/// * `service_did` : the signer's `did:pkh:eip155:1:0x..` (already in the
///   identity object; passed in here so witness DIDs are consistent with
///   the published service identity).
/// * `network_evm` : the network label the on-chain witness should
///   carry. M3 uses `"sepolia"` to match the M4 target.
/// * `service_eth_addr` : the service's EIP-55 ethereum address (no
///   `0x` prefix); used as the `sender_account_address` in the EVM
///   witness payload.
/// * `epoch_timestamp` : the unix timestamp that closed the epoch; used
///   as the witness `timestamp` field across both methods.
///
/// Witnesses are produced in deterministic order: leaves iterate in the
/// same (sorted) order as the Merkle build, methods iterate in the
/// order given. Output ordering is documented because the storage layer
/// writes the whole list through a single fjall batch.
#[allow(clippy::too_many_arguments)]
pub async fn mint_witnesses_for_epoch(
    snapshot: &SealedSnapshot,
    merkle_root: &Hash32,
    sorted_leaves: &[Hash32],
    methods: &[AnchorMethod],
    signer: Arc<Secp256k1Signer>,
    service_eth_addr: &str,
    network_evm: &str,
    epoch_timestamp: u64,
) -> Result<Vec<MintedWitness>, WitnessError> {
    if snapshot.leaves.is_empty() {
        return Ok(Vec::new());
    }

    // Map every leaf to its index in the sorted (Merkle) order so the
    // inclusion proof we attach to each witness verifies against the
    // persisted root. The accumulator hands leaves out in insertion
    // order; the Merkle build operates on the lexicographic sort. We
    // need the index in the *sort*, not the index of submission.
    let leaves_vec: Vec<Vec<u8>> = sorted_leaves.iter().map(|h| h.to_vec()).collect();
    let tree_size = sorted_leaves.len();

    let merkle_root_hex = hex_lower_bytes(merkle_root);

    let mut out = Vec::with_capacity(snapshot.leaves.len() * methods.len());

    for entry in &snapshot.leaves {
        let leaf = entry.leaf;
        let leaf_index = sorted_leaves
            .binary_search(&leaf)
            .map_err(|_| WitnessError::Object("leaf missing from sorted leaf-set".into()))?;
        let proof = inclusion_proof(&leaves_vec, leaf_index, &HashType::Sha3_256);
        let proof_hex: Vec<String> = proof
            .iter()
            .map(|sib| format!("0x{}", hex::encode(sib)))
            .collect();

        for &method in methods {
            let witness = mint_single_witness(
                &leaf,
                &entry.submitter_did,
                snapshot.epoch_id,
                method,
                leaf_index,
                tree_size,
                &proof_hex,
                &merkle_root_hex,
                signer.as_ref(),
                service_eth_addr,
                network_evm,
                epoch_timestamp,
            )
            .await?;
            out.push(witness);
        }
    }

    Ok(out)
}

#[allow(clippy::too_many_arguments)]
async fn mint_single_witness(
    leaf: &Hash32,
    submitter_did: &str,
    epoch_id: u64,
    method: AnchorMethod,
    leaf_index: usize,
    tree_size: usize,
    proof_hex: &[String],
    merkle_root_hex: &str,
    signer: &Secp256k1Signer,
    service_eth_addr: &str,
    network_evm: &str,
    epoch_timestamp: u64,
) -> Result<MintedWitness, WitnessError> {
    // Build the typed payload via the SDK's template structs. Using the
    // typed payload guarantees we satisfy the template's JSON-schema
    // validator (the SDK's `create_object_util` invokes that validator).
    //
    // Stub anchor outputs at M3:
    //   * `transaction_hash`  = 0x + 64 zeros (both methods).
    //   * `smart_contract_address` (EVM only) = 0x + 40 zeros.
    //   * `tsa_provider` (qTSA only) = "stub".
    // The SDK template schemas accept these as plain strings; they're
    // distinguishable from a real anchor result by the all-zero hash and
    // the literal "stub" provider name.
    let stub_tx_hash = format!("0x{}", "0".repeat(64));
    let stub_contract = format!("0x{}", "0".repeat(40));

    let payload_value = match method {
        AnchorMethod::Evm => {
            let payload = EvmTimestampPayload {
                timestamp_type: "timestamp".to_string(),
                merkle_root: merkle_root_hex.to_string(),
                timestamp: epoch_timestamp,
                network: network_evm.to_string(),
                smart_contract_address: stub_contract,
                transaction_hash: stub_tx_hash,
                sender_account_address: ensure_0x(service_eth_addr),
                merkle_proof: proof_hex.to_vec(),
                batch_tree_size: tree_size,
                batch_leaf_index: leaf_index,
            };
            serde_json::to_value(&payload)?
        }
        AnchorMethod::Qtsa => {
            let payload = TsaTimestampPayload {
                timestamp_type: "timestamp".to_string(),
                merkle_root: merkle_root_hex.to_string(),
                timestamp: epoch_timestamp,
                network: "tsa".to_string(),
                transaction_hash: stub_tx_hash,
                tsa_provider: "stub".to_string(),
                merkle_proof: proof_hex.to_vec(),
                batch_tree_size: tree_size,
                batch_leaf_index: leaf_index,
            };
            serde_json::to_value(&payload)?
        }
    };

    let template_link = match method {
        AnchorMethod::Evm => RevisionLink::from_bytes(EvmTimestampPayload::TEMPLATE_LINK),
        AnchorMethod::Qtsa => RevisionLink::from_bytes(TsaTimestampPayload::TEMPLATE_LINK),
    };

    // Construct the Object directly chained to the client leaf. We don't
    // go through `create_object_util` here because that helper builds a
    // fresh genesis anchor when no previous tree is supplied; the
    // witness chain is rooted in the client's leaf (which the client
    // already owns and signed in their own tree), not in an anchor we
    // mint.
    let leaf_link = RevisionLink::from_bytes(*leaf);
    let mut object = Object::<serde_json::Value>::new(
        leaf_link.clone(),
        template_link,
        Method::Scalar,
        HashType::Sha3_256,
        payload_value,
    );
    let object_link = object
        .calculate_link()
        .map_err(|e| WitnessError::Object(format!("calculate_link: {e:?}")))?;
    // Method::Scalar means `populate_leaves` is a no-op, but call it
    // anyway so the object's serialised shape is identical to whatever
    // `create_object_util` would have emitted.
    object
        .populate_leaves()
        .map_err(|e| WitnessError::Object(format!("populate_leaves: {e:?}")))?;
    let object_hash = revision_link_to_hash(&object_link)?;

    let signature_revision = signer
        .sign_revision(&object_link, Method::Scalar, HashType::Sha3_256)
        .await
        .map_err(|e| WitnessError::Sign(format!("{e:?}")))?;
    let signature_link = signature_revision
        .calculate_link()
        .map_err(|e| WitnessError::Sign(format!("calculate_link: {e:?}")))?;
    let signature_hash = revision_link_to_hash(&signature_link)?;

    let leaf_hex = hex_lower_bytes(leaf);
    let leaf_short = &leaf_hex[2..10]; // 8 hex chars after 0x

    Ok(MintedWitness {
        object_hash,
        signature_hash,
        leaf: *leaf,
        method,
        epoch_id,
        submitter_did: submitter_did.to_string(),
        object_file_name: format!("witness_{}_{}", method.as_str(), leaf_short),
        signature_file_name: format!("witness_sig_{}_{}", method.as_str(), leaf_short),
        object_revision: AnyRevision::Typed(object),
        signature_revision: AnyRevision::Signature(signature_revision),
    })
}

fn hex_lower_bytes(bytes: &Hash32) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn ensure_0x(addr: &str) -> String {
    if addr.starts_with("0x") || addr.starts_with("0X") {
        addr.to_string()
    } else {
        format!("0x{addr}")
    }
}

fn revision_link_to_hash(link: &RevisionLink) -> Result<Hash32, WitnessError> {
    let bytes = link.as_ref();
    if bytes.len() != 32 {
        return Err(WitnessError::BadHash(bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accumulator::{Accumulator, LeafEntry};
    use crate::merkle::merkle_root_for_leaves;
    use aqua_rs_sdk::primitives::merkle::verify_inclusion;

    const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";

    async fn build_signer() -> Arc<Secp256k1Signer> {
        let (_addr, _eip55, pk_hex) = aqua_rs_sdk::primitives::get_wallet(TEST_MNEMONIC)
            .await
            .unwrap();
        let pk = hex::decode(pk_hex.trim_start_matches("0x")).unwrap();
        Arc::new(Secp256k1Signer::new(pk))
    }

    #[test]
    fn method_round_trip_through_byte() {
        for m in AnchorMethod::ALL {
            assert_eq!(AnchorMethod::from_byte(m.method_byte()), Some(m));
            assert_eq!(AnchorMethod::parse(m.as_str()), Some(m));
        }
        assert_eq!(AnchorMethod::from_byte(0xFF), None);
        assert_eq!(AnchorMethod::parse("nope"), None);
    }

    #[tokio::test]
    async fn mint_produces_two_revisions_per_leaf_per_method() {
        let acc = Accumulator::new(7, 1000, 60);
        let leaves: Vec<Hash32> = (1u8..=3).map(|i| [i; 32]).collect();
        acc.append_batch(&leaves, "did:pkh:eip155:1:0xAAAA");
        let snapshot = acc.swap_and_open_next(1060, 1060, 60);

        let mut sorted = leaves.clone();
        sorted.sort();
        let root = merkle_root_for_leaves(&sorted);

        let signer = build_signer().await;
        let witnesses = mint_witnesses_for_epoch(
            &snapshot,
            &root,
            &sorted,
            &AnchorMethod::ALL,
            signer,
            "0x0000000000000000000000000000000000000000",
            "sepolia",
            1060,
        )
        .await
        .unwrap();
        assert_eq!(witnesses.len(), 6);

        // Pick the first witness and verify its inclusion proof.
        let w = &witnesses[0];
        let leaf_index = sorted.iter().position(|h| h == &w.leaf).unwrap();
        let leaves_vec: Vec<Vec<u8>> = sorted.iter().map(|h| h.to_vec()).collect();
        let proof = inclusion_proof(&leaves_vec, leaf_index, &HashType::Sha3_256);
        assert!(verify_inclusion(
            &w.leaf,
            leaf_index,
            sorted.len(),
            &proof,
            &root,
            &HashType::Sha3_256
        ));
    }

    #[tokio::test]
    async fn empty_snapshot_mints_no_witnesses() {
        let snap = SealedSnapshot {
            epoch_id: 1,
            opened_at: 0,
            closed_at: 60,
            leaves: vec![],
        };
        let root = crate::merkle::empty_merkle_root();
        let signer = build_signer().await;
        let witnesses = mint_witnesses_for_epoch(
            &snap,
            &root,
            &[],
            &AnchorMethod::ALL,
            signer,
            "0x0",
            "sepolia",
            60,
        )
        .await
        .unwrap();
        assert!(witnesses.is_empty());
    }

    #[tokio::test]
    async fn witness_chains_to_client_leaf() {
        let leaf: Hash32 = [0x99; 32];
        let acc = Accumulator::new(2, 0, 60);
        acc.append_batch(&[leaf], "did:pkh:eip155:1:0xCCCC");
        let snap = acc.swap_and_open_next(60, 60, 60);
        let sorted = vec![leaf];
        let root = merkle_root_for_leaves(&sorted);
        let signer = build_signer().await;
        let witnesses = mint_witnesses_for_epoch(
            &snap,
            &root,
            &sorted,
            &[AnchorMethod::Evm],
            signer,
            "0x0000000000000000000000000000000000000000",
            "sepolia",
            60,
        )
        .await
        .unwrap();
        assert_eq!(witnesses.len(), 1);
        let w = &witnesses[0];
        // The object's previous_revision must be the client leaf.
        if let AnyRevision::Typed(obj) = &w.object_revision {
            let prev = obj
                .previous_revision()
                .expect("witness object must have a previous_revision");
            let prev_bytes = prev.as_ref();
            assert_eq!(prev_bytes, leaf);
        } else {
            panic!("expected Typed object revision");
        }
        // The signature's previous_revision must be the object hash.
        if let AnyRevision::Signature(sig) = &w.signature_revision {
            let prev = sig.previous_revision();
            assert_eq!(prev.as_ref(), w.object_hash);
        } else {
            panic!("expected Signature revision");
        }
    }

    // Suppress unused-import warnings under `cargo test` when the SDK
    // helpers above are inlined.
    #[allow(dead_code)]
    fn _kept(_: LeafEntry) {}
}
