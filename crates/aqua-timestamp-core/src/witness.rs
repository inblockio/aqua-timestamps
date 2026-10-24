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
//! The batch is the SDK's (PCA-0015 section 3.8): [`EpochBatch::prepare`]
//! calls `prepare_batch_timestamp` (one target per leaf, one shielding nonce
//! per leaf, the shielded RFC 9162 tree and its `0x1620` root), the sealer
//! anchors [`EpochBatch::anchor_root`] once per method, and
//! [`mint_witnesses_for_epoch`] calls `finish_batch_timestamp` with each
//! method's anchor facts, which builds every TimestampObject. Nothing in this
//! crate computes a batch leaf, root, proof or nonce.

use std::sync::Arc;

use aqua_rs_sdk::{
    core::timestamp::{finish_batch_timestamp, prepare_batch_timestamp, PreparedBatch},
    primitives::{merkle::parse_batch_root, multihash_decode, HashType, Method, RevisionLink},
    schema::{
        template::BuiltInTemplate, templates::TsaTimestampPayload, timestamp::TimestampValue,
        tree::Tree, AnyRevision, AquaTreeWrapper, Object,
    },
    verification::Linkable,
    Secp256k1Signer, Signer,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::accumulator::{LeafEntry, SealedSnapshot};
use crate::merkle::Hash32;

/// The `network` value of every qTSA payload: the SDK's TSA timestamp
/// template fixes it (`src/schema/templates/timestamp_tsa.json`,
/// `"network": {"const": "tsa"}`) and `finish_batch_timestamp` builds a TSA
/// payload only for this label (audit G).
pub const QTSA_NETWORK_LABEL: &str = "tsa";

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

    /// Inverse of [`Self::method_byte`]; `None` for an unknown byte.
    pub fn from_method_byte(byte: u8) -> Option<Self> {
        match byte {
            METHOD_BYTE_EVM => Some(AnchorMethod::Evm),
            METHOD_BYTE_QTSA => Some(AnchorMethod::Qtsa),
            _ => None,
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
    #[error("witness batch failed: {0}")]
    Batch(String),
    #[error("witness signature failed: {0}")]
    Sign(String),
    #[error("witness payload serialise failed: {0}")]
    Serialise(#[from] serde_json::Error),
    #[error("hash conversion: expected 32 bytes, got {0}")]
    BadHash(usize),
}

/// Per-method anchor result the seal-time witness minter hands to the SDK's
/// `finish_batch_timestamp` as the anchor facts of every per-leaf
/// TimestampObject of the matching method.
///
/// The fields mirror the anchor-derived part of the SDK's [`TimestampValue`];
/// the batch fields (`merkle_root`, `merkle_proof`, `batch_tree_size`,
/// `batch_leaf_index`, `shielding_nonce`) belong to the SDK's prepared batch.
///
/// Outcomes come only from a live anchor provider (`CliEthTimestamper` for
/// EVM, `TsaTimestamper` for qTSA). There is no placeholder outcome: a
/// missing or failed provider leaves the method pending (decision D51).
#[derive(Debug, Clone)]
pub struct MethodAnchorOutcome {
    /// The `0x` + 64-hex transaction id (EVM), the base64 `TimeStampResp` (qTSA).
    pub transaction_hash: String,
    /// The `0x` + 40-hex EIP-55 sender address (EVM), the TSA name (qTSA).
    pub sender_account_address: String,
    /// EVM contract address. For qTSA this is the TSA URL (the SDK overloads
    /// the field); qTSA payloads do not carry it.
    pub smart_contract_address: String,
    /// `"sepolia"` / `"mainnet"` etc. for EVM. A qTSA payload always carries
    /// [`QTSA_NETWORK_LABEL`], whatever this field says.
    pub network: String,
    /// For qTSA only: the provider name.
    pub tsa_provider: String,
    /// The anchor's own time as the provider returned it: the TSA token's
    /// genTime for qTSA (the SDK binds `payloads.timestamp` to it, audit B),
    /// the provider's time for EVM.
    pub timestamp: u64,
}

impl MethodAnchorOutcome {
    /// The outcome of `method` from a provider's [`TimestampValue`].
    pub fn from_value(method: AnchorMethod, value: &TimestampValue) -> Self {
        match method {
            AnchorMethod::Evm => Self::from_evm_timestamp_value(value),
            AnchorMethod::Qtsa => Self::from_tsa_timestamp_value(value),
        }
    }

    /// Build an EVM outcome from a [`TimestampValue`] returned by a live
    /// provider. Only the anchor-derived fields are pulled across; the batch
    /// fields come from the SDK's prepared batch.
    pub fn from_evm_timestamp_value(value: &TimestampValue) -> Self {
        Self {
            transaction_hash: value.transaction_hash.clone(),
            sender_account_address: value.sender_account_address.clone(),
            smart_contract_address: value.smart_contract_address.clone(),
            network: value.network.clone(),
            tsa_provider: String::new(),
            timestamp: value.timestamp,
        }
    }

    /// Build a qTSA outcome from a [`TimestampValue`] returned by a live
    /// RFC 3161 provider (the SDK's `TsaTimestamper`). The TSA value carries
    /// the base64 `TimeStampResp` in `transaction_hash`, the publisher name
    /// in `tsa_provider`, the request URL in `smart_contract_address` and
    /// the token's genTime in `timestamp`.
    pub fn from_tsa_timestamp_value(value: &TimestampValue) -> Self {
        let sender = if value.sender_account_address.is_empty() {
            value.tsa_provider.clone()
        } else {
            value.sender_account_address.clone()
        };
        Self {
            transaction_hash: value.transaction_hash.clone(),
            sender_account_address: sender,
            smart_contract_address: value.smart_contract_address.clone(),
            network: QTSA_NETWORK_LABEL.to_string(),
            tsa_provider: value.tsa_provider.clone(),
            timestamp: value.timestamp,
        }
    }

    /// The anchor facts `finish_batch_timestamp` takes for `method`: this
    /// outcome's fields, the anchored root, and the provider's time. The batch
    /// fields are left empty; finish ignores them and writes the prepared
    /// batch's own.
    fn facts(&self, method: AnchorMethod, merkle_root: &str) -> TimestampValue {
        let (sender, network) = match method {
            AnchorMethod::Evm => (
                ensure_0x(&self.sender_account_address),
                self.network.clone(),
            ),
            AnchorMethod::Qtsa => (
                self.sender_account_address.clone(),
                QTSA_NETWORK_LABEL.to_string(),
            ),
        };
        TimestampValue::new(
            Vec::new(),
            sender,
            self.tsa_provider.clone(),
            self.transaction_hash.clone(),
            self.smart_contract_address.clone(),
            network,
            merkle_root.to_string(),
            self.timestamp,
            0,
            0,
            String::new(),
        )
    }
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

/// One epoch's batch as the SDK prepared it: one target per accepted leaf
/// (in the snapshot's order), each with its shielding nonce and inclusion
/// proof, and the shielded root every anchor of the epoch carries.
///
/// The aggregator holds only the client's leaf (a revision link), not the
/// client's tree, while the SDK's batch producer takes trees. Each target is
/// therefore handed over in a link-only carrier tree (see
/// [`link_only_carrier`]); the producer reads nothing from it but the
/// target's presence, and the minter keeps only the timestamp revision the
/// producer adds.
pub struct EpochBatch {
    prepared: PreparedBatch,
    leaves: Vec<Hash32>,
    carriers: Vec<AquaTreeWrapper>,
}

impl EpochBatch {
    /// Prepare the batch of `leaves` through `prepare_batch_timestamp`.
    /// `None` for an empty epoch: there is nothing to anchor.
    pub fn prepare(leaves: &[Hash32]) -> Result<Option<Self>, WitnessError> {
        if leaves.is_empty() {
            return Ok(None);
        }
        let carriers: Vec<AquaTreeWrapper> = leaves.iter().map(link_only_carrier).collect();
        let prepared = prepare_batch_timestamp(&carriers, None)
            .map_err(|e| WitnessError::Batch(format!("prepare_batch_timestamp: {e:?}")))?;
        Ok(Some(Self {
            prepared,
            leaves: leaves.to_vec(),
            carriers,
        }))
    }

    /// The batch root in its wire form (`0x1620` + digest): the value every
    /// anchor of the epoch must carry. An EVM provider sends it as
    /// `PreparedBatch::evm_calldata` (selector + root); a TSA stamps it.
    pub fn anchor_root(&self) -> &str {
        self.prepared.merkle_root()
    }

    /// The bare 32-byte digest of [`Self::anchor_root`], as the epoch record
    /// stores it.
    pub fn root_digest(&self) -> Result<Hash32, WitnessError> {
        parse_batch_root(self.prepared.merkle_root())
            .map_err(|e| WitnessError::Batch(format!("batch root: {e:?}")))
    }

    /// The leaves in batch order.
    pub fn leaves(&self) -> &[Hash32] {
        &self.leaves
    }

    /// Rebuild a batch from a stored [`PreparedBatch`] and its leaves (in
    /// batch order), so a pending method can be anchored and finished later
    /// for the same root. Nothing is recomputed here: the carriers are the
    /// same link-only trees [`Self::prepare`] built, and
    /// `finish_batch_timestamp` itself re-derives the root from the stored
    /// targets and nonces and refuses a batch that does not follow.
    pub fn from_parts(prepared: PreparedBatch, leaves: Vec<Hash32>) -> Self {
        let carriers = leaves.iter().map(link_only_carrier).collect();
        Self {
            prepared,
            leaves,
            carriers,
        }
    }

    /// The SDK's prepared batch (serde), as persisted for a pending method.
    pub fn prepared(&self) -> &PreparedBatch {
        &self.prepared
    }
}

/// One sealed epoch whose anchor is still outstanding for `methods`
/// (decision D51): the anchor call failed, so those methods' witnesses are
/// not minted yet. Persisted by the store so every later tick, also after a
/// restart, retries anchoring the SAME root: `batch` is the SDK's own
/// [`PreparedBatch`] (root, per-leaf targets, shielding nonces and proofs,
/// serde as the SDK defines it) and `leaves` carries what minting needs
/// besides it (the leaf and its submitter, in batch order).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingEpoch {
    pub epoch_id: u64,
    pub opened_at: u64,
    pub closed_at: u64,
    /// Methods still to anchor and mint, in the configured order.
    pub methods: Vec<AnchorMethod>,
    pub leaves: Vec<PendingLeaf>,
    pub batch: PreparedBatch,
    /// Anchors that succeeded but whose witnesses are not served yet (OW1.4):
    /// stored before minting, so a mint, save or not-yet-final self-check
    /// retries from the same anchor and never spends a second transaction or
    /// token for this root. Removed when the method's witnesses are served,
    /// or discarded when the self-check finds the anchor itself at fault.
    #[serde(default)]
    pub anchors: Vec<StoredAnchor>,
}

/// One method's successful anchor of a [`PendingEpoch`]'s root, as the
/// provider returned it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAnchor {
    pub method: AnchorMethod,
    pub value: TimestampValue,
    /// Seal-tick time (unix seconds) the anchor was stored, or first judged
    /// for a record written before OW1.6 (missing field: treated as that
    /// first judgement's time). An EVM anchor whose transaction stays not
    /// found past the not-found timeout is discarded (OW1.6 H2).
    #[serde(default)]
    pub first_seen: Option<u64>,
}

/// A leaf of a [`PendingEpoch`]: `0x` + 64 hex, and its submitter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingLeaf {
    pub leaf: String,
    pub submitter_did: String,
}

impl PendingEpoch {
    /// Record `methods` of `snapshot` as pending on `batch`.
    pub fn new(snapshot: &SealedSnapshot, batch: &EpochBatch, methods: Vec<AnchorMethod>) -> Self {
        Self {
            epoch_id: snapshot.epoch_id,
            opened_at: snapshot.opened_at,
            closed_at: snapshot.closed_at,
            methods,
            leaves: snapshot
                .leaves
                .iter()
                .map(|e| PendingLeaf {
                    leaf: hex_lower_bytes(&e.leaf),
                    submitter_did: e.submitter_did.clone(),
                })
                .collect(),
            batch: batch.prepared.clone(),
            anchors: Vec::new(),
        }
    }

    /// The stored anchor of `method`, if one succeeded and is kept.
    pub fn anchor(&self, method: AnchorMethod) -> Option<&TimestampValue> {
        self.anchors
            .iter()
            .find(|a| a.method == method)
            .map(|a| &a.value)
    }

    /// Store (or replace) `method`'s anchor, first seen at `now`.
    pub fn set_anchor(&mut self, method: AnchorMethod, value: TimestampValue, now: u64) {
        self.drop_anchor(method);
        self.anchors.push(StoredAnchor {
            method,
            value,
            first_seen: Some(now),
        });
    }

    /// When `method`'s stored anchor was first seen; a record written
    /// before OW1.6 gets `now` (written into the record, `true` when it
    /// changed and needs saving).
    pub fn anchor_first_seen(&mut self, method: AnchorMethod, now: u64) -> Option<(u64, bool)> {
        let a = self.anchors.iter_mut().find(|a| a.method == method)?;
        match a.first_seen {
            Some(t) => Some((t, false)),
            None => {
                a.first_seen = Some(now);
                Some((now, true))
            }
        }
    }

    /// Discard `method`'s stored anchor.
    pub fn drop_anchor(&mut self, method: AnchorMethod) {
        self.anchors.retain(|a| a.method != method);
    }

    /// The anchored root every method of this epoch carries.
    pub fn anchor_root(&self) -> &str {
        self.batch.merkle_root()
    }

    /// The 32-byte leaves, in batch order.
    pub fn leaf_hashes(&self) -> Result<Vec<Hash32>, WitnessError> {
        self.leaves
            .iter()
            .map(|l| {
                let bytes = hex::decode(l.leaf.trim_start_matches("0x"))
                    .map_err(|e| WitnessError::Batch(format!("pending leaf hex: {e}")))?;
                <Hash32>::try_from(bytes.as_slice()).map_err(|_| WitnessError::BadHash(bytes.len()))
            })
            .collect()
    }

    /// The sealed snapshot and the batch, rebuilt for minting.
    pub fn restore(&self) -> Result<(SealedSnapshot, EpochBatch), WitnessError> {
        let leaves = self.leaf_hashes()?;
        let snapshot = SealedSnapshot {
            epoch_id: self.epoch_id,
            opened_at: self.opened_at,
            closed_at: self.closed_at,
            leaves: leaves
                .iter()
                .zip(self.leaves.iter())
                .map(|(leaf, l)| LeafEntry {
                    leaf: *leaf,
                    submitter_did: l.submitter_did.clone(),
                })
                .collect(),
        };
        Ok((snapshot, EpochBatch::from_parts(self.batch.clone(), leaves)))
    }
}

/// A tree that holds only the key of `leaf`, aimed at it, so the SDK's batch
/// producer accepts the leaf as a target. The value under the key is an inert
/// placeholder that no output carries: `finish_batch_timestamp` only checks
/// that the tree contains its target, and the minter takes from the result
/// nothing but the timestamp revision the producer added.
fn link_only_carrier(leaf: &Hash32) -> AquaTreeWrapper {
    let link = RevisionLink::from_bytes(*leaf);
    let placeholder = Object::<serde_json::Value>::new(
        RevisionLink::from_bytes([0u8; 32]),
        RevisionLink::from_bytes(TsaTimestampPayload::TEMPLATE_LINK),
        Method::Scalar,
        serde_json::Value::Null,
    );
    let tree = Tree {
        revisions: [(link.clone(), AnyRevision::Typed(placeholder))]
            .into_iter()
            .collect(),
        file_index: Default::default(),
    };
    AquaTreeWrapper::new(tree, None, Some(link))
}

/// Mint every witness revision of a sealed epoch.
///
/// Inputs:
/// * `snapshot` : the just-closed accumulator output (leaves and submitter
///   DIDs).
/// * `batch` : the SDK batch prepared over the snapshot's leaves, whose
///   [`EpochBatch::anchor_root`] the sealer anchored.
/// * `method_outcomes` : per-method anchor result, in deterministic
///   iteration order. Each is handed to `finish_batch_timestamp` once, which
///   builds one TimestampObject per leaf.
/// * `signer` : the service's secp256k1 signer.
///
/// Witnesses are produced in deterministic order: leaves in batch order,
/// methods in the order given. The storage layer writes the whole list
/// through a single fjall batch.
pub async fn mint_witnesses_for_epoch(
    snapshot: &SealedSnapshot,
    batch: &EpochBatch,
    method_outcomes: &[(AnchorMethod, MethodAnchorOutcome)],
    signer: Arc<Secp256k1Signer>,
) -> Result<Vec<MintedWitness>, WitnessError> {
    if snapshot.leaves.len() != batch.leaves.len()
        || snapshot
            .leaves
            .iter()
            .zip(batch.leaves.iter())
            .any(|(entry, leaf)| &entry.leaf != leaf)
    {
        return Err(WitnessError::Batch(
            "prepared batch does not hold the snapshot's leaves in order".into(),
        ));
    }

    // One finish per method: per method, one timestamp object per leaf.
    let mut objects: Vec<Vec<(RevisionLink, AnyRevision)>> = Vec::new();
    for (method, outcome) in method_outcomes {
        let facts = outcome.facts(*method, batch.anchor_root());
        let results = finish_batch_timestamp(
            &batch.prepared,
            &batch.carriers,
            facts,
            Method::Scalar,
            None,
        )
        .map_err(|e| WitnessError::Batch(format!("finish_batch_timestamp: {e:?}")))?;
        let per_leaf = results
            .into_iter()
            .zip(batch.leaves.iter())
            .map(|(op, leaf)| added_timestamp(op.aqua_tree, leaf))
            .collect::<Result<Vec<_>, _>>()?;
        objects.push(per_leaf);
    }

    let mut out = Vec::with_capacity(snapshot.leaves.len() * method_outcomes.len());
    for (i, entry) in snapshot.leaves.iter().enumerate() {
        for (m, (method, _)) in method_outcomes.iter().enumerate() {
            let (object_link, object_revision) = objects[m][i].clone();
            out.push(
                sign_witness(
                    &entry.leaf,
                    &entry.submitter_did,
                    snapshot.epoch_id,
                    *method,
                    object_link,
                    object_revision,
                    signer.as_ref(),
                )
                .await?,
            );
        }
    }
    Ok(out)
}

/// The one revision `finish_batch_timestamp` added to a carrier: a typed
/// timestamp object chained to `leaf`.
fn added_timestamp(tree: Tree, leaf: &Hash32) -> Result<(RevisionLink, AnyRevision), WitnessError> {
    let leaf_link = RevisionLink::from_bytes(*leaf);
    let mut added = tree.revisions.into_iter().filter(|(k, _)| k != &leaf_link);
    let (link, revision) = added
        .next()
        .ok_or_else(|| WitnessError::Object("batch producer added no revision".into()))?;
    if added.next().is_some() {
        return Err(WitnessError::Object(
            "batch producer added more than one revision".into(),
        ));
    }
    match &revision {
        AnyRevision::Typed(obj) if obj.previous_revision() == Some(&leaf_link) => {}
        _ => {
            return Err(WitnessError::Object(
                "batch producer's revision is not a timestamp object on the leaf".into(),
            ))
        }
    }
    Ok((link, revision))
}

async fn sign_witness(
    leaf: &Hash32,
    submitter_did: &str,
    epoch_id: u64,
    method: AnchorMethod,
    object_link: RevisionLink,
    object_revision: AnyRevision,
    signer: &Secp256k1Signer,
) -> Result<MintedWitness, WitnessError> {
    let object_hash = revision_link_to_hash(&object_link)?;

    let signature_revision = signer
        .sign_revision(&object_link, Method::Scalar, HashType::Sha3_256)
        .await
        .map_err(|e| WitnessError::Sign(format!("{e:?}")))?;
    let signature_link = signature_revision
        .calculate_link(HashType::Sha3_256)
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
        object_revision,
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

/// Digest of a SHA3-256 `RevisionLink`. Since `aqua-rs-sdk` 5.0.0 a link is
/// the full multihash (`0x16 0x20` + digest, PCA-0015 §3.5); storage keeps the
/// bare digest, which loses nothing while every link here is SHA3-256.
fn revision_link_to_hash(link: &RevisionLink) -> Result<Hash32, WitnessError> {
    let bytes = link.as_ref();
    let (hash_type, digest) =
        multihash_decode(bytes).map_err(|_| WitnessError::BadHash(bytes.len()))?;
    if hash_type != HashType::Sha3_256 {
        return Err(WitnessError::BadHash(bytes.len()));
    }
    digest
        .try_into()
        .map_err(|_| WitnessError::BadHash(bytes.len()))
}

/// Wire form of a stored revision digest: the SDK's `RevisionLink` string
/// (`0x1620` + digest). This is what the revisions inside a tree reference in
/// `previous_revision`, so tree keys and tip lists must use it too.
pub fn revision_wire_hex(digest: &Hash32) -> String {
    RevisionLink::from_bytes(*digest).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accumulator::Accumulator;
    use aqua_rs_sdk::primitives::merkle::{
        parse_batch_digest, parse_batch_proof, shielded_leaf, verify_batch_inclusion,
    };

    const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";

    async fn build_signer() -> Arc<Secp256k1Signer> {
        let (_addr, _eip55, pk_hex) = aqua_evm_provider::get_wallet(TEST_MNEMONIC).await.unwrap();
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

    fn canned_outcomes() -> Vec<(AnchorMethod, MethodAnchorOutcome)> {
        let evm = MethodAnchorOutcome {
            transaction_hash: format!("0x{}", "ab".repeat(32)),
            sender_account_address: "0xCAFE000000000000000000000000000000000000".into(),
            smart_contract_address: "0xDEAD000000000000000000000000000000000000".into(),
            network: "sepolia".into(),
            tsa_provider: String::new(),
            timestamp: 60,
        };
        let qtsa = MethodAnchorOutcome {
            transaction_hash: "AAAA".into(),
            sender_account_address: "Test TSA".into(),
            smart_contract_address: "http://tsa.test/".into(),
            network: QTSA_NETWORK_LABEL.into(),
            tsa_provider: "Test TSA".into(),
            timestamp: 60,
        };
        vec![(AnchorMethod::Evm, evm), (AnchorMethod::Qtsa, qtsa)]
    }

    fn snapshot_of(id: u64, leaves: &[Hash32]) -> (SealedSnapshot, EpochBatch) {
        let acc = Accumulator::new(id, 0, 60);
        acc.append_batch(leaves, "did:pkh:eip155:1:0xAAAA");
        let snap = acc.swap_and_open_next(60, 60, 60);
        let batch_leaves: Vec<Hash32> = snap.leaves.iter().map(|e| e.leaf).collect();
        let batch = EpochBatch::prepare(&batch_leaves)
            .unwrap()
            .expect("non-empty");
        (snap, batch)
    }

    fn payloads(w: &MintedWitness) -> serde_json::Value {
        match &w.object_revision {
            AnyRevision::Typed(obj) => serde_json::to_value(obj).unwrap()["payloads"].clone(),
            _ => panic!("expected Typed"),
        }
    }

    #[test]
    fn empty_epoch_prepares_no_batch() {
        assert!(EpochBatch::prepare(&[]).unwrap().is_none());
    }

    #[tokio::test]
    async fn mint_produces_two_revisions_per_leaf_per_method() {
        let leaves: Vec<Hash32> = (1u8..=3).map(|i| [i; 32]).collect();
        let (snap, batch) = snapshot_of(7, &leaves);
        let witnesses =
            mint_witnesses_for_epoch(&snap, &batch, &canned_outcomes(), build_signer().await)
                .await
                .unwrap();
        assert_eq!(witnesses.len(), 6);

        // Every witness proves its leaf into the anchored root, judged by the
        // SDK's batch inclusion check (shielded leaf, RFC 9162 path).
        let root = batch.root_digest().unwrap();
        for w in &witnesses {
            let p = payloads(w);
            assert_eq!(p["merkle_root"].as_str().unwrap(), batch.anchor_root());
            let nonce = parse_batch_digest(p["shielding_nonce"].as_str().unwrap()).unwrap();
            let leaf = shielded_leaf(&RevisionLink::from_bytes(w.leaf), &nonce).unwrap();
            let proof = parse_batch_proof(&p["merkle_proof"]).unwrap();
            verify_batch_inclusion(
                &leaf,
                p["batch_leaf_index"].as_u64().unwrap(),
                p["batch_tree_size"].as_u64().unwrap(),
                &proof,
                &root,
            )
            .expect("inclusion proof verifies against the anchored root");
        }
    }

    #[tokio::test]
    async fn witness_chains_to_client_leaf() {
        let leaf: Hash32 = [0x99; 32];
        let (snap, batch) = snapshot_of(2, &[leaf]);
        let outcomes = vec![canned_outcomes().remove(0)];
        let witnesses = mint_witnesses_for_epoch(&snap, &batch, &outcomes, build_signer().await)
            .await
            .unwrap();
        assert_eq!(witnesses.len(), 1);
        let w = &witnesses[0];
        if let AnyRevision::Typed(obj) = &w.object_revision {
            let prev = obj
                .previous_revision()
                .expect("witness object must have a previous_revision");
            assert_eq!(revision_link_to_hash(prev).unwrap(), leaf);
        } else {
            panic!("expected Typed object revision");
        }
        if let AnyRevision::Signature(sig) = &w.signature_revision {
            let prev = sig.previous_revision();
            assert_eq!(revision_link_to_hash(prev).unwrap(), w.object_hash);
        } else {
            panic!("expected Signature revision");
        }
    }

    #[tokio::test]
    async fn payload_folds_anchor_outcome_fields() {
        let leaf: Hash32 = [0xAB; 32];
        let (snap, batch) = snapshot_of(3, &[leaf]);
        let canned = MethodAnchorOutcome {
            transaction_hash: "0xfeedface00000000000000000000000000000000000000000000000000000000"
                .into(),
            sender_account_address: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            smart_contract_address: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            network: "sepolia".into(),
            tsa_provider: String::new(),
            timestamp: 1234,
        };
        let tsa = MethodAnchorOutcome {
            network: "operator-label".into(),
            tsa_provider: "Some TSA".into(),
            timestamp: 5678,
            ..canned.clone()
        };
        let outcomes = vec![
            (AnchorMethod::Evm, canned.clone()),
            (AnchorMethod::Qtsa, tsa),
        ];
        let ws = mint_witnesses_for_epoch(&snap, &batch, &outcomes, build_signer().await)
            .await
            .unwrap();
        let p = payloads(&ws[0]);
        assert_eq!(p["transaction_hash"], canned.transaction_hash.as_str());
        assert_eq!(
            p["sender_account_address"],
            canned.sender_account_address.as_str()
        );
        assert_eq!(
            p["smart_contract_address"],
            canned.smart_contract_address.as_str()
        );
        assert_eq!(p["network"], "sepolia");
        assert_eq!(p["timestamp"], 1234);
        let q = payloads(&ws[1]);
        assert_eq!(q["network"], QTSA_NETWORK_LABEL);
        assert_eq!(q["tsa_provider"], "Some TSA");
        assert_eq!(
            q["timestamp"], 5678,
            "qTSA payload carries the anchor's time"
        );
    }
}
