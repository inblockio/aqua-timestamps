//! Pre-serve self-check (OW1.4): before a minted witness is written to the
//! serving partitions, the aggregator verifies it with the SDK.
//!
//! The aggregator holds only the client's leaf link, never the client tree,
//! and the SDK pinned here (b8859a16) has no detached witness verifier: a
//! full-tree verify of a link-only tree stops at `DanglingPath`
//! (`src/core/partition.rs:73`), and the pipeline's own Stage 2.5 inclusion
//! check and schema check are `pub(crate)`. [`verify_minted_witness`]
//! therefore composes the SDK's PUBLIC per-check functions. Nothing here
//! computes a hash, a proof or a signature check itself (SDK ask filed at
//! OW1.7: a public detached `verify_witness`).

use std::sync::Arc;

use aqua_rs_sdk::{
    core::{
        evm_anchor::{
            judge_evm_anchor, EvmAnchorClaim, EvmAnchorInvalidReason, EvmAnchorNotEvaluableReason,
            EvmAnchorVerdict, EvmFinalityRequirement,
        },
        signature::{classify_signature_leaf, LeafVerdict},
    },
    primitives::{merkle, HashType, RevisionLink},
    schema::AnyRevision,
    verification::Linkable,
    BlockchainHost, QualifiedVerifyLevel, WebHost,
};

use crate::witness::{AnchorMethod, MintedWitness};

/// The hosts the self-check asks for external facts, and the EVM finality a
/// witness needs before it is served.
#[derive(Clone)]
pub struct SelfCheckHosts {
    /// Chain host the EVM anchor is judged against (production:
    /// `aqua_evm_provider::EthBlockchainHost` on the configured RPC URL).
    /// Required when the EVM method is enabled.
    pub blockchain: Option<Arc<dyn BlockchainHost>>,
    /// TSA host the qTSA token is judged by (production:
    /// `aqua_tsa_provider::TsaWebHost::new()`, the reader's default EU trust
    /// list validation). Required when the qTSA method is enabled.
    pub tsa: Option<Arc<dyn WebHost>>,
    /// EVM finality a witness needs before it is served. Default
    /// [`EvmFinalityRequirement::Finalized`]: the SDK reader's own default
    /// requirement, and the only level at which the timestamp template's
    /// `blockchain_verify_tx` import answers success
    /// (`EvmAnchorVerdict::import_code`) and a verified time exists
    /// (`EvmAnchorVerdict::verified_time`). A witness served earlier would
    /// not verify for a default reader.
    pub evm_finality: EvmFinalityRequirement,
}

impl Default for SelfCheckHosts {
    fn default() -> Self {
        Self {
            blockchain: None,
            tsa: None,
            evm_finality: EvmFinalityRequirement::Finalized,
        }
    }
}

/// The self-check's answer for one witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfCheckVerdict {
    /// Every covered check passed: the witness may be served.
    Verified,
    /// No verdict yet (EVM known but not included, not final, host
    /// unavailable). Not an error: the method stays pending, the stored anchor is
    /// kept and re-checked next tick without re-anchoring.
    NotYet(String),
    /// Like [`Self::NotYet`], but the node does not know the EVM anchor's
    /// transaction (not found). Kept like `NotYet` until the anchor is older
    /// than the not-found timeout; then it is treated as dropped or reorged
    /// out, discarded and re-anchored (OW1.6 H2). A transaction known but
    /// not in a block is `NotYet`, never times out (it holds its nonce).
    Missing(String),
    /// A check failed. `anchor_at_fault` is true only when the anchor itself
    /// does not hold (the token does not verify, the transaction does not
    /// carry this root from this sender to this contract, or reverted): the
    /// stored anchor is then discarded and the next tick re-anchors. Every
    /// other failure keeps the anchor (re-anchoring the same root would not
    /// change it) and retries minting from it.
    Failed {
        reason: String,
        anchor_at_fault: bool,
    },
}

impl SelfCheckVerdict {
    fn failed(reason: impl Into<String>) -> Self {
        Self::Failed {
            reason: reason.into(),
            anchor_at_fault: false,
        }
    }
    fn anchor_failed(reason: impl Into<String>) -> Self {
        Self::Failed {
            reason: reason.into(),
            anchor_at_fault: true,
        }
    }
}

/// Verify one minted witness (timestamp revision plus service signature over
/// it) with the SDK's public per-check functions.
///
/// Covered, in order (first failure wins):
/// 1. content hash: the timestamp revision hashes to its own key
///    (`Linkable::calculate_link`, SHA3-256) and chains to the client's leaf
///    (`previous_revision` = leaf link);
/// 2. shielded batch inclusion of the leaf under the payload's root, exactly
///    the SDK pipeline's Stage 2.5 (`src/core/verify_common.rs:1827-1849`:
///    `parse_batch_digest` on the nonce, `parse_batch_proof`,
///    `parse_batch_root`, `shielded_leaf`, `verify_batch_inclusion`);
/// 3. the anchor: qTSA through `WebHost::verify_tsa_token` (CMS signature,
///    certificate chain, imprint of `merkle_root`, genTime equal to the
///    payload `timestamp`; level Verified or QualifiedVerified), EVM through
///    `core::evm_anchor::judge_evm_anchor` at [`SelfCheckHosts::evm_finality`];
/// 4. the signature revision: `classify_signature_leaf` (its own content hash
///    and the signature predicate) must say Verified, it signs the timestamp
///    revision (`previous_revision`), and its signer is `service_did`.
///
/// Not covered (not reachable through the SDK's public API at b8859a16):
/// timestamp template schema validation and template execution. Both are
/// covered by the full-pipeline tests (`tests/witness_sdk_verify.rs`) on
/// every build.
///
/// Synchronous: the hosts block (the EVM host uses `Handle::block_on`), so
/// async callers run it on a blocking thread.
pub fn verify_minted_witness(
    w: &MintedWitness,
    service_did: &str,
    hosts: &SelfCheckHosts,
) -> SelfCheckVerdict {
    let payloads = match content_and_inclusion(w) {
        Ok(p) => p,
        Err(v) => return v,
    };
    let anchor = judge_anchor(w.method, payloads, hosts);
    if anchor != SelfCheckVerdict::Verified {
        return anchor;
    }
    service_signature(w, service_did)
}

/// The payload fields a witness takes from its method's anchor and the
/// batch root: equal in every witness of one (epoch, method).
const ANCHOR_FIELDS: [&str; 7] = [
    "network",
    "transaction_hash",
    "merkle_root",
    "smart_contract_address",
    "sender_account_address",
    "tsa_provider",
    "timestamp",
];

fn anchor_fields(payloads: &serde_json::Value) -> Vec<Option<&serde_json::Value>> {
    ANCHOR_FIELDS.iter().map(|k| payloads.get(*k)).collect()
}

/// [`verify_minted_witness`] over every witness of one (epoch, method),
/// judging the anchor once (OW1.6 H1): the anchor of the first witness is
/// judged after its content hash and inclusion pass (one chain lookup or one
/// token check per tick, never one per witness); every witness then gets
/// checks 1 and 4, and its anchor fields must equal the judged witness's.
/// An anchor that is not Verified settles the batch: every witness gets that
/// verdict, without per-witness work. Always one verdict per witness.
pub fn verify_minted_batch(
    ws: &[MintedWitness],
    service_did: &str,
    hosts: &SelfCheckHosts,
) -> Vec<SelfCheckVerdict> {
    let Some(first) = ws.first() else {
        return Vec::new();
    };
    let settled = |v: SelfCheckVerdict| vec![v; ws.len()];
    let judged = match content_and_inclusion(first) {
        Ok(p) => p,
        Err(v) => return settled(v),
    };
    let anchor = judge_anchor(first.method, judged, hosts);
    if anchor != SelfCheckVerdict::Verified {
        return settled(anchor);
    }
    let judged = anchor_fields(judged);
    ws.iter()
        .map(|w| {
            let payloads = match content_and_inclusion(w) {
                Ok(p) => p,
                Err(v) => return v,
            };
            if w.method != first.method || anchor_fields(payloads) != judged {
                return SelfCheckVerdict::failed("anchor fields differ from the judged anchor");
            }
            service_signature(w, service_did)
        })
        .collect()
}

/// Checks 1 and 2 of [`verify_minted_witness`]; the payloads on success.
fn content_and_inclusion(w: &MintedWitness) -> Result<&serde_json::Value, SelfCheckVerdict> {
    let leaf_link = RevisionLink::from_bytes(w.leaf);
    let object_link = RevisionLink::from_bytes(w.object_hash);

    // 1. Content hash and chain of the timestamp revision.
    let AnyRevision::Typed(object) = &w.object_revision else {
        return Err(SelfCheckVerdict::failed(
            "timestamp revision is not a typed object",
        ));
    };
    match object.calculate_link(HashType::Sha3_256) {
        Ok(link) if link == object_link => {}
        Ok(_) => {
            return Err(SelfCheckVerdict::failed(
                "timestamp revision does not hash to its key",
            ))
        }
        Err(e) => {
            return Err(SelfCheckVerdict::failed(format!(
                "timestamp revision hash: {e:?}"
            )))
        }
    }
    if object.previous_revision() != Some(&leaf_link) {
        return Err(SelfCheckVerdict::failed(
            "timestamp revision does not chain to the leaf",
        ));
    }
    let payloads = object.payloads();

    // 2. Shielded batch inclusion, as verify_common.rs:1827-1849.
    if let Err(reason) = batch_inclusion(payloads, &leaf_link) {
        return Err(SelfCheckVerdict::failed(format!(
            "batch inclusion: {reason}"
        )));
    }
    Ok(payloads)
}

/// Check 3 of [`verify_minted_witness`]: the anchor.
fn judge_anchor(
    method: AnchorMethod,
    payloads: &serde_json::Value,
    hosts: &SelfCheckHosts,
) -> SelfCheckVerdict {
    match method {
        AnchorMethod::Qtsa => check_tsa(payloads, hosts),
        AnchorMethod::Evm => check_evm(payloads, hosts),
    }
}

/// Check 4 of [`verify_minted_witness`]: the service signature over the
/// timestamp revision.
fn service_signature(w: &MintedWitness, service_did: &str) -> SelfCheckVerdict {
    let object_link = RevisionLink::from_bytes(w.object_hash);
    let signature_link = RevisionLink::from_bytes(w.signature_hash);
    let AnyRevision::Signature(sig) = &w.signature_revision else {
        return SelfCheckVerdict::failed("signature revision is not a signature");
    };
    match classify_signature_leaf(sig, &signature_link) {
        Ok(LeafVerdict::Verified) => {}
        Ok(other) => return SelfCheckVerdict::failed(format!("signature: {other:?}")),
        Err(e) => return SelfCheckVerdict::failed(format!("signature: {e:?}")),
    }
    if sig.previous_revision() != &object_link {
        return SelfCheckVerdict::failed("signature does not sign the timestamp revision");
    }
    if sig.signer() != service_did {
        return SelfCheckVerdict::failed(format!(
            "signature signer {} is not the service DID {service_did}",
            sig.signer()
        ));
    }
    SelfCheckVerdict::Verified
}

/// The SDK's Stage 2.5 inclusion check, composed from its public merkle
/// primitives in the order `verify_batch_inclusion` (verify_common.rs:1793)
/// applies them.
fn batch_inclusion(payloads: &serde_json::Value, target: &RevisionLink) -> Result<(), String> {
    let text = |field: &str| {
        payloads
            .get(field)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("missing {field}"))
    };
    let integer = |field: &str| {
        payloads
            .get(field)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| format!("missing {field}"))
    };
    let merkle_root = text("merkle_root")?;
    let size = integer("batch_tree_size")?;
    if size > crate::accumulator::MAX_LEAVES_PER_EPOCH as u64 {
        return Err(format!(
            "batch_tree_size {size} exceeds the template maximum {}",
            crate::accumulator::MAX_LEAVES_PER_EPOCH
        ));
    }
    let index = integer("batch_leaf_index")?;
    let proof = payloads
        .get("merkle_proof")
        .ok_or_else(|| "missing merkle_proof".to_string())?;
    let nonce = text("shielding_nonce")?;

    let nonce = merkle::parse_batch_digest(nonce).map_err(|e| format!("shielding_nonce: {e}"))?;
    let proof = merkle::parse_batch_proof(proof).map_err(|e| format!("merkle_proof: {e}"))?;
    let root = merkle::parse_batch_root(merkle_root).map_err(|e| format!("merkle_root: {e}"))?;
    let leaf = merkle::shielded_leaf(target, &nonce).map_err(|e| format!("leaf: {e}"))?;
    merkle::verify_batch_inclusion(&leaf, index, size, &proof, &root)
        .map_err(|e| format!("the inclusion proof: {e}"))
}

fn check_tsa(payloads: &serde_json::Value, hosts: &SelfCheckHosts) -> SelfCheckVerdict {
    let Some(host) = hosts.tsa.as_ref() else {
        return SelfCheckVerdict::failed("no TSA host configured for the self-check");
    };
    let field = |k: &str| payloads.get(k).and_then(serde_json::Value::as_str);
    let (Some(response), Some(root), Some(time)) = (
        field("transaction_hash"),
        field("merkle_root"),
        payloads
            .get("timestamp")
            .and_then(serde_json::Value::as_u64),
    ) else {
        return SelfCheckVerdict::failed(
            "qTSA payload lacks transaction_hash, merkle_root or timestamp",
        );
    };
    match host.verify_tsa_token(response, root, time) {
        Ok((QualifiedVerifyLevel::QualifiedVerified | QualifiedVerifyLevel::Verified, _, _)) => {
            SelfCheckVerdict::Verified
        }
        Ok((level, message, _)) => {
            SelfCheckVerdict::anchor_failed(format!("TSA token {level:?}: {message}"))
        }
        Err(e) => SelfCheckVerdict::anchor_failed(format!("TSA token: {e:?}")),
    }
}

fn check_evm(payloads: &serde_json::Value, hosts: &SelfCheckHosts) -> SelfCheckVerdict {
    let Some(host) = hosts.blockchain.as_ref() else {
        return SelfCheckVerdict::failed("no chain host configured for the self-check");
    };
    let claim = EvmAnchorClaim::from_payload(payloads);
    match judge_evm_anchor(&claim, host.as_ref(), &hosts.evm_finality) {
        EvmAnchorVerdict::Verified { .. } => SelfCheckVerdict::Verified,
        EvmAnchorVerdict::Invalid { reason } => {
            use EvmAnchorInvalidReason as R;
            let text = format!("EVM anchor invalid: {}", reason_str(&reason));
            match reason {
                // The payload is ours, not the anchor's: re-anchoring would
                // not change it and would spend a transaction every tick.
                R::MalformedClaim => SelfCheckVerdict::failed(text),
                R::ContractMismatch | R::SenderMismatch | R::InputMismatch | R::Reverted => {
                    SelfCheckVerdict::anchor_failed(text)
                }
            }
        }
        EvmAnchorVerdict::NotEvaluable { reason, finality } => {
            use EvmAnchorNotEvaluableReason as R;
            let text = format!(
                "EVM anchor not evaluable: {} ({finality:?})",
                reason.as_str()
            );
            match reason {
                // Configuration errors: nothing a later tick changes on its
                // own, but the anchor is not at fault either.
                R::UnsupportedNetwork | R::NetworkNotConfigured => SelfCheckVerdict::failed(text),
                // Only an unknown tx times out (ruled). A tx the node knows but has
                // not included keeps its nonce; a new anchor would queue behind it.
                R::NotFound => SelfCheckVerdict::Missing(text),
                _ => SelfCheckVerdict::NotYet(text),
            }
        }
    }
}

fn reason_str(reason: &EvmAnchorInvalidReason) -> String {
    serde_json::to_value(reason)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{reason:?}"))
}

/// Test doubles for the self-check: anchor providers that are also the host
/// their own anchors are judged by. Behind the `test-doubles` feature; never
/// wired by the production binary.
#[cfg(any(test, feature = "test-doubles"))]
pub mod doubles {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    use aqua_rs_sdk::{
        schema::timestamp::TimestampValue, BlockchainHost, EvmChainHead, EvmInclusion,
        EvmTransactionFacts, HostError, QualifiedVerifyLevel, TsaTokenFacts, WebHost,
    };
    use async_trait::async_trait;

    use crate::anchors::{AnchorError, AnchorProvider};

    /// Height of an anchoring block (above every supported chain's first
    /// proof-of-stake block, as the SDK test chain uses).
    const BLOCK: u64 = 20_000_100;

    fn bytes<const N: usize>(s: &str) -> Option<[u8; N]> {
        hex::decode(s.strip_prefix("0x")?).ok()?.try_into().ok()
    }

    /// A simulated EVM chain that is also the anchor provider: every
    /// `create_timestamp` returns `template` (its tx hash, sender, contract,
    /// network) and puts a transaction on the chain that carries the root,
    /// from that sender, to that contract. [`Self::set_final`] decides whether
    /// the including block is finalized or only included.
    pub struct SimChain {
        template: TimestampValue,
        txs: Mutex<HashMap<String, Vec<u8>>>,
        is_final: AtomicBool,
        dropped: AtomicBool,
        unmined: AtomicBool,
        calls: AtomicUsize,
    }

    impl SimChain {
        pub fn new(template: TimestampValue) -> Self {
            Self {
                template,
                txs: Mutex::new(HashMap::new()),
                is_final: AtomicBool::new(true),
                dropped: AtomicBool::new(false),
                unmined: AtomicBool::new(false),
                calls: AtomicUsize::new(0),
            }
        }
        pub fn set_final(&self, is_final: bool) {
            self.is_final.store(is_final, Ordering::SeqCst);
        }
        /// While set, an anchor call still returns its anchor but the
        /// transaction never reaches the chain (dropped from the mempool),
        /// and the transactions already on the chain are dropped too.
        pub fn set_dropped(&self, dropped: bool) {
            self.dropped.store(dropped, Ordering::SeqCst);
            if dropped {
                self.txs.lock().expect("sim chain").clear();
            }
        }
        /// While set, the node knows every transaction on the chain but none
        /// is in a block (facts without inclusion: the SDK's `NotIncluded`).
        pub fn set_unmined(&self, unmined: bool) {
            self.unmined.store(unmined, Ordering::SeqCst);
        }
        /// Number of anchor calls (`create_timestamp`) so far.
        pub fn anchor_calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl AnchorProvider for SimChain {
        async fn create_timestamp(
            &self,
            merkle_root_hex: &str,
        ) -> Result<TimestampValue, AnchorError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let root = merkle_root_hex
                .strip_prefix("0x")
                .and_then(|r| hex::decode(r).ok())
                .unwrap_or_default();
            // The witness selector the SDK's EVM provider calls (SDK
            // `EVM_WITNESS_SELECTOR`), then the 34-byte root.
            let mut input = vec![0x11, 0x4e, 0xe1, 0x97];
            input.extend_from_slice(&root);
            if self.dropped.load(Ordering::SeqCst) {
                let mut value = self.template.clone();
                value.merkle_root = merkle_root_hex.to_string();
                return Ok(value);
            }
            self.txs
                .lock()
                .expect("sim chain")
                .insert(self.template.transaction_hash.to_lowercase(), input);
            let mut value = self.template.clone();
            value.merkle_root = merkle_root_hex.to_string();
            Ok(value)
        }
    }

    impl BlockchainHost for SimChain {
        fn transaction_facts(
            &self,
            chain_id: u64,
            tx_hash: &str,
        ) -> Result<Option<EvmTransactionFacts>, HostError> {
            let txs = self.txs.lock().expect("sim chain");
            let Some(input) = txs.get(&tx_hash.to_lowercase()) else {
                return Ok(None);
            };
            let is_final = self.is_final.load(Ordering::SeqCst);
            Ok(Some(EvmTransactionFacts {
                chain_id,
                tx_hash: bytes::<32>(tx_hash).unwrap_or([0; 32]),
                from: bytes::<20>(&self.template.sender_account_address).unwrap_or([0; 20]),
                to: bytes::<20>(&self.template.smart_contract_address),
                input: input.clone(),
                inclusion: (!self.unmined.load(Ordering::SeqCst)).then_some(EvmInclusion {
                    block_number: if is_final { BLOCK } else { BLOCK + 60 },
                    block_hash: [0xee; 32],
                    block_time: self.template.timestamp,
                    succeeded: true,
                }),
                head: EvmChainHead {
                    latest: BLOCK + 100,
                    safe: Some(BLOCK + 50),
                    finalized: Some(BLOCK + 20),
                },
            }))
        }
    }

    /// A simulated TSA that is also the TSA host: it issues `template` as
    /// the token and remembers what it stamped (token, root, time); the host
    /// says Verified only for a token it issued, over that root, at that
    /// time. No PKI: the real token path is tested with the SDK's TSA host.
    pub struct SimTsa {
        template: TimestampValue,
        issued: Mutex<Vec<(String, String, u64)>>,
        calls: AtomicUsize,
    }

    impl SimTsa {
        pub fn new(template: TimestampValue) -> Self {
            Self {
                template,
                issued: Mutex::new(Vec::new()),
                calls: AtomicUsize::new(0),
            }
        }
        pub fn anchor_calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl AnchorProvider for SimTsa {
        async fn create_timestamp(
            &self,
            merkle_root_hex: &str,
        ) -> Result<TimestampValue, AnchorError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut value = self.template.clone();
            value.merkle_root = merkle_root_hex.to_string();
            self.issued.lock().expect("sim tsa").push((
                value.transaction_hash.clone(),
                merkle_root_hex.to_string(),
                value.timestamp,
            ));
            Ok(value)
        }
    }

    impl WebHost for SimTsa {
        fn verify_tsa_token(
            &self,
            tsa_response: &str,
            merkle_root: &str,
            timestamp: u64,
        ) -> Result<(QualifiedVerifyLevel, String, Option<TsaTokenFacts>), HostError> {
            let issued = self.issued.lock().expect("sim tsa");
            let ok = issued
                .iter()
                .any(|(t, r, ts)| t == tsa_response && r == merkle_root && *ts == timestamp);
            Ok(if ok {
                (QualifiedVerifyLevel::Verified, "sim tsa".into(), None)
            } else {
                (
                    QualifiedVerifyLevel::Failed,
                    "not issued by sim tsa".into(),
                    None,
                )
            })
        }
    }
}

#[cfg(test)]
mod cap_tests {
    use super::*;

    /// OW2.2 M2: a witness whose `batch_tree_size` is over the template
    /// maximum (2^20) fails the self-check, so it is never served.
    #[test]
    fn batch_tree_size_over_template_cap_fails() {
        let payloads = serde_json::json!({
            "merkle_root": "00",
            "batch_tree_size": 1_048_577u64,
            "batch_leaf_index": 0u64,
            "merkle_proof": [],
            "shielding_nonce": "00",
        });
        let target = RevisionLink::from_bytes([7u8; 32]);
        let err = batch_inclusion(&payloads, &target).unwrap_err();
        assert!(err.contains("batch_tree_size"), "{err}");
        assert!(err.contains("1048576"), "{err}");
    }
}
