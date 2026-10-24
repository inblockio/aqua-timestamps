//! OW1.1 red tests: a witness the aggregator mints must pass the aqua-rs-sdk verifier.
//!
//! Each test drives the real minting path (`sealer::seal_once`) with deterministic, offline
//! anchors, then judges the result with the SDK (the same `Aquafier::verify_tree_sync` a reader
//! runs, or the SDK's own TSA host). Nothing here re-implements a check.
//!
//! Anchors:
//! * EVM: [`ChainAnchor`] "sends" the root it is given to an honest simulated chain
//!   (`support/evm_chain.rs`, copied from the SDK's `tests/common/evm_chain.rs`) and returns
//!   what a real provider returns; the verifier reads the chain facts through
//!   `BlockchainHost`.
//! * qTSA: [`TestTsa`] mints an RFC 3161 token over the root it is given with the SDK's test
//!   PKI generator (`support/test_tsa.rs`) and a genTime of its own clock; the verifier checks
//!   it with the SDK's `aqua_tsa_provider::TsaWebHost` trusting only the test root.
//!
//! Blocker tags refer to the OW audit (pev seal track, `docs/track/notes/2026-10-24-ow-audit.md`):
//! A batch inclusion (shielding nonce, shielded tree, root form), B qTSA genTime binding,
//! C stub witnesses.

#[path = "support/evm_chain.rs"]
mod evm_chain;
#[path = "support/test_tsa.rs"]
mod test_tsa;

use std::path::PathBuf;
use std::sync::Arc;

use aqua_rs_sdk::primitives::Method;
use aqua_rs_sdk::schema::timestamp::TimestampValue;
use aqua_rs_sdk::schema::tree::Tree;
use aqua_rs_sdk::schema::{AnyRevision, AquaTreeWrapper, FileData};
use aqua_rs_sdk::{Aquafier, QualifiedVerifyLevel, Secp256k1Signer, VerificationResult, WebHost};
use aqua_timestamp_core::accumulator::Accumulator;
use aqua_timestamp_core::anchors::{AnchorError, AnchorProvider, FailingProvider};
use aqua_timestamp_core::sealer::{seal_once, WitnessContext};
use aqua_timestamp_core::selfcheck::{
    doubles::SimChain, verify_minted_batch, verify_minted_witness, SelfCheckHosts, SelfCheckVerdict,
};
use aqua_timestamp_core::storage::Store;
use aqua_timestamp_core::witness::{revision_wire_hex, AnchorMethod, MintedWitness};
use aqua_tsa_provider::TsaWebHost;
use async_trait::async_trait;
use base64::Engine as _;
use serde_json::Value;
use sha2::Digest as _;
use tempfile::tempdir;

const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";
const DID_A: &str = "did:pkh:eip155:1:0xaaaa000000000000000000000000000000000000";
const DID_B: &str = "did:pkh:eip155:1:0xbbbb000000000000000000000000000000000000";
/// The TSA's clock: genTime of every test token (2026-09-21T12:39:57Z).
const TSA_GEN_TIME: u64 = test_tsa::GEN_TIME as u64;
/// The epoch closes a few seconds before the TSA answers, as in production.
const EPOCH_CLOSE: u64 = TSA_GEN_TIME - 7;
const EPOCH_SECS: u64 = 60;
/// Block time of the EVM anchor transaction (after the close, as in production).
const BLOCK_TIME: u64 = TSA_GEN_TIME + 12;

// ---- deterministic anchors ------------------------------------------------------------------

/// EVM anchor on the honest simulated chain: the transaction carries exactly the root the
/// aggregator handed over, sent by `SENDER` to `CONTRACT`, finalized.
struct ChainAnchor;

#[async_trait]
impl AnchorProvider for ChainAnchor {
    async fn create_timestamp(&self, merkle_root_hex: &str) -> Result<TimestampValue, AnchorError> {
        let tx = evm_chain::anchor(
            evm_chain::NETWORK,
            evm_chain::SENDER,
            evm_chain::CONTRACT,
            merkle_root_hex,
            BLOCK_TIME,
        );
        Ok(TimestampValue::new(
            vec![],
            evm_chain::SENDER.to_string(),
            String::new(),
            tx,
            evm_chain::CONTRACT.to_string(),
            evm_chain::NETWORK.to_string(),
            merkle_root_hex.to_string(),
            BLOCK_TIME,
            1,
            0,
            String::new(),
        ))
    }
}

/// RFC 3161 TSA on the SDK test PKI: stamps `SHA-256(merkle_root)` (the imprint the SDK's
/// `verify_with_chain` expects) at its own clock, and returns what the SDK's `TsaTimestamper`
/// returns (base64 `TimeStampResp` in `transaction_hash`, genTime in `timestamp`).
struct TestTsa;

fn gen_time_octets(unix: u64) -> Vec<u8> {
    chrono::DateTime::from_timestamp(unix as i64, 0)
        .expect("time")
        .format("%Y%m%d%H%M%SZ")
        .to_string()
        .into_bytes()
}

#[async_trait]
impl AnchorProvider for TestTsa {
    async fn create_timestamp(&self, merkle_root_hex: &str) -> Result<TimestampValue, AnchorError> {
        let pki = test_tsa::pki();
        let spec = test_tsa::TokenSpec {
            imprint: sha2::Sha256::digest(merkle_root_hex.as_bytes()).to_vec(),
            gen_time: gen_time_octets(TSA_GEN_TIME),
            ..Default::default()
        };
        let token = test_tsa::token(&pki, &spec);
        let resp = test_tsa::time_stamp_resp(0, &token);
        Ok(TimestampValue::new(
            vec![],
            String::new(),
            "Aqua Test TSA".to_string(),
            base64::engine::general_purpose::STANDARD.encode(resp),
            "http://tsa.test/".to_string(),
            "tsa".to_string(),
            merkle_root_hex.to_string(),
            TSA_GEN_TIME,
            1,
            0,
            String::new(),
        ))
    }
}

/// The reader's TSA host, trusting only the test root.
fn tsa_host() -> TsaWebHost {
    TsaWebHost::with_validator(test_tsa::validator(&test_tsa::pki()))
}

// ---- aggregator fixture ---------------------------------------------------------------------

async fn signer() -> Arc<Secp256k1Signer> {
    let (_addr, _eip55, pk_hex) = aqua_evm_provider::get_wallet(TEST_MNEMONIC)
        .await
        .expect("wallet");
    let pk = hex::decode(pk_hex.trim_start_matches("0x")).expect("hex key");
    Arc::new(Secp256k1Signer::new(pk))
}

async fn ctx(
    evm: Option<Arc<dyn AnchorProvider>>,
    qtsa: Option<Arc<dyn AnchorProvider>>,
) -> WitnessContext {
    let mut ctx = WitnessContext::new(
        signer().await,
        evm_chain::SENDER.to_string(),
        vec![AnchorMethod::Evm, AnchorMethod::Qtsa],
    );
    ctx.evm_anchor = evm;
    ctx.qtsa_anchor = qtsa;
    // OW1.4: the pre-serve self-check judges with the reader's hosts.
    ctx.with_self_check(SelfCheckHosts {
        blockchain: Some(Arc::new(evm_chain::HonestChain)),
        tsa: Some(Arc::new(tsa_host())),
        ..SelfCheckHosts::default()
    })
}

/// A client's tree (one file genesis) and the file it covers. Its tip digest is the leaf.
struct ClientTree {
    tree: Tree,
    file: FileData,
    leaf: [u8; 32],
}

fn client_tree(tag: &str) -> ClientTree {
    let file = FileData::new(
        format!("{tag}.txt"),
        format!("client content {tag}").into_bytes(),
        PathBuf::from(format!("{tag}.txt")),
    );
    let tree = Aquafier::new()
        .create_genesis_revision(file.clone(), Some(Method::Scalar))
        .expect("client genesis");
    // The tip: the one revision no other revision names as its `previous_revision`.
    let json = serde_json::to_value(&tree).expect("tree json");
    let revisions = json["revisions"].as_object().expect("revisions");
    let previous: Vec<&str> = revisions
        .values()
        .filter_map(|r| r["previous_revision"].as_str())
        .collect();
    let tips: Vec<&String> = revisions
        .keys()
        .filter(|k| !previous.contains(&k.as_str()))
        .collect();
    assert_eq!(tips.len(), 1, "fixture: a linear client tree has one tip");
    let link: aqua_rs_sdk::primitives::RevisionLink = tips[0].parse().expect("tip link");
    let bytes: &[u8] = link.as_ref();
    let leaf: [u8; 32] = bytes[bytes.len() - 32..]
        .try_into()
        .expect("32-byte digest");
    ClientTree { tree, file, leaf }
}

/// Seal one epoch holding the leaves of `clients` (two submitters) through the real sealer.
async fn seal(clients: &[&ClientTree], ctx: &WitnessContext) -> Vec<MintedWitness> {
    let dir = tempdir().expect("tempdir");
    let store = Store::open(dir.path()).expect("store");
    let acc = Accumulator::new(1, EPOCH_CLOSE - EPOCH_SECS, EPOCH_SECS);
    for (i, c) in clients.iter().enumerate() {
        acc.append_batch(&[c.leaf], if i % 2 == 0 { DID_A } else { DID_B });
    }
    let (_record, witnesses) = seal_once(&acc, &store, EPOCH_CLOSE, EPOCH_SECS, Some(ctx))
        .await
        .expect("seal_once");
    witnesses
}

fn witness_for<'a>(
    ws: &'a [MintedWitness],
    leaf: &[u8; 32],
    method: AnchorMethod,
) -> &'a MintedWitness {
    ws.iter()
        .find(|w| &w.leaf == leaf && w.method == method)
        .unwrap_or_else(|| panic!("no {} witness minted for the leaf", method.as_str()))
}

fn payloads(w: &MintedWitness) -> Value {
    match &w.object_revision {
        AnyRevision::Typed(obj) => {
            serde_json::to_value(obj).expect("object json")["payloads"].clone()
        }
        other => panic!("witness object is not a typed revision: {other:?}"),
    }
}

/// The client's tree with the given witness pairs merged in (object and signature, keyed by
/// their wire links, as `GET /trees/by-leaf` serves them).
fn merged(client: &ClientTree, witnesses: &[&MintedWitness]) -> Tree {
    let mut tree = serde_json::to_value(&client.tree).expect("tree json");
    for w in witnesses {
        let obj = revision_wire_hex(&w.object_hash);
        let sig = revision_wire_hex(&w.signature_hash);
        tree["revisions"][&obj] = serde_json::to_value(&w.object_revision).expect("object");
        tree["revisions"][&sig] = serde_json::to_value(&w.signature_revision).expect("signature");
        tree["file_index"][&obj] = Value::String(w.object_file_name.clone());
        tree["file_index"][&sig] = Value::String(w.signature_file_name.clone());
    }
    serde_json::from_value(tree).expect("merged tree parses")
}

fn verify(client: &ClientTree, witnesses: &[&MintedWitness]) -> VerificationResult {
    Aquafier::builder()
        .blockchain_host(Arc::new(evm_chain::HonestChain))
        .web_host(Arc::new(tsa_host()))
        .build()
        .verify_tree_sync(
            AquaTreeWrapper::new(merged(client, witnesses), None, None),
            vec![client.file.clone()],
        )
        .expect("verification runs")
}

fn errors_of(result: &VerificationResult, revision: &str) -> Vec<String> {
    result
        .errors()
        .iter()
        .filter(|e| e.revision_hash == revision)
        .map(|e| format!("{}: {}", e.code, e.message))
        .collect()
}

fn error_logs(result: &VerificationResult) -> Vec<String> {
    result
        .logs
        .iter()
        .filter(|l| format!("{:?}", l.log_type).contains("Error"))
        .map(|l| l.log.clone())
        .collect()
}

/// The checks every minted witness pair must pass in a reader's verifier.
fn assert_witness_verifies(result: &VerificationResult, w: &MintedWitness) {
    let obj = revision_wire_hex(&w.object_hash);
    let sig = revision_wire_hex(&w.signature_hash);
    let method = w.method.as_str();
    // Blocker A: the batch fields must pass the template schema (Stage 2: `shielding_nonce`
    // must be `0x` + 64 hex, the only batch-field constraint of timestamp_base at b8859a16)
    // and prove the client's revision is in the anchored root (Stage 2.5: shielded RFC 9162
    // leaf, root form).
    let p = payloads(w);
    let inclusion: Vec<String> = errors_of(result, &obj)
        .into_iter()
        .filter(|e| e.contains("SCHEMA_VALIDATION_FAILED") || e.contains("Batch inclusion"))
        .collect();
    assert!(
        inclusion.is_empty(),
        "[A] {method} witness fails the SDK batch checks: {inclusion:#?}\nerror logs: {:#?}\n\
         batch fields: shielding_nonce={:?} merkle_root={} batch_tree_size={} batch_leaf_index={}",
        error_logs(result),
        p["shielding_nonce"],
        p["merkle_root"],
        p["batch_tree_size"],
        p["batch_leaf_index"]
    );
    // Blocker B (qTSA) / anchor check (EVM): the timestamp revision itself verifies.
    assert!(
        errors_of(result, &obj).is_empty(),
        "[{}] {method} timestamp revision fails verification: {:#?}\nerror logs: {:#?}",
        if w.method == AnchorMethod::Qtsa {
            "B"
        } else {
            "A"
        },
        errors_of(result, &obj),
        error_logs(result)
    );
    match w.method {
        AnchorMethod::Evm => {
            let verdict = result.evm_anchors.get(&obj);
            assert!(
                matches!(verdict, Some(v) if format!("{v:?}").starts_with("Verified")),
                "[A] EVM anchor verdict for the timestamp revision is not Verified: {verdict:?}"
            );
        }
        AnchorMethod::Qtsa => {
            assert!(
                result.tsa_tokens.contains_key(&obj),
                "[B] the TSA token was not admitted at Verified or QualifiedVerified: tsa_tokens={:?}",
                result.tsa_tokens
            );
        }
    }
    // The aggregator's signature over the timestamp revision verifies.
    assert!(
        errors_of(result, &sig).is_empty(),
        "{method} witness signature revision fails: {:#?}",
        errors_of(result, &sig)
    );
    assert!(
        result.is_verified(),
        "client tree with the {method} witness does not verify: {:?}\nerror logs: {:#?}",
        result.outcome,
        error_logs(result)
    );
}

async fn dual_anchor_epoch() -> (ClientTree, ClientTree, Vec<MintedWitness>) {
    let a = client_tree("ow1_leaf_a");
    let b = client_tree("ow1_leaf_b");
    let ctx = ctx(Some(Arc::new(ChainAnchor)), Some(Arc::new(TestTsa))).await;
    let ws = seal(&[&a, &b], &ctx).await;
    assert_eq!(ws.len(), 4, "fixture: two leaves x two methods");
    (a, b, ws)
}

// ---- A: batch inclusion ---------------------------------------------------------------------

/// Blocker A (EVM). Two leaves, live EVM anchor on the honest chain; each client's tree with
/// its EVM witness must verify (batch inclusion, anchor verdict Verified, signature).
#[tokio::test]
async fn a_evm_witness_verifies_in_sdk() {
    let (a, b, ws) = dual_anchor_epoch().await;
    for c in [&a, &b] {
        let w = witness_for(&ws, &c.leaf, AnchorMethod::Evm);
        assert_witness_verifies(&verify(c, &[w]), w);
    }
}

/// Blocker A (qTSA path; B behind it). Each client's tree with its qTSA witness must verify:
/// batch inclusion first, then the token (TsaWebHost), then the signature.
#[tokio::test]
async fn a_qtsa_witness_verifies_in_sdk() {
    let (a, b, ws) = dual_anchor_epoch().await;
    for c in [&a, &b] {
        let w = witness_for(&ws, &c.leaf, AnchorMethod::Qtsa);
        assert_witness_verifies(&verify(c, &[w]), w);
    }
}

/// Blockers A and B, the reader's view: one client tree with BOTH witness pairs merged in
/// verifies as a whole.
#[tokio::test]
async fn a_b_dual_anchor_client_tree_verifies_in_sdk() {
    let (a, _b, ws) = dual_anchor_epoch().await;
    let evm = witness_for(&ws, &a.leaf, AnchorMethod::Evm);
    let qtsa = witness_for(&ws, &a.leaf, AnchorMethod::Qtsa);
    let result = verify(&a, &[evm, qtsa]);
    assert_witness_verifies(&result, evm);
    assert_witness_verifies(&result, qtsa);
}

// ---- fixture control (green) ----------------------------------------------------------------

/// Control, not a blocker: the offline TSA fixture is sound. Its answer, judged by the SDK's
/// TSA host at the claims the provider returned (root and genTime), passes every step
/// including the certificate chain, so a red B test is red for the genTime binding only.
#[tokio::test]
async fn control_test_tsa_token_verifies_in_sdk_host() {
    let root = format!("0x{}", "ab".repeat(32));
    let value = TestTsa.create_timestamp(&root).await.expect("test TSA");
    let (level, message, facts) = tsa_host()
        .verify_tsa_token(&value.transaction_hash, &root, value.timestamp)
        .expect("TSA host answers");
    assert_eq!(level, QualifiedVerifyLevel::Verified, "{message}");
    assert!(facts.is_some(), "token facts admitted");
}

// ---- B: qTSA genTime binding ----------------------------------------------------------------

/// Blocker B, isolated from A: the SDK's TSA host (the one `web_verify_tsa` calls) judges the
/// minted qTSA payload's token against its claimed `merkle_root` and `timestamp`. The token's
/// genTime must equal the payload's `timestamp`.
#[tokio::test]
async fn b_qtsa_payload_timestamp_is_token_gentime() {
    let (a, b, ws) = dual_anchor_epoch().await;
    for c in [&a, &b] {
        let p = payloads(witness_for(&ws, &c.leaf, AnchorMethod::Qtsa));
        let (level, message, _facts) = tsa_host()
            .verify_tsa_token(
                p["transaction_hash"].as_str().expect("transaction_hash"),
                p["merkle_root"].as_str().expect("merkle_root"),
                p["timestamp"].as_u64().expect("timestamp"),
            )
            .expect("TSA host answers");
        assert!(
            matches!(
                level,
                QualifiedVerifyLevel::Verified | QualifiedVerifyLevel::QualifiedVerified
            ),
            "[B] SDK TSA host rejects the minted qTSA witness: level={level:?} message={message} \
             (payload timestamp {}, TSA genTime {TSA_GEN_TIME})",
            p["timestamp"]
        );
    }
}

// ---- G: qTSA network label --------------------------------------------------------------------

/// A TSA provider that labels its answer with an operator name (the label `deploy/config.toml`
/// carried for `[anchors.qtsa]`) instead of the SDK's TSA network label.
struct OperatorLabelTsa;

#[async_trait]
impl AnchorProvider for OperatorLabelTsa {
    async fn create_timestamp(&self, merkle_root_hex: &str) -> Result<TimestampValue, AnchorError> {
        let mut value = TestTsa.create_timestamp(merkle_root_hex).await?;
        value.network = "sectigo-qualified-tsa".to_string();
        Ok(value)
    }
}

/// Audit G: the qTSA payload's `network` is the label the SDK's TSA template requires
/// (`timestamp_tsa.json`: `"const": "tsa"`), whatever label the provider or the operator
/// config uses, and the witness then verifies in the SDK.
#[tokio::test]
async fn g_qtsa_network_label_is_the_sdk_tsa_label() {
    let a = client_tree("ow1_g_label_a");
    let b = client_tree("ow1_g_label_b");
    let ctx = ctx(
        Some(Arc::new(ChainAnchor)),
        Some(Arc::new(OperatorLabelTsa)),
    )
    .await;
    let ws = seal(&[&a, &b], &ctx).await;
    for c in [&a, &b] {
        let w = witness_for(&ws, &c.leaf, AnchorMethod::Qtsa);
        assert_eq!(
            payloads(w)["network"],
            Value::String("tsa".to_string()),
            "[G] qTSA payload network is not the SDK TSA label"
        );
        assert_witness_verifies(&verify(c, &[w]), w);
    }
}

// ---- C: never a stub ------------------------------------------------------------------------

fn stub_witnesses(ws: &[MintedWitness]) -> Vec<String> {
    let zero_tx = format!("0x{}", "0".repeat(64));
    ws.iter()
        .filter_map(|w| {
            let p = payloads(w);
            let tx = p["transaction_hash"].as_str().unwrap_or_default();
            let tsa = p["tsa_provider"].as_str().unwrap_or_default();
            let stub = tx.eq_ignore_ascii_case(&zero_tx) || tsa == "stub";
            stub.then(|| {
                format!(
                    "{} witness: transaction_hash={tx} tsa_provider={tsa:?}",
                    w.method.as_str()
                )
            })
        })
        .collect()
}

/// Blocker C: no provider wired for either method. Whatever the sealer does instead (defer,
/// refuse, error), it must not mint a stub witness.
#[tokio::test]
async fn c_missing_provider_never_mints_stub() {
    let (a, b) = (
        client_tree("ow1_c_missing_a"),
        client_tree("ow1_c_missing_b"),
    );
    let ctx = ctx(None, None).await;
    let ws = seal_lenient(&[&a, &b], &ctx).await;
    let stubs = stub_witnesses(&ws);
    assert!(
        stubs.is_empty(),
        "[C] stub witnesses minted with no provider: {stubs:#?}"
    );
}

/// Blocker C: both providers fail. No stub may be minted.
#[tokio::test]
async fn c_failed_provider_call_never_mints_stub() {
    let (a, b) = (client_tree("ow1_c_fail_a"), client_tree("ow1_c_fail_b"));
    let failing = || -> Option<Arc<dyn AnchorProvider>> {
        Some(Arc::new(FailingProvider {
            message: "synthetic outage".into(),
        }))
    };
    let ctx = ctx(failing(), failing()).await;
    let ws = seal_lenient(&[&a, &b], &ctx).await;
    let stubs = stub_witnesses(&ws);
    assert!(
        stubs.is_empty(),
        "[C] stub witnesses minted after a failed anchor call: {stubs:#?}"
    );
}

/// Blocker C: an empty epoch, with and without providers, mints no stub.
#[tokio::test]
async fn c_empty_epoch_never_mints_stub() {
    for ctx in [
        ctx(None, None).await,
        ctx(Some(Arc::new(ChainAnchor)), Some(Arc::new(TestTsa))).await,
    ] {
        let ws = seal_lenient(&[], &ctx).await;
        let stubs = stub_witnesses(&ws);
        assert!(
            stubs.is_empty(),
            "[C] stub witnesses minted for an empty epoch: {stubs:#?}"
        );
    }
}

/// As [`seal`], but a sealer that refuses to mint (an `Err`) counts as "no witness".
async fn seal_lenient(clients: &[&ClientTree], ctx: &WitnessContext) -> Vec<MintedWitness> {
    let dir = tempdir().expect("tempdir");
    let store = Store::open(dir.path()).expect("store");
    let acc = Accumulator::new(1, EPOCH_CLOSE - EPOCH_SECS, EPOCH_SECS);
    for (i, c) in clients.iter().enumerate() {
        acc.append_batch(&[c.leaf], if i % 2 == 0 { DID_A } else { DID_B });
    }
    match seal_once(&acc, &store, EPOCH_CLOSE, EPOCH_SECS, Some(ctx)).await {
        Ok((_record, ws)) => ws,
        Err(_) => Vec::new(),
    }
}

// ---- D51: a failed anchor stays pending and retries the same root ---------------------------

fn failing() -> Arc<dyn AnchorProvider> {
    Arc::new(FailingProvider {
        message: "synthetic outage".into(),
    })
}

/// Seal one epoch with `clients` into `store` (epoch 1), through the real sealer.
async fn seal_into(
    store: &Store,
    clients: &[&ClientTree],
    ctx: &WitnessContext,
) -> Vec<MintedWitness> {
    let acc = Accumulator::new(1, EPOCH_CLOSE - EPOCH_SECS, EPOCH_SECS);
    for (i, c) in clients.iter().enumerate() {
        acc.append_batch(&[c.leaf], if i % 2 == 0 { DID_A } else { DID_B });
    }
    let (_record, ws) = seal_once(&acc, store, EPOCH_CLOSE, EPOCH_SECS, Some(ctx))
        .await
        .expect("seal_once");
    ws
}

/// The next epoch tick on `store` (epoch 2, no new leaves).
async fn next_tick(store: &Store, ctx: &WitnessContext) -> Vec<MintedWitness> {
    let acc = Accumulator::new(2, EPOCH_CLOSE, EPOCH_SECS);
    let (_record, ws) = seal_once(&acc, store, EPOCH_CLOSE + EPOCH_SECS, EPOCH_SECS, Some(ctx))
        .await
        .expect("seal_once (retry tick)");
    ws
}

fn pending_methods(store: &Store) -> Vec<(u64, Vec<AnchorMethod>)> {
    store
        .list_pending_epochs()
        .expect("list_pending_epochs")
        .into_iter()
        .map(|p| (p.epoch_id, p.methods.clone()))
        .collect()
}

/// D51: an enabled method without a provider refuses to start (the context does not validate,
/// and the sealer refuses before it closes the epoch).
#[tokio::test]
async fn d51_missing_provider_refuses_to_start() {
    let no_evm = ctx(None, Some(Arc::new(TestTsa))).await;
    let err = no_evm.validate().expect_err("EVM enabled without provider");
    assert!(
        err.to_string().contains("evm"),
        "message names the method: {err}"
    );
    let no_qtsa = ctx(Some(Arc::new(ChainAnchor)), None).await;
    let err = no_qtsa
        .validate()
        .expect_err("qTSA enabled without provider");
    assert!(
        err.to_string().contains("qtsa"),
        "message names the method: {err}"
    );
    ctx(Some(Arc::new(ChainAnchor)), Some(Arc::new(TestTsa)))
        .await
        .validate()
        .expect("both providers wired");
}

/// D51: the EVM call fails, qTSA succeeds. qTSA is minted (and verifies), EVM stays pending.
#[tokio::test]
async fn d51_failed_evm_stays_pending_qtsa_minted() {
    let dir = tempdir().expect("tempdir");
    let store = Store::open(dir.path()).expect("store");
    let a = client_tree("d51_evm_down_a");
    let b = client_tree("d51_evm_down_b");
    let ctx = ctx(Some(failing()), Some(Arc::new(TestTsa))).await;
    let ws = seal_into(&store, &[&a, &b], &ctx).await;
    assert_eq!(ws.len(), 2, "only the qTSA witnesses are minted");
    assert!(ws.iter().all(|w| w.method == AnchorMethod::Qtsa));
    assert!(stub_witnesses(&ws).is_empty());
    assert_witness_verifies(
        &verify(&a, &[witness_for(&ws, &a.leaf, AnchorMethod::Qtsa)]),
        witness_for(&ws, &a.leaf, AnchorMethod::Qtsa),
    );
    assert_eq!(pending_methods(&store), vec![(1, vec![AnchorMethod::Evm])]);
    assert_eq!(
        store
            .get_pending_epoch_for_leaf(&a.leaf, AnchorMethod::Evm)
            .expect("store"),
        Some(1)
    );
    assert_eq!(
        store
            .get_pending_epoch_for_leaf(&a.leaf, AnchorMethod::Qtsa)
            .expect("store"),
        None
    );
}

/// D51, the other way round: qTSA fails, EVM is minted (and verifies), qTSA stays pending.
#[tokio::test]
async fn d51_failed_qtsa_stays_pending_evm_minted() {
    let dir = tempdir().expect("tempdir");
    let store = Store::open(dir.path()).expect("store");
    let a = client_tree("d51_tsa_down_a");
    let ctx = ctx(Some(Arc::new(ChainAnchor)), Some(failing())).await;
    let ws = seal_into(&store, &[&a], &ctx).await;
    assert_eq!(ws.len(), 1, "only the EVM witness is minted");
    let w = witness_for(&ws, &a.leaf, AnchorMethod::Evm);
    assert_witness_verifies(&verify(&a, &[w]), w);
    assert_eq!(pending_methods(&store), vec![(1, vec![AnchorMethod::Qtsa])]);
}

/// D51: a later tick with a working provider mints the pending method for the SAME root, and
/// the late witness verifies in the SDK next to the one minted on time.
#[tokio::test]
async fn d51_later_tick_mints_pending_for_same_root() {
    let dir = tempdir().expect("tempdir");
    let store = Store::open(dir.path()).expect("store");
    let a = client_tree("d51_retry_a");
    let b = client_tree("d51_retry_b");
    let down = ctx(Some(failing()), Some(Arc::new(TestTsa))).await;
    let on_time = seal_into(&store, &[&a, &b], &down).await;
    // Still down on the next tick: nothing minted, still pending.
    assert!(next_tick(&store, &down).await.is_empty());
    assert_eq!(pending_methods(&store), vec![(1, vec![AnchorMethod::Evm])]);
    // Provider back: the tick mints the epoch-1 EVM witnesses.
    let up = ctx(Some(Arc::new(ChainAnchor)), Some(Arc::new(TestTsa))).await;
    let late = next_tick(&store, &up).await;
    assert_eq!(
        late.len(),
        2,
        "both leaves of epoch 1 get their EVM witness"
    );
    assert!(late
        .iter()
        .all(|w| w.method == AnchorMethod::Evm && w.epoch_id == 1));
    assert!(pending_methods(&store).is_empty(), "nothing left pending");
    for c in [&a, &b] {
        let q = witness_for(&on_time, &c.leaf, AnchorMethod::Qtsa);
        let e = witness_for(&late, &c.leaf, AnchorMethod::Evm);
        assert_eq!(
            payloads(e)["merkle_root"],
            payloads(q)["merkle_root"],
            "the late EVM anchor carries the same epoch root"
        );
        assert_witness_verifies(&verify(c, &[e]), e);
        let both = verify(c, &[q, e]);
        assert!(
            both.is_verified(),
            "dual anchor tree: {:#?}",
            error_logs(&both)
        );
        assert!(store
            .get_tip_for_leaf(&c.leaf, AnchorMethod::Evm)
            .expect("store")
            .is_some());
    }
}

/// D51: a pending method survives a restart (store reopen) and is minted after it.
#[tokio::test]
async fn d51_pending_survives_store_reopen() {
    let dir = tempdir().expect("tempdir");
    let a = client_tree("d51_restart_a");
    {
        let store = Store::open(dir.path()).expect("store");
        let down = ctx(Some(Arc::new(ChainAnchor)), Some(failing())).await;
        seal_into(&store, &[&a], &down).await;
    }
    let store = Store::open(dir.path()).expect("reopen");
    assert_eq!(pending_methods(&store), vec![(1, vec![AnchorMethod::Qtsa])]);
    let up = ctx(Some(Arc::new(ChainAnchor)), Some(Arc::new(TestTsa))).await;
    let late = next_tick(&store, &up).await;
    let w = witness_for(&late, &a.leaf, AnchorMethod::Qtsa);
    assert_witness_verifies(&verify(&a, &[w]), w);
    assert!(pending_methods(&store).is_empty());
}

// ---- OW1.4: pre-serve self-check -----------------------------------------------------------

/// Captures the sealer's log lines (tracing) for one test thread.
#[derive(Clone, Default)]
struct LogSink(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log sink").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl LogSink {
    /// The process-wide sink. One global subscriber: a thread-local one loses events to the
    /// callsite interest cache when other test threads run without a subscriber. Tests share
    /// it and pick their own lines by their unique leaf.
    fn global() -> Self {
        static SINK: std::sync::OnceLock<LogSink> = std::sync::OnceLock::new();
        SINK.get_or_init(|| {
            let sink = LogSink::default();
            let writer = sink.clone();
            tracing_subscriber::fmt()
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .init();
            sink
        })
        .clone()
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("log sink")).into_owned()
    }
}

/// Counts the calls of the wrapped provider and lets a test corrupt its answer.
struct Counting<P> {
    inner: P,
    calls: std::sync::atomic::AtomicUsize,
    corrupt_token_byte: bool,
}

impl<P> Counting<P> {
    fn new(inner: P) -> Self {
        Self {
            inner,
            calls: Default::default(),
            corrupt_token_byte: false,
        }
    }
    fn calls(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait]
impl<P: AnchorProvider> AnchorProvider for Counting<P> {
    async fn create_timestamp(&self, merkle_root_hex: &str) -> Result<TimestampValue, AnchorError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut value = self.inner.create_timestamp(merkle_root_hex).await?;
        if self.corrupt_token_byte {
            // One byte of the TimeStampResp (the last byte: inside the CMS signature).
            let b64 = base64::engine::general_purpose::STANDARD;
            let mut resp = b64.decode(&value.transaction_hash).expect("base64 token");
            *resp.last_mut().expect("token bytes") ^= 0x01;
            value.transaction_hash = b64.encode(resp);
        }
        Ok(value)
    }
}

fn pending_anchor(store: &Store, method: AnchorMethod) -> Option<TimestampValue> {
    store
        .list_pending_epochs()
        .expect("pending")
        .first()
        .and_then(|p| p.anchor(method).cloned())
}

/// A TSA token with one corrupted byte: the qTSA witness is not served, the method stays
/// pending, an error with epoch, method, leaf and the SDK's reason is logged, and the stored
/// token is discarded (the token itself is at fault), so the next tick asks the TSA again.
#[tokio::test]
async fn ow14_corrupted_tsa_token_not_served_pending() {
    let logs = LogSink::global();
    let dir = tempdir().expect("tempdir");
    let store = Store::open(dir.path()).expect("store");
    let a = client_tree("ow14_bad_token");
    let mut bad = Counting::new(TestTsa);
    bad.corrupt_token_byte = true;
    let bad = Arc::new(bad);
    let c = ctx(Some(Arc::new(ChainAnchor)), Some(bad.clone())).await;

    let served = seal_into(&store, &[&a], &c).await;
    assert!(
        served.iter().all(|w| w.method != AnchorMethod::Qtsa),
        "a witness whose token does not verify is never served"
    );
    assert!(store
        .get_tip_for_leaf(&a.leaf, AnchorMethod::Qtsa)
        .expect("store")
        .is_none());
    assert!(served.iter().any(|w| w.method == AnchorMethod::Evm));
    assert_eq!(pending_methods(&store), vec![(1, vec![AnchorMethod::Qtsa])]);
    assert!(
        pending_anchor(&store, AnchorMethod::Qtsa).is_none(),
        "anchor discarded"
    );
    let text = logs.text();
    let line = text
        .lines()
        .find(|l| l.contains("witness self-check failed") && l.contains(&hex::encode(a.leaf)))
        .unwrap_or_else(|| panic!("error logged: {text}"));
    assert!(line.contains("ERROR"), "{line}");
    assert!(
        line.contains("epoch_id=1") && line.contains("method=\"qtsa\""),
        "{line}"
    );
    assert!(line.contains("TSA token"), "{line}");

    next_tick(&store, &c).await;
    assert_eq!(
        bad.calls(),
        2,
        "the discarded token is replaced by a new request"
    );
}

/// Corruption between mint and serve (a changed shielding nonce in the timestamp payload): the
/// SDK checks refuse the witness, it is not served, the method stays pending with its anchor
/// kept, and the next tick re-mints from the stored anchor without a second provider call.
#[tokio::test]
async fn ow14_corrupted_nonce_not_served_pending() {
    let dir = tempdir().expect("tempdir");
    let store = Store::open(dir.path()).expect("store");
    let a = client_tree("ow14_bad_nonce");
    let evm = Arc::new(Counting::new(ChainAnchor));
    let mut c = ctx(Some(evm.clone()), Some(Arc::new(TestTsa))).await;
    let once = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let flag = once.clone();
    c.after_mint = Some(Arc::new(move |ws: &mut Vec<MintedWitness>| {
        if ws[0].method == AnchorMethod::Evm
            && flag.swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            let mut obj = serde_json::to_value(&ws[0].object_revision).expect("object");
            obj["payloads"]["shielding_nonce"] = Value::String(format!("0x{}", "00".repeat(32)));
            ws[0].object_revision = serde_json::from_value(obj).expect("object parses");
        }
        Ok(())
    }));

    let served = seal_into(&store, &[&a], &c).await;
    assert!(served.iter().all(|w| w.method != AnchorMethod::Evm));
    assert_eq!(pending_methods(&store), vec![(1, vec![AnchorMethod::Evm])]);
    assert!(
        pending_anchor(&store, AnchorMethod::Evm).is_some(),
        "anchor kept"
    );

    let late = next_tick(&store, &c).await;
    let w = witness_for(&late, &a.leaf, AnchorMethod::Evm);
    assert_witness_verifies(&verify(&a, &[w]), w);
    assert_eq!(evm.calls(), 1, "re-minted from the stored anchor");
    assert!(pending_methods(&store).is_empty());
}

/// The inclusion check itself: a witness whose shielding nonce was changed and which is then
/// consistently re-hashed and re-signed passes the content-hash and signature checks and is
/// refused by the batch inclusion check (not the anchor's fault).
#[tokio::test]
async fn ow14_corrupted_inclusion_refused_by_self_check() {
    let a = client_tree("ow14_inclusion");
    let c = ctx(Some(Arc::new(ChainAnchor)), Some(Arc::new(TestTsa))).await;
    let served = seal(&[&a], &c).await;
    let good = witness_for(&served, &a.leaf, AnchorMethod::Evm).clone();
    assert_eq!(
        verify_minted_witness(&good, &c.service_did, &c.self_check),
        SelfCheckVerdict::Verified
    );

    let mut obj = serde_json::to_value(&good.object_revision).expect("object");
    obj["payloads"]["shielding_nonce"] = Value::String(format!("0x{}", "11".repeat(32)));
    let object: AnyRevision = serde_json::from_value(obj).expect("object parses");
    let AnyRevision::Typed(typed) = &object else {
        panic!("typed object")
    };
    use aqua_rs_sdk::verification::Linkable;
    let link = typed
        .calculate_link(aqua_rs_sdk::primitives::HashType::Sha3_256)
        .expect("link");
    let sig = aqua_rs_sdk::Signer::sign_revision(
        c.signer.as_ref(),
        &link,
        Method::Scalar,
        aqua_rs_sdk::primitives::HashType::Sha3_256,
    )
    .await
    .expect("sign");
    let sig_link = sig
        .calculate_link(aqua_rs_sdk::primitives::HashType::Sha3_256)
        .expect("sig link");
    let digest = |l: &aqua_rs_sdk::primitives::RevisionLink| -> [u8; 32] {
        l.as_ref()[2..].try_into().expect("sha3 digest")
    };
    let mut bad = good.clone();
    bad.object_hash = digest(&link);
    bad.signature_hash = digest(&sig_link);
    bad.object_revision = object;
    bad.signature_revision = AnyRevision::Signature(sig);

    match verify_minted_witness(&bad, &c.service_did, &c.self_check) {
        SelfCheckVerdict::Failed {
            reason,
            anchor_at_fault,
        } => {
            assert!(reason.starts_with("batch inclusion"), "{reason}");
            assert!(!anchor_at_fault);
        }
        other => panic!("inclusion corruption must fail, got {other:?}"),
    }
}

fn sim_evm() -> Arc<SimChain> {
    Arc::new(SimChain::new(TimestampValue::new(
        vec![],
        evm_chain::SENDER.to_string(),
        String::new(),
        format!("0x{}", "5e".repeat(32)),
        evm_chain::CONTRACT.to_string(),
        evm_chain::NETWORK.to_string(),
        String::new(),
        BLOCK_TIME,
        1,
        0,
        String::new(),
    )))
}

/// EVM transaction not final yet: the witness is not served and the method stays pending
/// (not an error); once the chain finalizes it, a later tick serves it without a second anchor.
#[tokio::test]
async fn ow14_evm_not_final_then_served_without_second_anchor() {
    let dir = tempdir().expect("tempdir");
    let store = Store::open(dir.path()).expect("store");
    let a = client_tree("ow14_finality");
    let chain = sim_evm();
    chain.set_final(false);
    let mut c = ctx(Some(chain.clone()), Some(Arc::new(TestTsa))).await;
    c.self_check.blockchain = Some(chain.clone());

    let served = seal_into(&store, &[&a], &c).await;
    assert!(served.iter().all(|w| w.method != AnchorMethod::Evm));
    assert!(served.iter().any(|w| w.method == AnchorMethod::Qtsa));
    assert_eq!(pending_methods(&store), vec![(1, vec![AnchorMethod::Evm])]);
    assert!(next_tick(&store, &c).await.is_empty(), "still not final");

    chain.set_final(true);
    let acc = Accumulator::new(3, EPOCH_CLOSE + EPOCH_SECS, EPOCH_SECS);
    let (_r, late) = seal_once(
        &acc,
        &store,
        EPOCH_CLOSE + 2 * EPOCH_SECS,
        EPOCH_SECS,
        Some(&c),
    )
    .await
    .expect("seal");
    witness_for(&late, &a.leaf, AnchorMethod::Evm);
    assert_eq!(
        chain.anchor_calls(),
        1,
        "no second anchor for the same root"
    );
    assert!(pending_methods(&store).is_empty());
}

/// A mint failure after a successful anchor (here: the new epoch's, every method): the leaves
/// are not lost (the epoch is pending with both anchors stored), and the next tick mints from
/// the stored anchors, each provider called once.
#[tokio::test]
async fn ow14_mint_failure_after_anchor_keeps_leaves_and_anchor() {
    let dir = tempdir().expect("tempdir");
    let store = Store::open(dir.path()).expect("store");
    let a = client_tree("ow14_mint_fail_a");
    let b = client_tree("ow14_mint_fail_b");
    let evm = Arc::new(Counting::new(ChainAnchor));
    let tsa = Arc::new(Counting::new(TestTsa));
    let mut c = ctx(Some(evm.clone()), Some(tsa.clone())).await;
    let failures = Arc::new(std::sync::atomic::AtomicUsize::new(2));
    let left = failures.clone();
    c.after_mint = Some(Arc::new(move |_ws: &mut Vec<MintedWitness>| {
        let n = left.load(std::sync::atomic::Ordering::SeqCst);
        if n > 0 {
            left.store(n - 1, std::sync::atomic::Ordering::SeqCst);
            return Err(aqua_timestamp_core::witness::WitnessError::Batch(
                "synthetic mint failure".into(),
            ));
        }
        Ok(())
    }));

    let served = seal_into(&store, &[&a, &b], &c).await;
    assert!(served.is_empty());
    assert_eq!(
        pending_methods(&store),
        vec![(1, vec![AnchorMethod::Evm, AnchorMethod::Qtsa])]
    );
    let pending = store.list_pending_epochs().expect("pending");
    let leaves = pending[0].leaf_hashes().expect("leaves");
    assert_eq!(leaves, vec![a.leaf, b.leaf], "leaves not lost");
    assert!(pending[0].anchor(AnchorMethod::Evm).is_some());
    assert!(pending[0].anchor(AnchorMethod::Qtsa).is_some());

    let late = next_tick(&store, &c).await;
    for client in [&a, &b] {
        let e = witness_for(&late, &client.leaf, AnchorMethod::Evm);
        let q = witness_for(&late, &client.leaf, AnchorMethod::Qtsa);
        assert_witness_verifies(&verify(client, &[e, q]), e);
    }
    assert_eq!(
        (evm.calls(), tsa.calls()),
        (1, 1),
        "no second transaction or token"
    );
    assert!(pending_methods(&store).is_empty());
}

// ---- OW1.6: review fixes ---------------------------------------------------------------------

/// The honest chain host, counting its lookups (each one is several RPCs in production).
#[derive(Default)]
struct CountingChain(std::sync::atomic::AtomicUsize);

impl CountingChain {
    fn calls(&self) -> usize {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl aqua_rs_sdk::BlockchainHost for CountingChain {
    fn transaction_facts(
        &self,
        chain_id: u64,
        tx_hash: &str,
    ) -> Result<Option<aqua_rs_sdk::EvmTransactionFacts>, aqua_rs_sdk::HostError> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        evm_chain::HonestChain::facts(chain_id, tx_hash)
    }
}

/// The reader's TSA host on the test PKI, counting its token checks.
struct CountingTsaHost {
    inner: TsaWebHost,
    calls: std::sync::atomic::AtomicUsize,
}

impl WebHost for CountingTsaHost {
    fn verify_tsa_token(
        &self,
        tsa_response: &str,
        merkle_root: &str,
        timestamp: u64,
    ) -> Result<
        (
            QualifiedVerifyLevel,
            String,
            Option<aqua_rs_sdk::TsaTokenFacts>,
        ),
        aqua_rs_sdk::HostError,
    > {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner
            .verify_tsa_token(tsa_response, merkle_root, timestamp)
    }
}

/// OW1.6 H1: the anchor is judged once per (epoch, method), not once per witness. A 50-leaf
/// epoch makes exactly one chain lookup and one TSA token check in its tick, and every witness
/// is still served and verifies.
#[tokio::test]
async fn ow16_h1_anchor_judged_once_per_epoch_and_method() {
    let dir = tempdir().expect("tempdir");
    let store = Store::open(dir.path()).expect("store");
    let a = client_tree("ow16_h1");
    let chain = Arc::new(CountingChain::default());
    let tsa = Arc::new(CountingTsaHost {
        inner: tsa_host(),
        calls: Default::default(),
    });
    let mut c = ctx(Some(Arc::new(ChainAnchor)), Some(Arc::new(TestTsa))).await;
    c.self_check.blockchain = Some(chain.clone());
    c.self_check.tsa = Some(tsa.clone());

    let acc = Accumulator::new(1, EPOCH_CLOSE - EPOCH_SECS, EPOCH_SECS);
    acc.append_batch(&[a.leaf], DID_A);
    let others: Vec<[u8; 32]> = (1..50u8).map(|i| [i; 32]).collect();
    acc.append_batch(&others, DID_B);
    let (_record, served) = seal_once(&acc, &store, EPOCH_CLOSE, EPOCH_SECS, Some(&c))
        .await
        .expect("seal_once");

    assert_eq!(served.len(), 100, "50 leaves x 2 methods served");
    assert_eq!(chain.calls(), 1, "one chain lookup per (epoch, EVM)");
    assert_eq!(
        tsa.calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "one token check per (epoch, qTSA)"
    );
    let evm = witness_for(&served, &a.leaf, AnchorMethod::Evm);
    let qtsa = witness_for(&served, &a.leaf, AnchorMethod::Qtsa);
    assert_witness_verifies(&verify(&a, &[evm, qtsa]), evm);
}

/// One empty epoch tick `epoch_id` at `now` on `store` (retries only).
async fn tick_at(
    store: &Store,
    ctx: &WitnessContext,
    epoch_id: u64,
    now: u64,
) -> Vec<MintedWitness> {
    let acc = Accumulator::new(epoch_id, now - EPOCH_SECS, EPOCH_SECS);
    let (_record, ws) = seal_once(&acc, store, now, EPOCH_SECS, Some(ctx))
        .await
        .expect("seal_once (tick)");
    ws
}

/// OW1.6 H2: a dropped EVM transaction. While the transaction is not found and the anchor is
/// younger than the not-found timeout, the method stays pending with its anchor kept and no
/// second transaction. Past the timeout the anchor is discarded (the pending record saved
/// without it), the next tick re-anchors, and the new anchor's witness is served.
#[tokio::test]
async fn ow16_h2_dropped_evm_tx_times_out_and_reanchors() {
    use aqua_timestamp_core::selfcheck::doubles::SimChain;
    let dir = tempdir().expect("tempdir");
    let store = Store::open(dir.path()).expect("store");
    let a = client_tree("ow16_h2");
    let chain = Arc::new(SimChain::new(TimestampValue::new(
        vec![],
        "0xCAFE000000000000000000000000000000000000".into(),
        String::new(),
        format!("0x{}", "ab".repeat(32)),
        "0xDEAD000000000000000000000000000000000000".into(),
        "sepolia".into(),
        String::new(),
        BLOCK_TIME,
        1,
        0,
        String::new(),
    )));
    chain.set_dropped(true);
    let mut c = ctx(Some(chain.clone()), Some(Arc::new(TestTsa))).await;
    c.self_check.blockchain = Some(chain.clone());
    // The default not-found timeout (anchors.evm.not_found_timeout_secs): one hour.
    let timeout = 3600;

    let served = seal_into(&store, &[&a], &c).await;
    assert!(served.iter().all(|w| w.method != AnchorMethod::Evm));
    assert_eq!(chain.anchor_calls(), 1);
    let first = pending_anchor(&store, AnchorMethod::Evm).expect("anchor stored");

    // Before the timeout: pending, anchor kept, no second transaction.
    let ws = tick_at(&store, &c, 2, EPOCH_CLOSE + timeout - 60).await;
    assert!(ws.iter().all(|w| w.method != AnchorMethod::Evm));
    assert_eq!(chain.anchor_calls(), 1, "no re-anchor before the timeout");
    assert!(
        pending_anchor(&store, AnchorMethod::Evm).is_some(),
        "anchor kept"
    );
    assert_eq!(pending_methods(&store)[0], (1, vec![AnchorMethod::Evm]));

    // Past the timeout: the abandoned anchor is discarded and saved so.
    let ws = tick_at(&store, &c, 3, EPOCH_CLOSE + timeout + 60).await;
    assert!(ws.iter().all(|w| w.method != AnchorMethod::Evm));
    assert!(
        pending_anchor(&store, AnchorMethod::Evm).is_none(),
        "abandoned anchor {} discarded",
        first.transaction_hash
    );

    // The next attempt re-anchors; the new transaction lands and is served.
    chain.set_dropped(false);
    let ws = tick_at(&store, &c, 4, EPOCH_CLOSE + timeout + 120).await;
    assert_eq!(chain.anchor_calls(), 2, "one new anchor");
    let w = witness_for(&ws, &a.leaf, AnchorMethod::Evm);
    assert_eq!(w.epoch_id, 1);
    assert!(pending_methods(&store).is_empty());
}

/// A context that mints only the EVM method, on `chain` (provider and self-check host), so no
/// later qTSA save of the same pending record can store the EVM anchor by accident.
async fn evm_only_ctx(
    chain: Arc<aqua_timestamp_core::selfcheck::doubles::SimChain>,
) -> WitnessContext {
    let mut c = ctx(Some(chain.clone()), None).await;
    c.methods = vec![AnchorMethod::Evm];
    c.self_check.blockchain = Some(chain);
    c
}

fn sim_chain() -> Arc<aqua_timestamp_core::selfcheck::doubles::SimChain> {
    Arc::new(aqua_timestamp_core::selfcheck::doubles::SimChain::new(
        TimestampValue::new(
            vec![],
            "0xCAFE000000000000000000000000000000000000".into(),
            String::new(),
            format!("0x{}", "cd".repeat(32)),
            "0xDEAD000000000000000000000000000000000000".into(),
            "sepolia".into(),
            String::new(),
            BLOCK_TIME,
            1,
            0,
            String::new(),
        ),
    ))
}

/// OW1.6 F2: a just-broadcast anchor is durable before anything can drop it. One failed
/// `save_pending` is retried: the anchor is stored, so a not-yet-final transaction is
/// re-checked next tick without a second transaction.
#[tokio::test]
async fn ow16_f2_anchor_save_retried_once() {
    let dir = tempdir().expect("tempdir");
    let store = Store::open(dir.path()).expect("store");
    let a = client_tree("ow16_f2_retry");
    let chain = sim_chain();
    chain.set_final(false);
    let c = evm_only_ctx(chain.clone()).await;

    store
        .save_pending_faults
        .store(1, std::sync::atomic::Ordering::SeqCst);
    let served = seal_into(&store, &[&a], &c).await;
    assert!(served.is_empty(), "not final yet");
    assert_eq!(chain.anchor_calls(), 1);
    assert!(
        pending_anchor(&store, AnchorMethod::Evm).is_some(),
        "the anchor survived the failed save"
    );

    chain.set_final(true);
    let ws = tick_at(&store, &c, 2, EPOCH_CLOSE + EPOCH_SECS).await;
    assert_eq!(chain.anchor_calls(), 1, "no second transaction");
    witness_for(&ws, &a.leaf, AnchorMethod::Evm);
}

/// OW1.6 F2: when the anchor cannot be stored (the retry fails too), nothing is minted from
/// memory, and the method is down for the rest of the tick: no second anchor call in the same
/// tick, even for another pending epoch.
#[tokio::test]
async fn ow16_f2_unstored_anchor_not_minted_method_down() {
    let dir = tempdir().expect("tempdir");
    let store = Store::open(dir.path()).expect("store");
    let a = client_tree("ow16_f2_down_a");
    let b = client_tree("ow16_f2_down_b");
    let chain = sim_chain();
    let c = evm_only_ctx(chain.clone()).await;
    let faults = store.save_pending_faults.clone();

    faults.store(2, std::sync::atomic::Ordering::SeqCst);
    let served = seal_into(&store, &[&a], &c).await;
    assert!(served.is_empty(), "nothing minted from an unstored anchor");
    assert_eq!(chain.anchor_calls(), 1);

    // Tick 2: epoch 1 re-anchors and its save fails twice; epoch 2 makes no anchor call.
    faults.store(2, std::sync::atomic::Ordering::SeqCst);
    let acc = Accumulator::new(2, EPOCH_CLOSE, EPOCH_SECS);
    acc.append_batch(&[b.leaf], DID_B);
    let (_r, served) = seal_once(&acc, &store, EPOCH_CLOSE + EPOCH_SECS, EPOCH_SECS, Some(&c))
        .await
        .expect("seal_once");
    assert!(served.is_empty());
    assert_eq!(
        chain.anchor_calls(),
        2,
        "the method is down for the rest of the tick"
    );

    let ws = tick_at(&store, &c, 3, EPOCH_CLOSE + 2 * EPOCH_SECS).await;
    witness_for(&ws, &a.leaf, AnchorMethod::Evm);
    witness_for(&ws, &b.leaf, AnchorMethod::Evm);
}

/// An EVM provider whose transactions land on the honest chain, but whose returned anchor names
/// another sender: the self-check finds the anchor itself at fault (SenderMismatch) every time.
#[derive(Default)]
struct WrongSenderAnchor(std::sync::atomic::AtomicUsize);

#[async_trait]
impl AnchorProvider for WrongSenderAnchor {
    async fn create_timestamp(&self, merkle_root_hex: &str) -> Result<TimestampValue, AnchorError> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut value = ChainAnchor.create_timestamp(merkle_root_hex).await?;
        value.sender_account_address = "0x2222222222222222222222222222222222222222".into();
        Ok(value)
    }
}

/// Per pending epoch: (epoch, EVM anchors counted at fault, EVM anchor stored).
fn evm_faults(store: &Store) -> Vec<(u64, u32, bool)> {
    store
        .list_pending_epochs()
        .expect("pending")
        .iter()
        .map(|p| {
            (
                p.epoch_id,
                p.anchor_fault_count(AnchorMethod::Evm),
                p.anchor(AnchorMethod::Evm).is_some(),
            )
        })
        .collect()
}

/// OW1.6 M4: an anchor-fault verdict puts the method down for the rest of the tick (no anchor
/// call for another pending epoch in that tick), and after the default 3 anchors at fault an
/// (epoch, method) is not re-anchored again.
#[tokio::test]
async fn ow16_m4_reanchor_at_fault_capped_and_method_down() {
    let dir = tempdir().expect("tempdir");
    let store = Store::open(dir.path()).expect("store");
    let a = client_tree("ow16_m4_a");
    let b = client_tree("ow16_m4_b");
    let evm = Arc::new(WrongSenderAnchor::default());
    let mut c = ctx(Some(evm.clone()), None).await;
    c.methods = vec![AnchorMethod::Evm];
    let calls = || evm.0.load(std::sync::atomic::Ordering::SeqCst);

    assert!(seal_into(&store, &[&a], &c).await.is_empty());
    assert_eq!(calls(), 1);

    let acc = Accumulator::new(2, EPOCH_CLOSE, EPOCH_SECS);
    acc.append_batch(&[b.leaf], DID_B);
    seal_once(&acc, &store, EPOCH_CLOSE + EPOCH_SECS, EPOCH_SECS, Some(&c))
        .await
        .expect("seal_once");
    assert_eq!(
        calls(),
        2,
        "down after the fault: epoch 2 makes no call this tick"
    );

    assert_eq!(evm_faults(&store), vec![(1, 2, false), (2, 0, false)]);

    tick_at(&store, &c, 3, EPOCH_CLOSE + 2 * EPOCH_SECS).await;
    assert_eq!(calls(), 3, "epoch 1: third anchor at fault");
    assert_eq!(evm_faults(&store), vec![(1, 3, false), (2, 0, false)]);
    tick_at(&store, &c, 4, EPOCH_CLOSE + 3 * EPOCH_SECS).await;
    assert_eq!(
        calls(),
        4,
        "epoch 1 stopped after 3 faults; epoch 2 anchors"
    );
    assert_eq!(
        evm_faults(&store),
        vec![(1, 3, false), (2, 1, false)],
        "the call went to epoch 2; epoch 1 is not anchored again"
    );
    tick_at(&store, &c, 5, EPOCH_CLOSE + 4 * EPOCH_SECS).await;
    assert_eq!(calls(), 5, "epoch 1 stays stopped");
    assert_eq!(
        evm_faults(&store),
        vec![(1, 3, false), (2, 2, false)],
        "epoch 1 capped at 3 anchors at fault"
    );
    assert_eq!(
        pending_methods(&store),
        vec![(1, vec![AnchorMethod::Evm]), (2, vec![AnchorMethod::Evm])],
        "stopped is still pending, never served"
    );
}

/// `w` with `edit` applied to its timestamp payloads, consistently re-hashed and re-signed with
/// `signer`, so the content-hash, inclusion and signature checks still pass.
async fn resigned(
    w: &MintedWitness,
    signer: &Secp256k1Signer,
    edit: impl FnOnce(&mut Value),
) -> MintedWitness {
    use aqua_rs_sdk::primitives::{HashType, RevisionLink};
    use aqua_rs_sdk::verification::Linkable;
    let mut obj = serde_json::to_value(&w.object_revision).expect("object");
    edit(&mut obj["payloads"]);
    let object: AnyRevision = serde_json::from_value(obj).expect("object parses");
    let AnyRevision::Typed(typed) = &object else {
        panic!("typed object")
    };
    let link = typed.calculate_link(HashType::Sha3_256).expect("link");
    let sig = aqua_rs_sdk::Signer::sign_revision(signer, &link, Method::Scalar, HashType::Sha3_256)
        .await
        .expect("sign");
    let sig_link = sig.calculate_link(HashType::Sha3_256).expect("sig link");
    let digest =
        |l: &RevisionLink| -> [u8; 32] { l.as_ref()[2..].try_into().expect("sha3 digest") };
    let mut out = w.clone();
    out.object_hash = digest(&link);
    out.signature_hash = digest(&sig_link);
    out.object_revision = object;
    out.signature_revision = AnyRevision::Signature(sig);
    out
}

/// OW1.6 N2 scenario: a two-leaf epoch whose `method` witness at `index` carries a different
/// anchor `field`, re-hashed and re-signed between mint and self-check. The batch self-check
/// fails the witness that differs from the judged (first) one with the anchor-field reason,
/// nothing of that (epoch, method) is served, the method stays pending with its anchor kept
/// (not the anchor's fault), and the other method is served.
async fn odd_anchor_field_not_served(method: AnchorMethod, index: usize, field: &'static str) {
    let dir = tempdir().expect("tempdir");
    let store = Store::open(dir.path()).expect("store");
    let a = client_tree(&format!("ow16_n2_{}_{index}_a", method.as_str()));
    let b = client_tree(&format!("ow16_n2_{}_{index}_b", method.as_str()));
    let mut c = ctx(Some(Arc::new(ChainAnchor)), Some(Arc::new(TestTsa))).await;
    let signer = c.signer.clone();
    let seen: Arc<std::sync::Mutex<Vec<MintedWitness>>> = Arc::default();
    let keep = seen.clone();
    c.after_mint = Some(Arc::new(move |ws: &mut Vec<MintedWitness>| {
        if ws[0].method == method {
            assert_eq!(ws.len(), 2, "one witness per leaf");
            let odd = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(resigned(&ws[index], &signer, |p| {
                    p[field] = Value::String(format!("0x{}", "ab".repeat(32)));
                }))
            });
            ws[index] = odd;
            *keep.lock().expect("lock") = ws.clone();
        }
        Ok(())
    }));

    let served = seal_into(&store, &[&a, &b], &c).await;
    assert!(
        served.iter().all(|w| w.method != method),
        "nothing of the (epoch, method) served"
    );
    assert_eq!(
        served.len(),
        2,
        "the other method is served for both leaves"
    );
    assert_eq!(pending_methods(&store), vec![(1, vec![method])]);
    assert!(pending_anchor(&store, method).is_some(), "anchor kept");

    let ws = seen.lock().expect("lock").clone();
    let verdicts = verify_minted_batch(&ws, &c.service_did, &c.self_check);
    assert_eq!(
        verdicts[0],
        SelfCheckVerdict::Verified,
        "the judged witness passes on its own"
    );
    match &verdicts[1] {
        SelfCheckVerdict::Failed {
            reason,
            anchor_at_fault,
        } => {
            assert!(reason.starts_with("anchor fields differ"), "{reason}");
            assert!(!anchor_at_fault);
        }
        other => panic!("an odd anchor field must fail, got {other:?}"),
    }
}

/// OW1.6 N2: a non-first EVM witness with another `transaction_hash` cannot ride on the anchor
/// verdict judged on the first witness.
#[tokio::test(flavor = "multi_thread")]
async fn ow16_n2_non_first_witness_odd_anchor_field_not_served() {
    odd_anchor_field_not_served(AnchorMethod::Evm, 1, "transaction_hash").await;
}

/// OW1.6 N2: the first (judged) qTSA witness carries an odd `tsa_provider`, a field the token
/// check does not read, so its anchor verdict passes; the comparison still fails the others.
#[tokio::test(flavor = "multi_thread")]
async fn ow16_n2_first_witness_odd_anchor_field_not_served() {
    odd_anchor_field_not_served(AnchorMethod::Qtsa, 0, "tsa_provider").await;
}

/// OW1.6b N5: a transaction the node knows but has not mined (facts without a block, the SDK's
/// `NotIncluded`) holds its nonce, so it never times out: past the not-found timeout the anchor
/// is kept and no second anchor call is made. Once mined, it is served from that anchor.
#[tokio::test]
async fn ow16_n5_known_unmined_tx_never_times_out() {
    let dir = tempdir().expect("tempdir");
    let store = Store::open(dir.path()).expect("store");
    let a = client_tree("ow16_n5");
    let chain = sim_chain();
    chain.set_unmined(true);
    let c = evm_only_ctx(chain.clone()).await;
    let timeout = c.evm_not_found_timeout_secs;

    assert!(seal_into(&store, &[&a], &c).await.is_empty());
    assert_eq!(chain.anchor_calls(), 1);
    let first = pending_anchor(&store, AnchorMethod::Evm).expect("anchor stored");

    for (epoch, now) in [
        (2, EPOCH_CLOSE + timeout + 60),
        (3, EPOCH_CLOSE + 3 * timeout),
    ] {
        assert!(tick_at(&store, &c, epoch, now).await.is_empty());
        assert_eq!(chain.anchor_calls(), 1, "no second anchor past the timeout");
        assert_eq!(
            pending_anchor(&store, AnchorMethod::Evm).map(|v| v.transaction_hash),
            Some(first.transaction_hash.clone()),
            "anchor kept"
        );
    }

    chain.set_unmined(false);
    let ws = tick_at(&store, &c, 4, EPOCH_CLOSE + 3 * timeout + 60).await;
    assert_eq!(chain.anchor_calls(), 1, "served from the kept anchor");
    assert_eq!(witness_for(&ws, &a.leaf, AnchorMethod::Evm).epoch_id, 1);
    assert!(pending_methods(&store).is_empty());
}

/// OW1.6b N3: anchors abandoned after the not-found timeout count toward the same
/// per-(epoch, method) cap as anchors at fault, so a host that never sees the provider's
/// transactions cannot make the sealer send one per timeout period forever: after the default
/// 3 abandoned anchors the epoch is not re-anchored again and stays pending.
#[tokio::test]
async fn ow16_n3_not_found_timeouts_capped() {
    let dir = tempdir().expect("tempdir");
    let store = Store::open(dir.path()).expect("store");
    let a = client_tree("ow16_n3");
    let chain = sim_chain();
    chain.set_dropped(true);
    let mut c = evm_only_ctx(chain.clone()).await;
    c.evm_not_found_timeout_secs = 100;

    assert!(seal_into(&store, &[&a], &c).await.is_empty());
    for epoch in 2..12u64 {
        let now = EPOCH_CLOSE + (epoch - 1) * 200;
        assert!(tick_at(&store, &c, epoch, now).await.is_empty());
    }
    assert_eq!(chain.anchor_calls(), 3, "capped at 3 abandoned anchors");
    assert_eq!(evm_faults(&store), vec![(1, 3, false)]);
}
