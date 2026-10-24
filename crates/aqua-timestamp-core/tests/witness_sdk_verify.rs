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
        evm_chain::NETWORK.to_string(),
        vec![AnchorMethod::Evm, AnchorMethod::Qtsa],
    );
    ctx.evm_anchor = evm;
    ctx.qtsa_anchor = qtsa;
    ctx
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
