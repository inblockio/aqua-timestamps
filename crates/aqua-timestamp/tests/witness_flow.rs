//! M3 integration tests for witness minting and the aqua-node-compatible
//! `/trees/*` endpoints.
//!
//! The harness drives the in-process router with the channel-based sealer,
//! so every test seals deterministically on demand. Two test client keys
//! (CLIENT_A, CLIENT_B) prove the DID isolation invariant.

use std::path::PathBuf;

use aqua_rs_sdk::{
    primitives::{merkle::verify_inclusion, HashType},
    schema::AnyRevision,
};
use aqua_timestamp::{
    build_app,
    config::{
        AnchorConfig, AnchorsConfig, AuthConfig, Config, EpochConfig, EvmAnchorConfig,
        IdentityConfig, QtsaAnchorConfig, ServerConfig, StorageConfig,
    },
    identity::{IdentityClaimOverrides, ServiceIdentity},
    SealDriver,
};
use aqua_timestamp_core::sealer::SealTick;
use axum::{
    body::{to_bytes, Body},
    http::{Method, Request, StatusCode},
    Router,
};
use serde_json::Value;
use sha3::{Digest, Keccak256};
use tempfile::TempDir;
use tokio::sync::mpsc;
use tower::ServiceExt;

const SERVICE_MNEMONIC: &str = "test test test test test test test test test test test junk";

/// Two distinct Hardhat default accounts. Their private keys are
/// publicly known; safe for tests.
const CLIENT_A_PK: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const CLIENT_A_DID: &str = "did:pkh:eip155:1:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const CLIENT_B_PK: &str = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const CLIENT_B_DID: &str = "did:pkh:eip155:1:0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

fn cfg(allow: Vec<String>, storage: PathBuf, max_leaves: usize) -> Config {
    Config {
        server: ServerConfig {
            listen: "127.0.0.1:0".into(),
        },
        identity: IdentityConfig {
            chain_id: 1,
            trust_domain: "timestamp".into(),
            dns: "timestamp.test".into(),
            ip: "127.0.0.1".into(),
        },
        auth: AuthConfig {
            challenge_ttl_secs: 60,
            session_ttl_secs: 600,
            allowed_dids: allow,
        },
        storage: StorageConfig { path: storage },
        epoch: EpochConfig {
            duration_secs: 60,
            max_leaves_per_request: max_leaves,
        },
        anchor_legacy: AnchorConfig::default(),
        // M3 tests assert stub witness payloads byte for byte; keep the
        // EVM live provider off here so the assertions remain stable
        // (no Sepolia RPC dependency during unit/integration tests).
        anchors: AnchorsConfig {
            evm: EvmAnchorConfig {
                enabled: false,
                ..EvmAnchorConfig::default()
            },
            qtsa: QtsaAnchorConfig {
                enabled: false,
                ..QtsaAnchorConfig::default()
            },
        },
    }
}

struct Harness {
    router: Router,
    seal_tx: mpsc::Sender<SealTick>,
    _tmp: TempDir,
}

async fn build_harness() -> Harness {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = cfg(
        vec![CLIENT_A_DID.to_string(), CLIENT_B_DID.to_string()],
        tmp.path().to_path_buf(),
        10_000,
    );
    let identity = ServiceIdentity::from_mnemonic(SERVICE_MNEMONIC, &cfg.identity)
        .await
        .expect("identity");
    let (tx, rx) = mpsc::channel::<SealTick>(8);
    let (router, _state) = build_app(
        cfg,
        identity,
        IdentityClaimOverrides::default(),
        SealDriver::Channel(rx),
    )
    .await
    .expect("build_app");
    Harness {
        router,
        seal_tx: tx,
        _tmp: tmp,
    }
}

fn eip191_sign(message: &str, private_key_hex: &str) -> Vec<u8> {
    use k256::ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, SigningKey};
    let pk = hex::decode(private_key_hex).unwrap();
    let signing_key = SigningKey::from_slice(&pk).unwrap();
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut h = Keccak256::new();
    h.update(prefix.as_bytes());
    h.update(message.as_bytes());
    let prehash: [u8; 32] = h.finalize().into();
    let (sig, rec_id): (k256::ecdsa::Signature, RecoveryId) =
        signing_key.sign_prehash(&prehash).unwrap();
    let mut bytes = [0u8; 65];
    bytes[..64].copy_from_slice(&sig.to_bytes());
    bytes[64] = u8::from(rec_id) + 27;
    bytes.to_vec()
}

async fn read_body(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    if bytes.is_empty() {
        return Value::Null;
    }
    serde_json::from_slice(&bytes).expect("json")
}

async fn mint_bearer_for(router: &Router, did: &str, pk_hex: &str) -> String {
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/auth/challenge?did={did}"))
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let body = read_body(resp).await;
    let nonce = body["nonce"].as_str().unwrap().to_string();
    let message = body["message"].as_str().unwrap().to_string();
    let sig = eip191_sign(&message, pk_hex);
    let payload = serde_json::json!({
        "did": did,
        "nonce": nonce,
        "signature": format!("0x{}", hex::encode(sig)),
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri("/auth/session")
        .header("content-type", "application/json")
        .body(Body::from(payload.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_body(resp).await;
    body["token"].as_str().unwrap().to_string()
}

async fn post_leaves(router: &Router, token: &str, leaves: &[String]) -> (StatusCode, Value) {
    let payload = serde_json::json!({ "leaves": leaves }).to_string();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/leaves")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(payload))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = read_body(resp).await;
    (status, body)
}

async fn get_json(router: &Router, uri: &str, token: Option<&str>) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(Method::GET).uri(uri);
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    let req = builder.body(Body::empty()).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = read_body(resp).await;
    (status, body)
}

fn leaf_hex(prefix: u8) -> String {
    let mut bytes = [0u8; 32];
    for (i, slot) in bytes.iter_mut().enumerate() {
        *slot = prefix.wrapping_add(i as u8);
    }
    format!("0x{}", hex::encode(bytes))
}

async fn drain_seal(harness: &Harness, now: u64) {
    harness.seal_tx.send(SealTick { now }).await.unwrap();
    // Yield enough times for the seal task to drain the queue without
    // closing the channel (other tests in the same harness may seal too).
    for _ in 0..40 {
        tokio::task::yield_now().await;
    }
}

fn parse_hex32(s: &str) -> [u8; 32] {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).expect("hex");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn round_trip_submit_seal_fetch_witness_verify_proof() {
    let h = build_harness().await;
    let token_a = mint_bearer_for(&h.router, CLIENT_A_DID, CLIENT_A_PK).await;

    // Submit three leaves, seal, fetch the witness for one of them.
    let leaves: Vec<String> = (10u8..=12).map(leaf_hex).collect();
    let (status, body) = post_leaves(&h.router, &token_a, &leaves).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");

    drain_seal(&h, 1000).await;

    // Pick the middle leaf; fetch its evm witness.
    let target = &leaves[1];
    let uri = format!("/trees/by-leaf/{target}?method=evm");
    let (status, body) = get_json(&h.router, &uri, Some(&token_a)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let revisions = body["revisions"].as_object().unwrap();
    let file_index = body["file_index"].as_object().unwrap();
    assert_eq!(revisions.len(), 2);
    assert_eq!(file_index.len(), 2);
    // All keys should be 66-char hex strings (`0x` + 64).
    for k in revisions.keys() {
        assert!(k.starts_with("0x") && k.len() == 66, "bad hash key: {k}");
        assert!(file_index.contains_key(k), "file_index missing {k}");
    }

    // Find the TimestampObject (`revision_type` points at the EVM template
    // hash) and verify its inclusion proof + chained previous_revision.
    let target_leaf_bytes = parse_hex32(target);
    let mut found_object = false;
    let mut found_sig = false;
    for rev_value in revisions.values() {
        let rev: AnyRevision = serde_json::from_value(rev_value.clone()).expect("rev json");
        match rev {
            AnyRevision::Typed(_obj) => {
                found_object = true;
                let payloads = rev_value["payloads"].as_object().unwrap();
                assert_eq!(payloads["type"].as_str().unwrap(), "timestamp");
                let merkle_root_hex = payloads["merkle_root"].as_str().unwrap();
                let merkle_root = parse_hex32(merkle_root_hex);
                let proof: Vec<Vec<u8>> = payloads["merkle_proof"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|p| parse_hex32(p.as_str().unwrap()).to_vec())
                    .collect();
                let tree_size = payloads["batch_tree_size"].as_u64().unwrap() as usize;
                let leaf_index = payloads["batch_leaf_index"].as_u64().unwrap() as usize;

                assert!(
                    verify_inclusion(
                        &target_leaf_bytes,
                        leaf_index,
                        tree_size,
                        &proof,
                        &merkle_root,
                        &HashType::Sha3_256
                    ),
                    "inclusion proof failed to verify against stated merkle_root"
                );

                let prev = rev_value["previous_revision"].as_str().unwrap();
                assert_eq!(
                    parse_hex32(prev),
                    target_leaf_bytes,
                    "TimestampObject.previous_revision must be the client leaf"
                );
            }
            AnyRevision::Signature(_) => {
                found_sig = true;
                let signer = rev_value["signer"].as_str().unwrap();
                assert!(
                    signer.starts_with("did:pkh:eip155:1:0x"),
                    "expected did:pkh signer, got {signer}"
                );
                let sig_obj = &rev_value["signature"];
                assert_eq!(sig_obj["signature_type"], "ethereum:eip-191");
            }
            _ => panic!("unexpected revision type"),
        }
    }
    assert!(found_object, "witness pair must include an Object");
    assert!(found_sig, "witness pair must include a Signature");
}

#[tokio::test]
async fn isolation_invariant_403_on_other_dids_leaf_and_tip() {
    let h = build_harness().await;

    let token_a = mint_bearer_for(&h.router, CLIENT_A_DID, CLIENT_A_PK).await;
    let token_b = mint_bearer_for(&h.router, CLIENT_B_DID, CLIENT_B_PK).await;

    // A submits, both leaves go into epoch 1; seal.
    let leaf = leaf_hex(0x42);
    let (status, _) = post_leaves(&h.router, &token_a, std::slice::from_ref(&leaf)).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    drain_seal(&h, 1234).await;

    // A can fetch their own witness.
    let (status, body) = get_json(
        &h.router,
        &format!("/trees/by-leaf/{leaf}?method=evm"),
        Some(&token_a),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let tip = body["revisions"]
        .as_object()
        .unwrap()
        .keys()
        // The signature revision is the "tip" (the one whose hash is NOT
        // referenced as a previous_revision by any other revision in the
        // pair). Either pick is fine for the next probe; pick the one
        // whose revision is a Signature.
        .find(|k| body["revisions"][k]["signer"].is_string())
        .cloned()
        .unwrap();

    // B is denied 403 on A's leaf.
    let (status, body) = get_json(
        &h.router,
        &format!("/trees/by-leaf/{leaf}?method=evm"),
        Some(&token_b),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // B is denied 403 on A's tip.
    let (status, body) = get_json(&h.router, &format!("/trees/{tip}"), Some(&token_b)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn unknown_tip_returns_404_known_tip_for_other_did_returns_403() {
    let h = build_harness().await;
    let token_a = mint_bearer_for(&h.router, CLIENT_A_DID, CLIENT_A_PK).await;
    let token_b = mint_bearer_for(&h.router, CLIENT_B_DID, CLIENT_B_PK).await;

    let unknown_tip = format!("0x{}", "0".repeat(64));
    let (status, _) = get_json(&h.router, &format!("/trees/{unknown_tip}"), Some(&token_b)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let leaf = leaf_hex(0x77);
    let _ = post_leaves(&h.router, &token_a, std::slice::from_ref(&leaf)).await;
    drain_seal(&h, 2000).await;

    // Find A's tip by inspecting /trees as A.
    let (status, body) = get_json(&h.router, "/trees", Some(&token_a)).await;
    assert_eq!(status, StatusCode::OK);
    let tips = body.as_array().unwrap();
    assert!(!tips.is_empty(), "A should own at least one witness tip");
    let tip = tips[0].as_str().unwrap();

    // Same known tip is 403 for B.
    let (status, _) = get_json(&h.router, &format!("/trees/{tip}"), Some(&token_b)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // And A's own access stays 200.
    let (status, _) = get_json(&h.router, &format!("/trees/{tip}"), Some(&token_a)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn trees_list_only_shows_callers_own_tips() {
    let h = build_harness().await;
    let token_a = mint_bearer_for(&h.router, CLIENT_A_DID, CLIENT_A_PK).await;
    let token_b = mint_bearer_for(&h.router, CLIENT_B_DID, CLIENT_B_PK).await;

    let _ = post_leaves(&h.router, &token_a, &[leaf_hex(0x11)]).await;
    let _ = post_leaves(&h.router, &token_b, &[leaf_hex(0xEE)]).await;
    drain_seal(&h, 3000).await;

    // 2 witnesses per leaf (evm + qtsa), but each DID only sees their own.
    let (_, body_a) = get_json(&h.router, "/trees", Some(&token_a)).await;
    let (_, body_b) = get_json(&h.router, "/trees", Some(&token_b)).await;
    let tips_a = body_a.as_array().unwrap();
    let tips_b = body_b.as_array().unwrap();
    assert_eq!(tips_a.len(), 2, "A submitted 1 leaf → 2 method witnesses");
    assert_eq!(tips_b.len(), 2, "B submitted 1 leaf → 2 method witnesses");
    // No overlap between the two sets.
    for t in tips_a {
        assert!(!tips_b.contains(t), "tip {t} leaked across DIDs");
    }
}

#[tokio::test]
async fn trees_epoch_method_union_only_returns_callers_witnesses() {
    let h = build_harness().await;
    let token_a = mint_bearer_for(&h.router, CLIENT_A_DID, CLIENT_A_PK).await;
    let token_b = mint_bearer_for(&h.router, CLIENT_B_DID, CLIENT_B_PK).await;

    // A submits 3 leaves, B submits 2 in the same epoch.
    let a_leaves: Vec<String> = (0xA0u8..=0xA2).map(leaf_hex).collect();
    let b_leaves: Vec<String> = (0xB0u8..=0xB1).map(leaf_hex).collect();
    let _ = post_leaves(&h.router, &token_a, &a_leaves).await;
    let _ = post_leaves(&h.router, &token_b, &b_leaves).await;
    drain_seal(&h, 4000).await;

    // A asks for the EVM union of epoch 1: expect 3 witness pairs = 6 revisions.
    let (status, body) = get_json(&h.router, "/trees?epoch=1&method=evm", Some(&token_a)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let revs = body["revisions"].as_object().unwrap();
    let fi = body["file_index"].as_object().unwrap();
    assert_eq!(revs.len(), 6, "3 leaves × (object+signature) = 6");
    assert_eq!(fi.len(), 6);

    // B asks for the same: expect 2 leaves × 2 = 4.
    let (status, body) = get_json(&h.router, "/trees?epoch=1&method=evm", Some(&token_b)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["revisions"].as_object().unwrap().len(), 4);

    // qTSA result is independent.
    let (_, body) = get_json(&h.router, "/trees?epoch=1&method=qtsa", Some(&token_a)).await;
    assert_eq!(body["revisions"].as_object().unwrap().len(), 6);
}

#[tokio::test]
async fn trees_query_validation() {
    let h = build_harness().await;
    let token = mint_bearer_for(&h.router, CLIENT_A_DID, CLIENT_A_PK).await;

    // epoch without method
    let (status, _) = get_json(&h.router, "/trees?epoch=1", Some(&token)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // method without epoch
    let (status, _) = get_json(&h.router, "/trees?method=evm", Some(&token)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // unknown method
    let (status, _) = get_json(&h.router, "/trees?epoch=1&method=wat", Some(&token)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // by-leaf needs method
    let (status, _) = get_json(
        &h.router,
        &format!("/trees/by-leaf/{}", leaf_hex(0x44)),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // unsealed epoch
    let (status, _) = get_json(&h.router, "/trees?epoch=99&method=evm", Some(&token)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn trees_epoch_method_empty_membership_returns_empty_200() {
    let h = build_harness().await;
    let token_a = mint_bearer_for(&h.router, CLIENT_A_DID, CLIENT_A_PK).await;
    let token_b = mint_bearer_for(&h.router, CLIENT_B_DID, CLIENT_B_PK).await;

    // Only B submits.
    let _ = post_leaves(&h.router, &token_b, &[leaf_hex(0xCC)]).await;
    drain_seal(&h, 5000).await;

    // A asks for the same epoch: known epoch, no membership = empty maps, 200.
    let (status, body) = get_json(&h.router, "/trees?epoch=1&method=evm", Some(&token_a)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revisions"].as_object().unwrap().len(), 0);
    assert_eq!(body["file_index"].as_object().unwrap().len(), 0);
}

#[tokio::test]
async fn witness_retrievable_across_keyspace_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let storage_path = tmp.path().to_path_buf();

    let leaf = leaf_hex(0x99);

    // Boot once: submit, seal, drop everything.
    let captured_tip = {
        let cfg = cfg(vec![CLIENT_A_DID.to_string()], storage_path.clone(), 10_000);
        let identity = ServiceIdentity::from_mnemonic(SERVICE_MNEMONIC, &cfg.identity)
            .await
            .unwrap();
        let (tx, rx) = mpsc::channel::<SealTick>(8);
        let (router, _state) = build_app(
            cfg,
            identity,
            IdentityClaimOverrides::default(),
            SealDriver::Channel(rx),
        )
        .await
        .unwrap();
        let token = mint_bearer_for(&router, CLIENT_A_DID, CLIENT_A_PK).await;
        let _ = post_leaves(&router, &token, std::slice::from_ref(&leaf)).await;
        tx.send(SealTick { now: 7777 }).await.unwrap();
        for _ in 0..40 {
            tokio::task::yield_now().await;
        }
        let (_, body) = get_json(&router, "/trees", Some(&token)).await;
        let tips = body.as_array().unwrap().clone();
        // Drop tx so the seal task can exit, but use std::mem::drop to
        // be explicit.
        drop(tx);
        tips
    };
    let tip = captured_tip[0].as_str().unwrap().to_string();

    // Reopen at the same path.
    let cfg2 = cfg(vec![CLIENT_A_DID.to_string()], storage_path.clone(), 10_000);
    let identity2 = ServiceIdentity::from_mnemonic(SERVICE_MNEMONIC, &cfg2.identity)
        .await
        .unwrap();
    let (_tx2, rx2) = mpsc::channel::<SealTick>(8);
    let (router2, _state2) = build_app(
        cfg2,
        identity2,
        IdentityClaimOverrides::default(),
        SealDriver::Channel(rx2),
    )
    .await
    .unwrap();
    let token2 = mint_bearer_for(&router2, CLIENT_A_DID, CLIENT_A_PK).await;

    let (status, body) = get_json(&router2, &format!("/trees/{tip}"), Some(&token2)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["revisions"].as_object().unwrap().len(), 2);

    // by-leaf still resolves too.
    let (status, _) = get_json(
        &router2,
        &format!("/trees/by-leaf/{leaf}?method=evm"),
        Some(&token2),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn tip_response_shape_matches_aqua_node() {
    // The aqua-node `GET /trees/{tip}` handler does
    // `Json(serde_json::to_value(tree).unwrap_or_default())` where
    // `tree: aqua_rs_sdk::schema::Tree`. So a valid response must
    // deserialise back into the SDK's `Tree` without error.
    let h = build_harness().await;
    let token = mint_bearer_for(&h.router, CLIENT_A_DID, CLIENT_A_PK).await;
    let _ = post_leaves(&h.router, &token, &[leaf_hex(0x33)]).await;
    drain_seal(&h, 8000).await;

    let (_, body) = get_json(&h.router, "/trees", Some(&token)).await;
    let tip = body[0].as_str().unwrap().to_string();
    let (status, body) = get_json(&h.router, &format!("/trees/{tip}"), Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    let _tree: aqua_rs_sdk::schema::tree::Tree =
        serde_json::from_value(body.clone()).expect("response deserialises to Tree");
}
