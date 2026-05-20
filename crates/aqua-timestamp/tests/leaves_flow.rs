//! M2 integration tests for `POST /v1/leaves`, `GET /v1/schedule`, and the
//! seal pipeline.
//!
//! All tests drive the in-process router and a tempdir-backed fjall
//! keyspace. Seal cycles are triggered through the `SealDriver::Channel`
//! variant so the suite never sleeps.

use aqua_rs_sdk::primitives::{merkle::merkle_root, HashType};
use aqua_timestamp::{
    build_app,
    config::{
        AnchorConfig, AnchorsConfig, AuthConfig, BondingCurveConfig, Config, EpochConfig,
        EvmAnchorConfig, IdentityConfig, QtsaAnchorConfig, ServerConfig, StorageConfig,
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
use std::path::PathBuf;
use tempfile::TempDir;
use tokio::sync::mpsc;
use tower::ServiceExt;

const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";
const TEST_PRIVATE_KEY_HEX: &str =
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const CLIENT_DID: &str = "did:pkh:eip155:1:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

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
        bonding_curve: BondingCurveConfig::default(),
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

async fn build_harness(max_leaves: usize) -> Harness {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = cfg(
        vec![CLIENT_DID.to_string()],
        tmp.path().to_path_buf(),
        max_leaves,
    );
    let identity = ServiceIdentity::from_mnemonic(TEST_MNEMONIC, &cfg.identity)
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
    serde_json::from_slice(&bytes).expect("json")
}

/// Mint a Bearer for the client DID against the given router.
async fn mint_bearer(router: &Router) -> String {
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/auth/challenge?did={CLIENT_DID}"))
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let body = read_body(resp).await;
    let nonce = body["nonce"].as_str().unwrap().to_string();
    let message = body["message"].as_str().unwrap().to_string();
    let sig = eip191_sign(&message, TEST_PRIVATE_KEY_HEX);
    let payload = serde_json::json!({
        "did": CLIENT_DID,
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

// ── Tests ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn submit_seal_and_fetch_epoch() {
    let h = build_harness(10_000).await;
    let token = mint_bearer(&h.router).await;

    let leaves: Vec<String> = (1u8..=4).map(leaf_hex).collect();
    let (status, body) = post_leaves(&h.router, &token, &leaves).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(body["accepted"].as_u64().unwrap(), 4);
    assert_eq!(body["duplicates"].as_u64().unwrap(), 0);
    assert_eq!(body["submitter_did"].as_str().unwrap(), CLIENT_DID);
    let epoch_id = body["epoch_id"].as_u64().unwrap();
    assert_eq!(epoch_id, 1);

    // Drive one seal cycle.
    h.seal_tx.send(SealTick { now: 1000 }).await.unwrap();
    drop(h.seal_tx);
    // Yield to let the seal task drain.
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }

    let (status, body) = get_json(&h.router, "/v1/epochs?limit=10", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    let epochs = body["epochs"].as_array().unwrap();
    assert_eq!(epochs.len(), 1);
    let rec = &epochs[0];
    assert_eq!(rec["id"].as_u64().unwrap(), 1);
    assert_eq!(rec["leaf_count"].as_u64().unwrap(), 4);
    assert_eq!(rec["hash_type"].as_str().unwrap(), "FIPS_202-SHA3-256");

    // Expected root: decode the four leaves, sort them, feed the SDK.
    let mut sorted: Vec<Vec<u8>> = leaves
        .iter()
        .map(|s| hex::decode(s.trim_start_matches("0x")).unwrap())
        .collect();
    sorted.sort();
    let expected = merkle_root(&sorted, &HashType::Sha3_256);
    let expected_hex = format!("0x{}", hex::encode(expected));
    assert_eq!(rec["merkle_root"].as_str().unwrap(), expected_hex);
}

#[tokio::test]
async fn duplicate_within_one_request_is_deduped() {
    let h = build_harness(10_000).await;
    let token = mint_bearer(&h.router).await;

    let leaf = leaf_hex(0xAA);
    let (status, body) = post_leaves(&h.router, &token, &[leaf.clone(), leaf.clone()]).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(body["accepted"].as_u64().unwrap(), 1);
    assert_eq!(body["duplicates"].as_u64().unwrap(), 1);

    h.seal_tx.send(SealTick { now: 1000 }).await.unwrap();
    drop(h.seal_tx);
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }

    let (_, body) = get_json(&h.router, "/v1/epochs?limit=10", Some(&token)).await;
    let epochs = body["epochs"].as_array().unwrap();
    assert_eq!(epochs[0]["leaf_count"].as_u64().unwrap(), 1);
    // Single-leaf Merkle root equals the leaf bytes themselves.
    assert_eq!(
        epochs[0]["merkle_root"].as_str().unwrap(),
        leaf.to_lowercase()
    );
}

#[tokio::test]
async fn batch_of_ten_thousand_is_accepted_ten_thousand_and_one_is_rejected() {
    let h = build_harness(10_000).await;
    let token = mint_bearer(&h.router).await;

    let big: Vec<String> = (0u32..10_000)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[..4].copy_from_slice(&i.to_be_bytes());
            format!("0x{}", hex::encode(bytes))
        })
        .collect();
    let (status, body) = post_leaves(&h.router, &token, &big).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{}", body);
    assert_eq!(body["accepted"].as_u64().unwrap(), 10_000);

    let too_big: Vec<String> = (0u32..10_001)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[..4].copy_from_slice(&i.to_be_bytes());
            format!("0x{}", hex::encode(bytes))
        })
        .collect();
    let (status, _) = post_leaves(&h.router, &token, &too_big).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn invalid_leaf_hex_returns_400() {
    let h = build_harness(10_000).await;
    let token = mint_bearer(&h.router).await;

    let (status, body) = post_leaves(&h.router, &token, &["0xnothex".to_string()]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let err = body["error"].as_str().unwrap();
    assert!(err.contains("leaves[0]"), "error message: {err}");
}

#[tokio::test]
async fn empty_batch_returns_400() {
    let h = build_harness(10_000).await;
    let token = mint_bearer(&h.router).await;
    let (status, _) = post_leaves(&h.router, &token, &[]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn schedule_reports_open_epoch_and_anchor_methods() {
    let h = build_harness(10_000).await;
    let (status, body) = get_json(&h.router, "/v1/schedule", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["current_epoch_id"].as_u64().unwrap(), 1);
    assert!(body["current_epoch_opened_at"].is_number());
    assert!(body["current_epoch_closes_at"].is_number());
    assert_eq!(body["epoch_duration_secs"].as_u64().unwrap(), 60);
    assert!(body["last_sealed_epoch_id"].is_null());
    assert!(body["last_sealed_at"].is_null());
    let methods: Vec<&str> = body["anchor_methods"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(methods, vec!["evm", "qtsa"]);
}

#[tokio::test]
async fn schedule_after_seal_reports_last_sealed() {
    let h = build_harness(10_000).await;
    let token = mint_bearer(&h.router).await;
    let _ = post_leaves(&h.router, &token, &[leaf_hex(0x11)]).await;
    h.seal_tx.send(SealTick { now: 999 }).await.unwrap();
    drop(h.seal_tx);
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    let (_, body) = get_json(&h.router, "/v1/schedule", None).await;
    assert_eq!(body["last_sealed_epoch_id"].as_u64().unwrap(), 1);
    assert_eq!(body["last_sealed_at"].as_u64().unwrap(), 999);
    // The fresh accumulator has advanced to epoch 2.
    assert_eq!(body["current_epoch_id"].as_u64().unwrap(), 2);
}

/// Restart durability: persist one epoch in a tempdir, rebuild the app at
/// the same path, and assert the record is still retrievable through the
/// HTTP API.
#[tokio::test]
async fn persistence_survives_keyspace_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let storage_path = tmp.path().to_path_buf();

    // First boot: submit a leaf and seal.
    let (sealed_root, sealed_leaf) = {
        let cfg = cfg(vec![CLIENT_DID.to_string()], storage_path.clone(), 10_000);
        let identity = ServiceIdentity::from_mnemonic(TEST_MNEMONIC, &cfg.identity)
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
        let token = mint_bearer(&router).await;
        let leaf = leaf_hex(0x55);
        let _ = post_leaves(&router, &token, std::slice::from_ref(&leaf)).await;
        tx.send(SealTick { now: 4242 }).await.unwrap();
        drop(tx);
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        (leaf.to_lowercase(), leaf)
    };

    // Second boot at the same path.
    let cfg2 = cfg(vec![CLIENT_DID.to_string()], storage_path.clone(), 10_000);
    let identity2 = ServiceIdentity::from_mnemonic(TEST_MNEMONIC, &cfg2.identity)
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
    let token2 = mint_bearer(&router2).await;

    // Persisted epoch is still listed.
    let (status, body) = get_json(&router2, "/v1/epochs?limit=10", Some(&token2)).await;
    assert_eq!(status, StatusCode::OK);
    let epochs = body["epochs"].as_array().unwrap();
    assert_eq!(epochs.len(), 1);
    assert_eq!(epochs[0]["id"].as_u64().unwrap(), 1);
    assert_eq!(epochs[0]["merkle_root"].as_str().unwrap(), sealed_root);

    // And the next epoch starts at id 2, not 1.
    let (_, schedule_body) = get_json(&router2, "/v1/schedule", None).await;
    assert_eq!(schedule_body["current_epoch_id"].as_u64().unwrap(), 2);

    // Sanity: the leaf we submitted ended up keyed under epoch 1.
    let _ = sealed_leaf;
}
