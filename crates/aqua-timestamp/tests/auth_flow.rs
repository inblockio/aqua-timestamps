//! End-to-end auth flow against the in-process Axum app.
//!
//! Covers:
//!   * `/auth/challenge` issues a CAIP-122 message and nonce.
//!   * `/auth/session` accepts an EIP-191 signature over that message
//!     and mints a bearer.
//!   * The bearer extractor on `POST /v1/leaves` returns 401 without a
//!     token, 403 for a non-allowlisted DID, 202 once the DID is added.

use aqua_timestamp::{
    build_app,
    config::{AuthConfig, Config, EpochConfig, IdentityConfig, ServerConfig, StorageConfig},
    identity::{IdentityClaimOverrides, ServiceIdentity},
    SealDriver,
};
use axum::{
    body::{to_bytes, Body},
    http::{Method, Request, StatusCode},
};
use serde_json::Value;
use sha3::{Digest, Keccak256};
use tempfile::TempDir;
use tower::ServiceExt;

/// Hardhat test mnemonic.
const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";

/// The matching private key (32 bytes). Public domain Hardhat default.
const TEST_PRIVATE_KEY_HEX: &str =
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

fn service_config(allowed_dids: Vec<String>, storage_path: std::path::PathBuf) -> Config {
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
            allowed_dids,
        },
        storage: StorageConfig { path: storage_path },
        epoch: EpochConfig {
            duration_secs: 600,
            max_leaves_per_request: 10_000,
        },
    }
}

async fn build(allowed: Vec<String>) -> (axum::Router, TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = service_config(allowed, tmp.path().to_path_buf());
    let identity = ServiceIdentity::from_mnemonic(TEST_MNEMONIC, &cfg.identity)
        .await
        .expect("identity");
    let (router, _state) = build_app(
        cfg,
        identity,
        IdentityClaimOverrides::default(),
        SealDriver::Off,
    )
    .await
    .expect("build_app");
    (router, tmp)
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

const CLIENT_DID: &str = "did:pkh:eip155:1:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

async fn read_body(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).expect("json")
}

#[tokio::test]
async fn full_auth_dance() {
    let (router, _tmp) = build(vec![CLIENT_DID.to_string()]).await;

    // 1. challenge
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/auth/challenge?did={CLIENT_DID}"))
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_body(resp).await;
    let nonce = body["nonce"].as_str().unwrap().to_string();
    let message = body["message"].as_str().unwrap().to_string();
    assert!(
        message.contains(CLIENT_DID)
            || message.contains("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
    );
    assert!(body["expires_at"].is_number());

    // 2. sign + session
    let sig = eip191_sign(&message, TEST_PRIVATE_KEY_HEX);
    let sig_hex = format!("0x{}", hex::encode(&sig));
    let body = serde_json::json!({
        "did": CLIENT_DID,
        "nonce": nonce,
        "signature": sig_hex,
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri("/auth/session")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_body(resp).await;
    let token = body["token"].as_str().unwrap().to_string();
    assert_eq!(body["did"].as_str().unwrap(), CLIENT_DID);
    assert!(body["valid_until"].is_number());
    assert!(body["created_at"].is_number());

    // 3. protected route, no auth: bearer is the first extractor so a
    //    request with no auth header is rejected before the JSON body
    //    is inspected.
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/leaves")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"leaves":["0x11"]}"#))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 4. protected route, valid bearer + valid batch → 202.
    let leaf = format!("0x{}", "11".repeat(32));
    let payload = serde_json::json!({ "leaves": [leaf] }).to_string();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/leaves")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(payload))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn non_allowlisted_did_is_forbidden() {
    let other_did = "did:pkh:eip155:1:0x0000000000000000000000000000000000000001";
    let (router, _tmp) = build(vec![other_did.to_string()]).await;

    // Get challenge for client DID.
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/auth/challenge?did={CLIENT_DID}"))
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let body = read_body(resp).await;
    let nonce = body["nonce"].as_str().unwrap().to_string();
    let message = body["message"].as_str().unwrap().to_string();

    // Sign + mint session.
    let sig = eip191_sign(&message, TEST_PRIVATE_KEY_HEX);
    let body = serde_json::json!({
        "did": CLIENT_DID,
        "nonce": nonce,
        "signature": format!("0x{}", hex::encode(sig)),
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri("/auth/session")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_body(resp).await;
    let token = body["token"].as_str().unwrap().to_string();

    let leaf = format!("0x{}", "22".repeat(32));
    let payload = serde_json::json!({ "leaves": [leaf] }).to_string();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/leaves")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(payload))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn bad_bearer_is_rejected() {
    let (router, _tmp) = build(vec![]).await;
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/leaves")
        .header("authorization", "Bearer not-a-real-token")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"leaves":[]}"#))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn caip122_round_trip_via_aqua_auth() {
    // Exercises the same path the auth route does, but without HTTP:
    // create challenge → sign → verify via aqua_auth::verify_caip122.
    use aqua_auth::{verify_caip122, ChallengeStore};

    let store = ChallengeStore::new(60, "test".into(), "http://test".into());
    let challenge = store.create(CLIENT_DID).unwrap();
    let sig = eip191_sign(&challenge.message, TEST_PRIVATE_KEY_HEX);
    assert!(verify_caip122(CLIENT_DID, &challenge.message, &sig).unwrap());
}
