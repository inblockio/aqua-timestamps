//! Live Sepolia anchor integration test (M4).
//!
//! This test is `#[ignore]` AND gated on `AQUA_TIMESTAMP_LIVE_SEPOLIA=1`
//! so the default `cargo test --workspace` pass does NOT burn gas on
//! every run. Run it explicitly with:
//!
//! ```sh
//! AQUA_TIMESTAMP_LIVE_SEPOLIA=1 \
//! AQUA_TIMESTAMP_ANCHOR_MNEMONIC="<funded mnemonic>" \
//!     cargo test -p aqua-timestamp --test live_sepolia_anchor \
//!         -- --ignored --nocapture
//! ```
//!
//! Preconditions:
//! - The mnemonic in `AQUA_TIMESTAMP_ANCHOR_MNEMONIC` derives to a
//!   funded Sepolia address (>= ~0.001 ETH is plenty for one anchor).
//! - The public RPC `https://ethereum-sepolia-rpc.publicnode.com` is
//!   reachable from the test host.
//!
//! What it asserts:
//! 1. After one submit + seal, the per-leaf EVM witness payload's
//!    `transaction_hash` is `0x` + 64 hex chars AND not all zeros.
//! 2. The funded wallet's `eth_getBalance` strictly decreased by the
//!    gas cost between before-seal and after-seal.

use std::path::PathBuf;

use aqua_rs_sdk::primitives::get_wallet;
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

const SEPOLIA_RPC: &str = "https://ethereum-sepolia-rpc.publicnode.com";
const ENV_GATE: &str = "AQUA_TIMESTAMP_LIVE_SEPOLIA";
const MNEMONIC_ENV: &str = "AQUA_TIMESTAMP_ANCHOR_MNEMONIC";

fn cfg(allow: Vec<String>, storage: PathBuf) -> Config {
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
            max_leaves_per_request: 1_000,
        },
        anchor_legacy: AnchorConfig::default(),
        anchors: AnchorsConfig {
            evm: EvmAnchorConfig {
                enabled: true,
                rpc_url: SEPOLIA_RPC.to_string(),
                chain: "sepolia".to_string(),
                network_label: "sepolia".to_string(),
            },
            // The Sepolia anchor test exercises only the EVM path; leave
            // qTSA off so the test does not depend on Sectigo reachability.
            qtsa: QtsaAnchorConfig {
                enabled: false,
                ..QtsaAnchorConfig::default()
            },
        },
    }
}

fn eip191_sign(message: &str, private_key_hex: &str) -> Vec<u8> {
    use k256::ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, SigningKey};
    let pk = hex::decode(private_key_hex.trim_start_matches("0x")).unwrap();
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

async fn mint_bearer(router: &Router, did: &str, pk_hex: &str) -> String {
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

async fn rpc_get_balance(address: &str) -> u128 {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getBalance",
        "params": [address, "latest"],
    });
    let resp = reqwest::Client::new()
        .post(SEPOLIA_RPC)
        .json(&body)
        .send()
        .await
        .expect("rpc send");
    let v: Value = resp.json().await.expect("rpc json");
    let hex = v["result"].as_str().expect("balance result").to_string();
    let hex = hex.trim_start_matches("0x");
    u128::from_str_radix(hex, 16).expect("balance hex")
}

#[tokio::test]
#[ignore = "live Sepolia: opt in with AQUA_TIMESTAMP_LIVE_SEPOLIA=1"]
async fn live_sepolia_seal_produces_real_tx_and_charges_gas() {
    if std::env::var(ENV_GATE).ok().as_deref() != Some("1") {
        eprintln!("skipping: set {ENV_GATE}=1 to run");
        return;
    }
    let mnemonic = std::env::var(MNEMONIC_ENV).expect(MNEMONIC_ENV);
    assert!(!mnemonic.trim().is_empty(), "{MNEMONIC_ENV} is empty");

    let tmp = TempDir::new().expect("tempdir");
    let cfg = cfg(vec![], tmp.path().to_path_buf());
    let identity = ServiceIdentity::from_mnemonic(&mnemonic, &cfg.identity)
        .await
        .expect("identity");
    let service_addr = format!("0x{}", identity.address_eip55.trim_start_matches("0x"));
    eprintln!("service wallet: {service_addr}");

    // Pre-seal balance.
    let balance_before = rpc_get_balance(&service_addr).await;
    eprintln!("balance before: {balance_before} wei");
    assert!(
        balance_before > 0,
        "wallet has zero balance; fund {service_addr} on Sepolia and retry"
    );

    // Build a separate client key so we can authenticate (any random
    // secp256k1 keypair works; the service mnemonic is reused here for
    // simplicity; the bearer DID is the service's own DID with empty
    // allowlist => any authenticated DID accepted).
    let (_addr, eip55_addr, client_pk_hex) = get_wallet(&mnemonic).await.expect("derive");
    let client_did = format!("did:pkh:eip155:1:{eip55_addr}");

    let (tx, rx) = mpsc::channel::<SealTick>(8);
    let (router, _state) = build_app(
        cfg,
        identity,
        IdentityClaimOverrides::default(),
        SealDriver::Channel(rx),
    )
    .await
    .expect("build_app");

    let token = mint_bearer(&router, &client_did, &client_pk_hex).await;
    // Submit one random-ish leaf.
    let mut leaf = [0u8; 32];
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let mut h = Keccak256::new();
    h.update(seed.to_le_bytes());
    let digest = h.finalize();
    leaf.copy_from_slice(&digest);
    let leaf_hex = format!("0x{}", hex::encode(leaf));

    let payload = serde_json::json!({ "leaves": [leaf_hex] }).to_string();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/leaves")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(payload))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    // Trigger the seal. This blocks until the Sepolia tx hash is known
    // (the SDK's CliEthTimestamper does NOT wait for the receipt; it
    // returns as soon as the tx is broadcast).
    tx.send(SealTick { now: seed }).await.unwrap();
    // Give the seal task ample wall-clock time to talk to the RPC.
    let mut found = false;
    let mut last_body = Value::Null;
    for _ in 0..120 {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("/trees/by-leaf/{leaf_hex}?method=evm"))
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        if resp.status() == StatusCode::OK {
            last_body = read_body(resp).await;
            found = true;
            break;
        }
    }
    assert!(found, "witness never appeared; last body: {last_body}");

    // Pull the transaction_hash out of the TimestampObject payload.
    let revisions = last_body["revisions"].as_object().unwrap();
    let mut tx_hash: Option<String> = None;
    for rev in revisions.values() {
        if let Some(payloads) = rev.get("payloads") {
            if let Some(h) = payloads.get("transaction_hash").and_then(Value::as_str) {
                tx_hash = Some(h.to_string());
                break;
            }
        }
    }
    let tx_hash = tx_hash.expect("witness payload missing transaction_hash");
    eprintln!("got tx_hash: {tx_hash}");
    let stripped = tx_hash.trim_start_matches("0x");
    assert_eq!(stripped.len(), 64, "transaction_hash must be 64 hex chars");
    assert!(
        stripped.chars().any(|c| c != '0'),
        "transaction_hash is all zeros; live anchor did not run"
    );
    // Lightly validate hex: every char must be 0-9 / a-f.
    assert!(
        stripped.chars().all(|c| c.is_ascii_hexdigit()),
        "transaction_hash has non-hex characters: {tx_hash}"
    );

    // Post-seal balance must be strictly lower (gas consumed).
    let balance_after = rpc_get_balance(&service_addr).await;
    eprintln!("balance after: {balance_after} wei");
    assert!(
        balance_after < balance_before,
        "balance did not decrease: before={balance_before} after={balance_after}"
    );

    drop(tx);
}
