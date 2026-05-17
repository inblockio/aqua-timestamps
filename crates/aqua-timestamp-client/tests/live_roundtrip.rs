//! Live integration test against the deployed `timestamp.inblock.io`.
//!
//! Disabled by default. Run with:
//!
//! ```bash
//! cargo test -p aqua-timestamp-client --features live-tests --test live_roundtrip -- --nocapture
//! ```
//!
//! Environment variables:
//! - `TIMESTAMP_BASE_URL` (default `https://timestamp.inblock.io`)
//! - `LIVE_TIMEOUT_SECS` (default `900` — 15 min, enough for one ~10 min epoch
//!   to roll over with margin)
//!
//! The test generates an ephemeral secp256k1 key per run. The server's
//! allowlist is empty in production, so any authenticated DID can submit.

#![cfg(feature = "live-tests")]

use std::time::{Duration, Instant};

use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use aqua_timestamp_client::{AnchorMethod, TimestampClient};
use rand::RngCore;

fn ephemeral_signer() -> (String, impl Fn(&str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> + Send + Sync + Clone + 'static) {
    let mut key_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    let wallet = PrivateKeySigner::from_bytes(&key_bytes.into()).expect("valid secp256k1 key");
    let address = wallet.address();
    let did = format!("did:pkh:eip155:1:{}", address.to_checksum(None));
    let signer = move |msg: &str| -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let sig = wallet.sign_message_sync(msg.as_bytes())?;
        let bytes = sig.as_bytes();
        Ok(format!("0x{}", hex::encode(bytes)))
    };
    (did, signer)
}

fn base_url() -> String {
    std::env::var("TIMESTAMP_BASE_URL").unwrap_or_else(|_| "https://timestamp.inblock.io".to_string())
}

fn live_timeout() -> Duration {
    let secs: u64 = std::env::var("LIVE_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(900);
    Duration::from_secs(secs)
}

#[tokio::test]
async fn live_roundtrip_evm_and_qtsa() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("aqua_timestamp_client=info")
        .with_test_writer()
        .try_init();

    let (did, signer) = ephemeral_signer();
    println!("[live] ephemeral DID: {did}");
    println!("[live] base URL: {}", base_url());

    let started = Instant::now();

    let client = TimestampClient::builder()
        .base_url(base_url())
        .my_did(did.clone())
        .signer(signer)
        .poll_interval(Duration::from_secs(10))
        .build()
        .await
        .expect("build live client");

    let server_did = client.server_identity().did.clone();
    println!("[live] server DID: {server_did}");

    // Submit one leaf.
    let mut leaf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut leaf);
    println!("[live] submitting leaf: 0x{}", hex::encode(leaf));
    let receipt = client.submit(&leaf).await.expect("submit");
    println!(
        "[live] epoch {} closes at {}, server-side DID echo: {}",
        receipt.epoch_id, receipt.epoch_closes_at, receipt.submitter_did
    );
    assert_eq!(receipt.submitter_did, did);

    // Await the EVM witness first (epoch must seal). Then qTSA.
    let evm_deadline = live_timeout();
    println!(
        "[live] awaiting EVM witness (max {:?})...",
        evm_deadline
    );
    let evm = client
        .await_witness(&receipt, AnchorMethod::Evm, evm_deadline)
        .await
        .expect("EVM witness");
    println!(
        "[live] EVM witness ok: object_hash={}, signature_hash={}",
        evm.object_hash, evm.signature_hash
    );

    // qTSA should already be ready by the time EVM is (sealed in same epoch).
    let qtsa = client
        .await_witness(&receipt, AnchorMethod::Qtsa, Duration::from_secs(60))
        .await
        .expect("qTSA witness");
    println!(
        "[live] qTSA witness ok: object_hash={}, signature_hash={}",
        qtsa.object_hash, qtsa.signature_hash
    );

    assert_eq!(evm.anchor_method, AnchorMethod::Evm);
    assert_eq!(qtsa.anchor_method, AnchorMethod::Qtsa);
    assert_ne!(evm.object_hash, qtsa.object_hash, "anchor methods must produce distinct objects");

    println!(
        "[live] roundtrip OK in {:.1}s",
        started.elapsed().as_secs_f64()
    );
}
