//! Integration tests for `aqua-timestamp-client`. Every test stands up a
//! local `wiremock` server, mounts the relevant endpoints, builds a real
//! `TimestampClient`, and exercises the public API. No live network.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use aqua_timestamp_client::{
    AnchorMethod, ClientError, OnRotation, RotationDecision, ServerRotation, TimestampClient,
};
use serde_json::json;
use wiremock::matchers::{method as wmethod, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::*;

// ── builder validation ────────────────────────────────────────────────────

#[tokio::test]
async fn build_requires_base_url() {
    let err = TimestampClient::builder()
        .my_did("did:test")
        .signer(make_test_signer())
        .build()
        .await
        .expect_err("build should fail");
    assert!(matches!(err, ClientError::Invalid(ref m) if m.contains("base_url")));
}

#[tokio::test]
async fn build_requires_my_did() {
    let err = TimestampClient::builder()
        .base_url("https://example.com")
        .signer(make_test_signer())
        .build()
        .await
        .expect_err("build should fail");
    assert!(matches!(err, ClientError::Invalid(ref m) if m.contains("my_did")));
}

#[tokio::test]
async fn build_requires_signer() {
    let err = TimestampClient::builder()
        .base_url("https://example.com")
        .my_did("did:test")
        .build()
        .await
        .expect_err("build should fail");
    assert!(matches!(err, ClientError::Invalid(ref m) if m.contains("signer")));
}

// ── bootstrap (TLS + well-known) ──────────────────────────────────────────

#[tokio::test]
async fn build_bootstraps_via_well_known() {
    let server = MockServer::start().await;
    let (did, identity) = build_identity_response(&SERVER_PRIVATE_KEY, "test.example").await;
    mount_identity(&server, identity).await;
    mount_auth(&server).await;

    let client = TimestampClient::builder()
        .base_url(server.uri())
        .my_did(client_did())
        .signer(make_test_signer())
        .build()
        .await
        .expect("build should succeed");

    assert_eq!(client.server_identity().did, did);
    assert!(client.rotation_detected().is_none());
}

#[tokio::test]
async fn build_rejects_unreachable_well_known() {
    let server = MockServer::start().await;
    // No identity mock mounted, so any GET 404s.
    let err = TimestampClient::builder()
        .base_url(server.uri())
        .my_did(client_did())
        .signer(make_test_signer())
        .build()
        .await
        .expect_err("build should fail");
    assert!(matches!(err, ClientError::IdentityDiscovery { .. }));
}

#[tokio::test]
async fn build_rejects_unsigned_identity_claim() {
    let server = MockServer::start().await;
    // Identity response without a Signature revision in the tree.
    let body = json!({
        "protocol": "aqua-timestamp",
        "version": "test",
        "server_did": "did:pkh:eip155:1:0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "identity_claim": { "revisions": {}, "file_index": {} }
    });
    mount_identity(&server, body).await;

    let err = TimestampClient::builder()
        .base_url(server.uri())
        .my_did(client_did())
        .signer(make_test_signer())
        .build()
        .await
        .expect_err("build should fail");
    assert!(matches!(err, ClientError::IdentityDiscovery { .. }));
}

// ── rotation policies ─────────────────────────────────────────────────────

#[tokio::test]
async fn rotation_refuse_blocks_unknown_did() {
    let server = MockServer::start().await;
    let (real_did, identity) = build_identity_response(&SERVER_PRIVATE_KEY, "test.example").await;
    mount_identity(&server, identity).await;
    mount_auth(&server).await;
    let _ = real_did;

    let err = TimestampClient::builder()
        .base_url(server.uri())
        .my_did(client_did())
        .signer(make_test_signer())
        .expect_server_did("did:pkh:eip155:1:0xfeedfacefeedfacefeedfacefeedfacefeedface", OnRotation::Refuse)
        .build()
        .await
        .expect_err("build should fail under refuse policy");

    assert!(matches!(err, ClientError::ServerIdentityRotated { .. }));
}

#[tokio::test]
async fn rotation_warn_proceeds_with_new_did() {
    let server = MockServer::start().await;
    let (did, identity) = build_identity_response(&SERVER_PRIVATE_KEY, "test.example").await;
    mount_identity(&server, identity).await;
    mount_auth(&server).await;

    let client = TimestampClient::builder()
        .base_url(server.uri())
        .my_did(client_did())
        .signer(make_test_signer())
        .expect_server_did(
            "did:pkh:eip155:1:0xfeedfacefeedfacefeedfacefeedfacefeedface",
            OnRotation::Warn,
        )
        .build()
        .await
        .expect("warn should still build");

    assert_eq!(client.server_identity().did, did);
    let rot = client
        .rotation_detected()
        .expect("rotation should be detected");
    assert_eq!(rot.discovered_did, did);
}

#[tokio::test]
async fn rotation_custom_accept() {
    let server = MockServer::start().await;
    let (did, identity) = build_identity_response(&SERVER_PRIVATE_KEY, "test.example").await;
    mount_identity(&server, identity).await;
    mount_auth(&server).await;

    let observed = Arc::new(AtomicUsize::new(0));
    let observed_cb = observed.clone();

    let client = TimestampClient::builder()
        .base_url(server.uri())
        .my_did(client_did())
        .signer(make_test_signer())
        .expect_server_did(
            "did:pkh:eip155:1:0xfeedfacefeedfacefeedfacefeedfacefeedface",
            OnRotation::Custom(Arc::new(move |_rot: &ServerRotation| {
                observed_cb.fetch_add(1, Ordering::SeqCst);
                RotationDecision::Accept
            })),
        )
        .build()
        .await
        .expect("custom accept should build");

    assert_eq!(client.server_identity().did, did);
    assert_eq!(observed.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn rotation_custom_reject() {
    let server = MockServer::start().await;
    let (_, identity) = build_identity_response(&SERVER_PRIVATE_KEY, "test.example").await;
    mount_identity(&server, identity).await;
    mount_auth(&server).await;

    let err = TimestampClient::builder()
        .base_url(server.uri())
        .my_did(client_did())
        .signer(make_test_signer())
        .expect_server_did(
            "did:pkh:eip155:1:0xfeedfacefeedfacefeedfacefeedfacefeedface",
            OnRotation::Custom(Arc::new(|_| RotationDecision::Reject)),
        )
        .build()
        .await
        .expect_err("custom reject should refuse build");

    assert!(matches!(err, ClientError::ServerIdentityRotated { .. }));
}

#[tokio::test]
async fn rotation_same_did_no_rotation_detected() {
    let server = MockServer::start().await;
    let (did, identity) = build_identity_response(&SERVER_PRIVATE_KEY, "test.example").await;
    mount_identity(&server, identity).await;
    mount_auth(&server).await;

    let client = TimestampClient::builder()
        .base_url(server.uri())
        .my_did(client_did())
        .signer(make_test_signer())
        .expect_server_did(did.clone(), OnRotation::Refuse)
        .build()
        .await
        .expect("same did should pass refuse policy");

    assert_eq!(client.server_identity().did, did);
    assert!(client.rotation_detected().is_none());
}

// ── schedule (public endpoint) ────────────────────────────────────────────

#[tokio::test]
async fn schedule_returns_current_epoch() {
    let server = MockServer::start().await;
    let (_, identity) = build_identity_response(&SERVER_PRIVATE_KEY, "test.example").await;
    mount_identity(&server, identity).await;
    mount_auth(&server).await;
    mount_schedule(&server, 42, Some(41)).await;

    let client = TimestampClient::builder()
        .base_url(server.uri())
        .my_did(client_did())
        .signer(make_test_signer())
        .build()
        .await
        .expect("build");

    let sched = client.schedule().await.expect("schedule");
    assert_eq!(sched.current_epoch_id, 42);
    assert_eq!(sched.last_sealed_epoch_id, Some(41));
    assert_eq!(sched.epoch_duration_secs, 600);
}

// ── submit ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn submit_returns_receipt() {
    let server = MockServer::start().await;
    let (_, identity) = build_identity_response(&SERVER_PRIVATE_KEY, "test.example").await;
    mount_identity(&server, identity).await;
    mount_auth(&server).await;
    mount_submit(&server, 42, &client_did()).await;

    let client = TimestampClient::builder()
        .base_url(server.uri())
        .my_did(client_did())
        .signer(make_test_signer())
        .build()
        .await
        .expect("build");

    let leaf = [0xab; 32];
    let receipt = client.submit(&leaf).await.expect("submit");
    assert_eq!(receipt.leaf, leaf);
    assert_eq!(receipt.epoch_id, 42);
    assert_eq!(receipt.submitter_did, client_did());
}

#[tokio::test]
async fn submit_many_returns_per_leaf_receipts() {
    let server = MockServer::start().await;
    let (_, identity) = build_identity_response(&SERVER_PRIVATE_KEY, "test.example").await;
    mount_identity(&server, identity).await;
    mount_auth(&server).await;
    mount_submit(&server, 7, &client_did()).await;

    let client = TimestampClient::builder()
        .base_url(server.uri())
        .my_did(client_did())
        .signer(make_test_signer())
        .build()
        .await
        .expect("build");

    let hashes = vec![[0x01; 32], [0x02; 32], [0x03; 32]];
    let receipts = client.submit_many(&hashes).await.expect("submit_many");
    assert_eq!(receipts.len(), 3);
    for (r, h) in receipts.iter().zip(&hashes) {
        assert_eq!(&r.leaf, h);
        assert_eq!(r.epoch_id, 7);
    }
}

#[tokio::test]
async fn submit_many_rejects_empty() {
    let server = MockServer::start().await;
    let (_, identity) = build_identity_response(&SERVER_PRIVATE_KEY, "test.example").await;
    mount_identity(&server, identity).await;
    mount_auth(&server).await;

    let client = TimestampClient::builder()
        .base_url(server.uri())
        .my_did(client_did())
        .signer(make_test_signer())
        .build()
        .await
        .expect("build");

    let err = client.submit_many(&[]).await.expect_err("empty submit");
    assert!(matches!(err, ClientError::Invalid(_)));
}

// ── witness fetch ─────────────────────────────────────────────────────────

#[tokio::test]
async fn try_fetch_witness_returns_none_on_404() {
    let server = MockServer::start().await;
    let (_, identity) = build_identity_response(&SERVER_PRIVATE_KEY, "test.example").await;
    mount_identity(&server, identity).await;
    mount_auth(&server).await;
    mount_by_leaf_404(&server).await;

    let client = TimestampClient::builder()
        .base_url(server.uri())
        .my_did(client_did())
        .signer(make_test_signer())
        .build()
        .await
        .expect("build");

    let result = client
        .try_fetch_witness(&[0xab; 32], AnchorMethod::Evm)
        .await
        .expect("fetch should not error on 404");
    assert!(result.is_none());
}

#[tokio::test]
async fn try_fetch_witness_returns_verified_pair() {
    let server = MockServer::start().await;
    let (_, identity) = build_identity_response(&SERVER_PRIVATE_KEY, "test.example").await;
    mount_identity(&server, identity).await;
    mount_auth(&server).await;

    let leaf = [0xcd; 32];
    let witness = build_witness_tree(&SERVER_PRIVATE_KEY, &leaf).await;
    mount_by_leaf_ok(&server, witness).await;

    let client = TimestampClient::builder()
        .base_url(server.uri())
        .my_did(client_did())
        .signer(make_test_signer())
        .build()
        .await
        .expect("build");

    let pair = client
        .try_fetch_witness(&leaf, AnchorMethod::Evm)
        .await
        .expect("fetch")
        .expect("witness should be present");
    assert_eq!(pair.anchor_method, AnchorMethod::Evm);
}

#[tokio::test]
async fn try_fetch_witness_rejects_wrong_signer() {
    let server = MockServer::start().await;
    // Real server identity uses SERVER_PRIVATE_KEY...
    let (_, identity) = build_identity_response(&SERVER_PRIVATE_KEY, "test.example").await;
    mount_identity(&server, identity).await;
    mount_auth(&server).await;

    // ...but the witness is signed by SERVER_PRIVATE_KEY_ALT, simulating a
    // tampered or forged response.
    let leaf = [0x33; 32];
    let bad_witness = build_witness_tree(&SERVER_PRIVATE_KEY_ALT, &leaf).await;
    mount_by_leaf_ok(&server, bad_witness).await;

    let client = TimestampClient::builder()
        .base_url(server.uri())
        .my_did(client_did())
        .signer(make_test_signer())
        .build()
        .await
        .expect("build");

    let err = client
        .try_fetch_witness(&leaf, AnchorMethod::Evm)
        .await
        .expect_err("forged witness should be rejected");
    assert!(matches!(err, ClientError::SignatureMismatch));
}

// ── await_witness ─────────────────────────────────────────────────────────

#[tokio::test]
async fn await_witness_times_out_when_epoch_not_sealed() {
    let server = MockServer::start().await;
    let (_, identity) = build_identity_response(&SERVER_PRIVATE_KEY, "test.example").await;
    mount_identity(&server, identity).await;
    mount_auth(&server).await;
    mount_submit(&server, 100, &client_did()).await;
    mount_schedule(&server, 100, Some(99)).await; // epoch 100 not yet sealed
    mount_by_leaf_404(&server).await;

    let client = TimestampClient::builder()
        .base_url(server.uri())
        .my_did(client_did())
        .signer(make_test_signer())
        .poll_interval(Duration::from_millis(50))
        .build()
        .await
        .expect("build");

    let receipt = client.submit(&[0xee; 32]).await.expect("submit");
    let err = client
        .await_witness(&receipt, AnchorMethod::Evm, Duration::from_millis(200))
        .await
        .expect_err("should time out");
    assert!(matches!(err, ClientError::Timeout { .. }));
}

#[tokio::test]
async fn await_witness_returns_after_seal() {
    let server = MockServer::start().await;
    let (_, identity) = build_identity_response(&SERVER_PRIVATE_KEY, "test.example").await;
    mount_identity(&server, identity).await;
    mount_auth(&server).await;
    mount_submit(&server, 7, &client_did()).await;
    // Schedule reports epoch 7 already sealed.
    mount_schedule(&server, 8, Some(7)).await;

    let leaf = [0x99; 32];
    let witness = build_witness_tree(&SERVER_PRIVATE_KEY, &leaf).await;
    mount_by_leaf_ok(&server, witness).await;

    let client = TimestampClient::builder()
        .base_url(server.uri())
        .my_did(client_did())
        .signer(make_test_signer())
        .poll_interval(Duration::from_millis(20))
        .build()
        .await
        .expect("build");

    let receipt = client.submit(&leaf).await.expect("submit");
    let pair = client
        .await_witness(&receipt, AnchorMethod::Evm, Duration::from_secs(2))
        .await
        .expect("witness");
    assert_eq!(pair.anchor_method, AnchorMethod::Evm);
}

// ── server error mapping ──────────────────────────────────────────────────

// ── identifier mismatch (defence in depth) ────────────────────────────────

#[tokio::test]
async fn build_rejects_message_with_wrong_identifier() {
    // A hostile server might mint a CAIP-122 challenge whose embedded
    // identifier is not the one we asked for, hoping a programmatic
    // signer signs it anyway. aqua-auth's authenticate() catches this
    // before signing.
    let server = MockServer::start().await;
    let (_, identity) = build_identity_response(&SERVER_PRIVATE_KEY, "test.example").await;
    mount_identity(&server, identity).await;

    // Craft a challenge whose message body claims a DIFFERENT identifier
    // than the one the client requested.
    let attacker_identifier = "0xDeAdBeEfDeAdBeEfDeAdBeEfDeAdBeEfDeAdBeEf";
    let message = format!(
        "test.example wants you to sign in with your Ethereum account:\n\
         {attacker_identifier}\n\
         \n\
         Sign in to Aqua Node\n"
    );
    Mock::given(wmethod("GET"))
        .and(path("/auth/challenge"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "nonce": "0011223344556677889900112233445566778899001122334455667788990011",
            "message": message,
            "expires_at": 2_000_000_000u64,
        })))
        .mount(&server)
        .await;

    let err = TimestampClient::builder()
        .base_url(server.uri())
        .my_did(client_did())
        .signer(make_test_signer())
        .build()
        .await
        .expect_err("build should refuse to sign for a foreign identifier");

    match err {
        ClientError::Auth(ref s) => assert!(
            s.contains("identifier mismatch"),
            "expected identifier mismatch error, got: {s}"
        ),
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[tokio::test]
async fn submit_maps_server_5xx() {
    let server = MockServer::start().await;
    let (_, identity) = build_identity_response(&SERVER_PRIVATE_KEY, "test.example").await;
    mount_identity(&server, identity).await;
    mount_auth(&server).await;

    Mock::given(wmethod("POST"))
        .and(path("/v1/leaves"))
        .respond_with(ResponseTemplate::new(500).set_body_string("backend down"))
        .mount(&server)
        .await;

    let client = TimestampClient::builder()
        .base_url(server.uri())
        .my_did(client_did())
        .signer(make_test_signer())
        .build()
        .await
        .expect("build");

    let err = client.submit(&[0xab; 32]).await.expect_err("should be 5xx");
    match err {
        ClientError::Server { status, ref body } => {
            assert_eq!(status, 500);
            assert!(body.contains("backend down"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
