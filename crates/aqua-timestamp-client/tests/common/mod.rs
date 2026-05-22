//! Shared test helpers: construct realistic signed identity and witness
//! trees using the SDK's signing primitives, and wire up wiremock stubs
//! that mirror the live `aqua-timestamp` server contract.

use std::collections::BTreeMap;

use aqua_rs_sdk::core::signature::sign_aqua_tree_with_signer;
use aqua_rs_sdk::primitives::{HashType, Method, RevisionLink};
use aqua_rs_sdk::schema::templates::{EvmTimestampPayload, ServiceClaimServer};
use aqua_rs_sdk::schema::{tree::Tree, AnyRevision, AquaTreeWrapper, Object};
use aqua_rs_sdk::verification::Linkable;
use aqua_rs_sdk::Secp256k1Signer;
use serde_json::{json, Value};
use wiremock::matchers::{header_exists, method as wmethod, path, path_regex, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Deterministic 32-byte test key for the *server* identity.
pub const SERVER_PRIVATE_KEY: [u8; 32] = [
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];

/// A different deterministic key for "rotation" tests.
pub const SERVER_PRIVATE_KEY_ALT: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
];

/// A client-side key (different from server) used in the auth flow stubs.
pub const CLIENT_PRIVATE_KEY: [u8; 32] = [0x42; 32];

#[allow(dead_code)]
pub fn server_did(key: &[u8; 32]) -> String {
    let signer = Secp256k1Signer::new(key.to_vec());
    signer.derive_did_pkh().expect("derive server did from key").0
}

pub fn client_did() -> String {
    let signer = Secp256k1Signer::new(CLIENT_PRIVATE_KEY.to_vec());
    signer.derive_did_pkh().expect("derive client did").0
}

/// Build a signed `service_claim_server` Aqua-tree and wrap it as the
/// `/.well-known/aqua-identity` JSON response.
pub async fn build_identity_response(key: &[u8; 32], dns: &str) -> (String, Value) {
    let signer = Secp256k1Signer::new(key.to_vec());
    let (did, _addr) = signer
        .derive_did_pkh()
        .expect("derive did from server key");

    let payload = ServiceClaimServer {
        signer_did: did.clone(),
        service_kind: "server".to_string(),
        valid_from: 1_700_000_000,
        valid_until: None,
        dns: dns.to_string(),
        ip: "127.0.0.1".to_string(),
        deploy_version: Some("test".to_string()),
    };

    let obj = Object::genesis_with_template(Method::Scalar, HashType::Sha3_256, payload)
        .genericize()
        .expect("genericize");
    let obj_link = obj.calculate_link().expect("object link");
    let mut tree = Tree {
        revisions: BTreeMap::new(),
        file_index: BTreeMap::new(),
    };
    tree.revisions
        .insert(obj_link.clone(), AnyRevision::Typed(obj));

    let wrapper = AquaTreeWrapper::new(tree, None, None);
    let op = sign_aqua_tree_with_signer(&wrapper, &signer, Method::Scalar, None)
        .await
        .expect("sign identity tree");

    let identity_claim = serde_json::to_value(&op.aqua_tree).expect("serialize tree");

    let response = json!({
        "protocol": "aqua-timestamp",
        "version": "test",
        "server_did": did,
        "supported_claims": ["timestamp_anchor"],
        "auth_method": "siwe",
        "endpoints": {
            "auth": "/auth",
            "trees": "/trees",
            "submit": "/v1/leaves",
            "verify": "/api/explorer/trees/{tip}/verify",
            "docs": "/docs",
            "well_known_skill": "/.well-known/aqua-skill.md",
            "well_known_skill_auth": "/.well-known/aqua-skill-auth.md",
        },
        "identity_claim": identity_claim,
    });

    (did, response)
}

/// Build a signed two-revision witness pair (timestamp Object + Signature)
/// chained off the given leaf hash. Returns the Tree JSON shape the server
/// emits via `/trees/by-leaf/{leaf}?method=evm`.
pub async fn build_witness_tree(key: &[u8; 32], leaf: &[u8; 32]) -> Value {
    let signer = Secp256k1Signer::new(key.to_vec());

    let payload = EvmTimestampPayload {
        timestamp_type: "timestamp".to_string(),
        merkle_root: format!("0x{}", hex::encode(leaf)),
        timestamp: 1_700_000_000,
        network: "sepolia".to_string(),
        smart_contract_address: "0x0000000000000000000000000000000000000000".to_string(),
        transaction_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        sender_account_address: "0x0000000000000000000000000000000000000000".to_string(),
        merkle_proof: vec![],
        batch_tree_size: 1,
        batch_leaf_index: 0,
        shielding_nonce: String::new(),
    };

    let leaf_link = RevisionLink::from_bytes(*leaf);
    let obj =
        Object::new_with_template(leaf_link, Method::Scalar, HashType::Sha3_256, payload)
            .genericize()
            .expect("genericize witness object");
    let obj_link = obj.calculate_link().expect("witness object link");

    let mut tree = Tree {
        revisions: BTreeMap::new(),
        file_index: BTreeMap::new(),
    };
    tree.revisions
        .insert(obj_link.clone(), AnyRevision::Typed(obj));

    let wrapper = AquaTreeWrapper::new(tree, None, None);
    let op = sign_aqua_tree_with_signer(&wrapper, &signer, Method::Scalar, None)
        .await
        .expect("sign witness tree");

    serde_json::to_value(&op.aqua_tree).expect("serialize witness tree")
}

/// Mount the public `/.well-known/aqua-identity` endpoint returning `body`.
pub async fn mount_identity(server: &MockServer, body: Value) {
    Mock::given(wmethod("GET"))
        .and(path("/.well-known/aqua-identity"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

/// Mount the CAIP-122 challenge + session endpoints. The session token
/// returned is `BEARER_TOKEN` and is valid for one hour.
pub const BEARER_TOKEN: &str = "test-bearer-token-deadbeef";

pub async fn mount_auth(server: &MockServer) {
    // The message must contain the client's identifier on line 2; the
    // client now checks this before signing (defence in depth against a
    // hostile server trying to make us sign as a different account).
    let did = client_did();
    let identifier = aqua_auth::did::identifier_from_did(&did)
        .expect("derive identifier from client did");
    let message = format!(
        "test.example wants you to sign in with your Ethereum account:\n\
         {identifier}\n\
         \n\
         Sign in to Aqua Node\n\
         \n\
         URI: http://test.example\n\
         Version: 1\n\
         Nonce: 0x00\n\
         Issued At: 2026-01-01T00:00:00.000Z\n\
         Expiration Time: 2026-01-01T00:05:00.000Z\n\
         Chain ID: 1"
    );

    Mock::given(wmethod("GET"))
        .and(path("/auth/challenge"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "nonce": "0011223344556677889900112233445566778899001122334455667788990011",
            "message": message,
            "expires_at": 2_000_000_000u64,
        })))
        .mount(server)
        .await;

    let valid_until = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        + 3_600;

    Mock::given(wmethod("POST"))
        .and(path("/auth/session"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "did": client_did(),
            "token": BEARER_TOKEN,
            "valid_until": valid_until,
            "created_at": valid_until - 3_600,
        })))
        .mount(server)
        .await;
}

pub async fn mount_schedule(server: &MockServer, current: u64, last_sealed: Option<u64>) {
    let body = json!({
        "current_epoch_id": current,
        "current_epoch_opened_at": 1_700_000_000u64,
        "current_epoch_closes_at": 1_700_000_600u64,
        "epoch_duration_secs": 600u64,
        "last_sealed_epoch_id": last_sealed,
        "last_sealed_at": last_sealed.map(|_| 1_700_000_500u64),
        "anchor_methods": ["evm", "qtsa"],
    });
    Mock::given(wmethod("GET"))
        .and(path("/v1/schedule"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

pub async fn mount_submit(server: &MockServer, epoch_id: u64, submitter_did: &str) {
    Mock::given(wmethod("POST"))
        .and(path("/v1/leaves"))
        .and(header_exists("authorization"))
        .respond_with(ResponseTemplate::new(202).set_body_json(json!({
            "accepted": 1u64,
            "duplicates": 0u64,
            "epoch_id": epoch_id,
            "epoch_closes_at": 1_700_000_600u64,
            "submitter_did": submitter_did,
        })))
        .mount(server)
        .await;
}

pub async fn mount_by_leaf_404(server: &MockServer) {
    Mock::given(wmethod("GET"))
        .and(path_regex(r"^/trees/by-leaf/[0-9a-fA-F]{64}$"))
        .and(query_param("method", "evm"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(json!({"error": "no witness yet"})),
        )
        .mount(server)
        .await;
}

pub async fn mount_by_leaf_ok(server: &MockServer, tree_json: Value) {
    Mock::given(wmethod("GET"))
        .and(path_regex(r"^/trees/by-leaf/[0-9a-fA-F]{64}$"))
        .and(query_param("method", "evm"))
        .respond_with(ResponseTemplate::new(200).set_body_json(tree_json))
        .mount(server)
        .await;
}

/// Signing closure used by the test builder. Returns a fixed hex string;
/// the test server's `/auth/session` stub ignores the value anyway.
pub fn make_test_signer() -> impl Fn(&str) -> Result<String, Box<dyn std::error::Error + Send + Sync>>
       + Send
       + Sync
       + 'static {
    |_msg: &str| Ok("0xdeadbeef".to_string())
}
