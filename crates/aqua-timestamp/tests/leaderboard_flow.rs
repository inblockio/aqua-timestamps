use aqua_timestamp::{
    build_app,
    config::{
        AnchorConfig, AnchorsConfig, AuthConfig, BondingCurveConfig, Config, EpochConfig,
        EvmAnchorConfig, IdentityConfig, LeaderboardConfig, QtsaAnchorConfig, ServerConfig,
        StorageConfig,
    },
    identity::{IdentityClaimOverrides, ServiceIdentity},
    SealDriver,
};
use aqua_timestamp_core::leaderboard::ContributorEntry;
use aqua_timestamp_core::storage::Store;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use serde_json::Value;
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";

async fn build_test_app(dir: &TempDir) -> (Router, Arc<aqua_timestamp::state::AppState>) {
    let cfg = Config {
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
            allowed_dids: vec![],
        },
        storage: StorageConfig {
            path: dir.path().to_path_buf(),
        },
        epoch: EpochConfig {
            duration_secs: 60,
            max_leaves_per_request: 10_000,
        },
        anchor_legacy: AnchorConfig::default(),
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
        bonding_curve: BondingCurveConfig::default(),
        leaderboard: LeaderboardConfig {
            enabled: false,
            max_pool_size: 500,
            ..LeaderboardConfig::default()
        },
    };

    let identity = ServiceIdentity::from_mnemonic(TEST_MNEMONIC, &cfg.identity)
        .await
        .unwrap();
    let overrides = IdentityClaimOverrides { valid_from: None };

    build_app(cfg, identity, overrides, SealDriver::Off)
        .await
        .unwrap()
}

fn populate_contributors(store: &Store) {
    let entries = vec![
        (
            [0x11; 20],
            ContributorEntry {
                did: "did:pkh:eip155:11155111:0x1111111111111111111111111111111111111111".into(),
                fuel_contributed_wei: 3_000_000_000_000_000_000, // 3 ETH
                fuel_contributed_sat: 0,
                hashes_submitted: 42,
                last_active: 1716000300,
            },
        ),
        (
            [0x22; 20],
            ContributorEntry {
                did: "did:pkh:eip155:11155111:0x2222222222222222222222222222222222222222".into(),
                fuel_contributed_wei: 1_000_000_000_000_000_000, // 1 ETH
                fuel_contributed_sat: 0,
                hashes_submitted: 10,
                last_active: 1716000200,
            },
        ),
        (
            [0x33; 20],
            ContributorEntry {
                did: "did:pkh:eip155:11155111:0x3333333333333333333333333333333333333333".into(),
                fuel_contributed_wei: 5_000_000_000_000_000_000, // 5 ETH
                fuel_contributed_sat: 0,
                hashes_submitted: 100,
                last_active: 1716000100,
            },
        ),
    ];
    store
        .upsert_contributors_and_watermark(&entries, "eth", 1000)
        .unwrap();
}

async fn get_json(router: &Router, uri: &str) -> (StatusCode, Value) {
    let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 64).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    (status, body)
}

#[tokio::test]
async fn leaderboard_returns_sorted_entries() {
    let dir = TempDir::new().unwrap();
    let (router, state) = build_test_app(&dir).await;
    populate_contributors(&state.store);

    let (status, body) = get_json(&router, "/v1/leaderboard?chain=eth").await;
    assert_eq!(status, StatusCode::OK);

    let wallets = body["wallets"].as_array().unwrap();
    assert_eq!(wallets.len(), 3);

    // Highest fuel first (5 ETH > 3 ETH > 1 ETH)
    assert_eq!(
        wallets[0]["fuel_contributed_wei"].as_str().unwrap(),
        "5000000000000000000"
    );
    assert_eq!(
        wallets[1]["fuel_contributed_wei"].as_str().unwrap(),
        "3000000000000000000"
    );
    assert_eq!(
        wallets[2]["fuel_contributed_wei"].as_str().unwrap(),
        "1000000000000000000"
    );

    // Verify each entry has the expected fields
    for w in wallets {
        assert!(w["did"].is_string());
        assert!(w["fuel_contributed_wei"].is_string());
        assert!(w["hashes_submitted"].is_number());
        assert!(w["last_active"].is_number());
    }

    // pool_count and max_pool present
    assert_eq!(body["pool_count"].as_u64().unwrap(), 3);
    assert_eq!(body["max_pool"].as_u64().unwrap(), 500);
}

#[tokio::test]
async fn leaderboard_default_chain_is_eth() {
    let dir = TempDir::new().unwrap();
    let (router, state) = build_test_app(&dir).await;
    populate_contributors(&state.store);

    let (status, body) = get_json(&router, "/v1/leaderboard").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["wallets"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn leaderboard_btc_returns_empty() {
    let dir = TempDir::new().unwrap();
    let (router, _) = build_test_app(&dir).await;

    let (status, body) = get_json(&router, "/v1/leaderboard?chain=btc").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["wallets"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn leaderboard_unknown_chain_returns_400() {
    let dir = TempDir::new().unwrap();
    let (router, _) = build_test_app(&dir).await;

    let (status, body) = get_json(&router, "/v1/leaderboard?chain=sol").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("unknown chain"));
}

#[tokio::test]
async fn pool_status_returns_count() {
    let dir = TempDir::new().unwrap();
    let (router, state) = build_test_app(&dir).await;
    populate_contributors(&state.store);

    let (status, body) = get_json(&router, "/v1/pool/status").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["current"].as_u64().unwrap(), 3);
    assert_eq!(body["max"].as_u64().unwrap(), 500);
}

#[tokio::test]
async fn pool_status_empty_store() {
    let dir = TempDir::new().unwrap();
    let (router, _) = build_test_app(&dir).await;

    let (status, body) = get_json(&router, "/v1/pool/status").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["current"].as_u64().unwrap(), 0);
    assert_eq!(body["max"].as_u64().unwrap(), 500);
}
