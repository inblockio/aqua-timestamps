//! Integration tests for the SSE `/events` endpoint, the ORL
//! `/.well-known/aqua-orl` endpoint, and landing page content.
//!
//! All tests drive the in-process router with a tempdir-backed fjall keyspace
//! and a `SealDriver::Channel` so the suite never sleeps.

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
use aqua_timestamp_core::sealer::SealTick;
use axum::{
    body::{to_bytes, Body},
    http::{Method, Request, StatusCode},
    Router,
};
use std::path::PathBuf;
use tempfile::TempDir;
use tokio::sync::mpsc;
use tower::ServiceExt;

const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";

fn cfg(storage: PathBuf) -> Config {
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
            allowed_dids: vec![],
        },
        storage: StorageConfig { path: storage },
        epoch: EpochConfig {
            duration_secs: 60,
            max_leaves_per_request: 10_000,
        },
        anchor_legacy: AnchorConfig::default(),
        bonding_curve: BondingCurveConfig::default(),
        leaderboard: LeaderboardConfig::default(),
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
    #[allow(dead_code)]
    seal_tx: mpsc::Sender<SealTick>,
    _tmp: TempDir,
}

async fn build_harness() -> Harness {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = cfg(tmp.path().to_path_buf());
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

// ── Tests ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn orl_endpoint_returns_valid_json() {
    let h = build_harness().await;

    let req = Request::builder()
        .method(Method::GET)
        .uri("/.well-known/aqua-orl")
        .body(Body::empty())
        .unwrap();
    let resp = h.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");

    assert_eq!(json["orl"], 2, "orl must be 2");
    assert_eq!(json["label"], "Development", "label must be Development");
    assert_eq!(json["color"], "#F97316", "color must be #F97316");
    assert!(
        json["next_level_blockers"].is_array(),
        "next_level_blockers must be an array"
    );
    assert!(
        json["checklist_url"].is_string(),
        "checklist_url must be a string"
    );
}

#[tokio::test]
async fn sse_endpoint_returns_event_stream_content_type() {
    let h = build_harness().await;

    let req = Request::builder()
        .method(Method::GET)
        .uri("/events")
        .body(Body::empty())
        .unwrap();
    let resp = h.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.contains("text/event-stream"),
        "content-type must contain text/event-stream, got: {content_type}"
    );
}

#[tokio::test]
async fn landing_page_contains_status_page_content() {
    let h = build_harness().await;

    let req = Request::builder()
        .method(Method::GET)
        .uri("/")
        .body(Body::empty())
        .unwrap();
    let resp = h.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = to_bytes(resp.into_body(), 1024 * 256).await.unwrap();
    let html = std::str::from_utf8(&bytes).expect("valid UTF-8");

    let checks: &[(&str, &str)] = &[
        ("Free and Open", "mission headline"),
        ("Ethereum", "channel card"),
        ("qTSA", "channel card"),
        ("Bitcoin", "channel card"),
        ("Help us build trust", "support header"),
        ("Burn My Crypto", "Goal 0"),
        ("Ethereum Mainnet", "Goal 1"),
        ("ORL-2", "ORL badge"),
        ("Sora", "Sora font"),
        ("JetBrains Mono", "JetBrains Mono font"),
    ];

    for (needle, label) in checks {
        assert!(
            html.contains(needle),
            "landing page must contain {label} ({needle:?})"
        );
    }
}
