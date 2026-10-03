//! The inblockio service endpoint contract for `GET /health` and `GET /version`
//! (aqua-ops `docs/service-endpoints/health-and-version.md`), driven through the
//! in-process router: status, content type, `no-store`, exact `/health` body,
//! HEAD and the 405 for every other method, query string ignored, and the
//! uptime that moved out of `/health` into `/v1/schedule`.

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
    http::{header, HeaderMap, Method, Request, StatusCode},
    Router,
};
use tempfile::TempDir;
use tokio::sync::mpsc;
use tower::ServiceExt;

const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";

/// Everything the contract allows `/health` to say.
const PASS_BODY: &str = r#"{"status":"pass"}"#;

struct Harness {
    router: Router,
    // Held so the seal channel stays open and the keyspace dir outlives the test.
    _seal_tx: mpsc::Sender<SealTick>,
    _tmp: TempDir,
}

fn cfg(storage: std::path::PathBuf) -> Config {
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

async fn harness() -> Harness {
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
        _seal_tx: tx,
        _tmp: tmp,
    }
}

struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Answer {
    fn header(&self, name: header::HeaderName) -> &str {
        self.headers
            .get(&name)
            .unwrap_or_else(|| panic!("missing header {name}"))
            .to_str()
            .unwrap()
    }

    /// Header values of `name`, to prove a header is set exactly once.
    fn header_count(&self, name: header::HeaderName) -> usize {
        self.headers.get_all(&name).iter().count()
    }

    fn body_str(&self) -> &str {
        std::str::from_utf8(&self.body).expect("utf-8 body")
    }
}

async fn call(h: &Harness, method: Method, uri: &str) -> Answer {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    let resp = h.router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    Answer {
        status,
        headers,
        body,
    }
}

/// Parse a comma separated `Allow` header into upper-case method names.
fn allowed_methods(a: &Answer) -> Vec<String> {
    a.header(header::ALLOW)
        .split(',')
        .map(|m| m.trim().to_ascii_uppercase())
        .collect()
}

fn assert_health_headers(a: &Answer) {
    assert_eq!(a.status, StatusCode::OK);
    assert_eq!(a.header(header::CONTENT_TYPE), "application/health+json");
    assert_eq!(a.header_count(header::CONTENT_TYPE), 1);
    assert_eq!(a.header(header::CACHE_CONTROL), "no-store");
    assert_eq!(a.header_count(header::CACHE_CONTROL), 1);
    assert!(
        a.headers.get(header::SET_COOKIE).is_none(),
        "/health must not set a cookie"
    );
    assert!(
        a.headers.get(header::LOCATION).is_none(),
        "/health must not redirect"
    );
}

// ── /health ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn health_get_is_exactly_status_pass() {
    let h = harness().await;
    let a = call(&h, Method::GET, "/health").await;
    assert_health_headers(&a);
    // Exactly one field: no uptime, no version, nothing else.
    assert_eq!(a.body_str(), PASS_BODY);
    let json: serde_json::Value = serde_json::from_slice(&a.body).unwrap();
    assert_eq!(json.as_object().unwrap().len(), 1);
}

#[tokio::test]
async fn health_head_has_the_same_status_and_headers_and_no_body() {
    let h = harness().await;
    let get = call(&h, Method::GET, "/health").await;
    let head = call(&h, Method::HEAD, "/health").await;
    assert_health_headers(&head);
    assert!(head.body.is_empty(), "HEAD must carry no body");
    assert_eq!(head.status, get.status);
    assert_eq!(
        head.header(header::CONTENT_TYPE),
        get.header(header::CONTENT_TYPE)
    );
    assert_eq!(
        head.header(header::CACHE_CONTROL),
        get.header(header::CACHE_CONTROL)
    );
}

#[tokio::test]
async fn health_other_methods_answer_405_with_allow_get_head() {
    let h = harness().await;
    for method in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
        let a = call(&h, method.clone(), "/health").await;
        assert_eq!(a.status, StatusCode::METHOD_NOT_ALLOWED, "{method} /health");
        let allow = allowed_methods(&a);
        assert!(allow.contains(&"GET".to_string()), "Allow was {allow:?}");
        assert!(allow.contains(&"HEAD".to_string()), "Allow was {allow:?}");
        assert!(
            !allow.contains(&"POST".to_string()),
            "Allow was {allow:?}: only GET and HEAD are allowed"
        );
    }
}

#[tokio::test]
async fn health_ignores_the_query_string() {
    let h = harness().await;
    for uri in ["/health?error=x", "/health?", "/health?status=fail&a=b"] {
        let a = call(&h, Method::GET, uri).await;
        assert_health_headers(&a);
        assert_eq!(a.body_str(), PASS_BODY, "GET {uri}");
        let head = call(&h, Method::HEAD, uri).await;
        assert_health_headers(&head);
        assert!(head.body.is_empty(), "HEAD {uri}");
    }
}

#[tokio::test]
async fn health_does_not_leak_uptime_or_version() {
    let h = harness().await;
    let a = call(&h, Method::GET, "/health").await;
    for forbidden in ["uptime", "version", "ok", "epoch"] {
        assert!(
            !a.body_str().contains(forbidden),
            "/health body {} contains {forbidden}",
            a.body_str()
        );
    }
}

// ── /version ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn version_head_has_the_same_status_and_headers_and_no_body() {
    let h = harness().await;
    let get = call(&h, Method::GET, "/version").await;
    assert_eq!(get.status, StatusCode::OK);
    let head = call(&h, Method::HEAD, "/version").await;
    assert_eq!(head.status, StatusCode::OK);
    assert!(head.body.is_empty(), "HEAD must carry no body");
    assert_eq!(head.header(header::CONTENT_TYPE), "application/json");
    assert_eq!(head.header(header::CACHE_CONTROL), "no-store");
    assert_eq!(
        head.header(header::CONTENT_TYPE),
        get.header(header::CONTENT_TYPE)
    );
    assert!(head.headers.get(header::SET_COOKIE).is_none());
}

#[tokio::test]
async fn version_other_methods_answer_405_with_allow_get_head() {
    let h = harness().await;
    for method in [Method::POST, Method::PUT, Method::DELETE] {
        let a = call(&h, method.clone(), "/version").await;
        assert_eq!(
            a.status,
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} /version"
        );
        let allow = allowed_methods(&a);
        assert!(allow.contains(&"GET".to_string()), "Allow was {allow:?}");
        assert!(allow.contains(&"HEAD".to_string()), "Allow was {allow:?}");
    }
}

#[tokio::test]
async fn version_ignores_the_query_string() {
    let h = harness().await;
    let plain = call(&h, Method::GET, "/version").await;
    let queried = call(&h, Method::GET, "/version?error=x").await;
    assert_eq!(queried.status, StatusCode::OK);
    assert_eq!(queried.body, plain.body);
}

// ── uptime moved to /v1/schedule ──────────────────────────────────────────

#[tokio::test]
async fn schedule_carries_the_uptime_the_landing_page_needs() {
    let h = harness().await;
    let a = call(&h, Method::GET, "/v1/schedule").await;
    assert_eq!(a.status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&a.body).unwrap();
    let up = json["uptime_secs"]
        .as_u64()
        .expect("/v1/schedule must carry an integer uptime_secs");
    // A freshly built app has been up for moments, not minutes.
    assert!(up < 60, "uptime_secs was {up} on a fresh app");
}

#[tokio::test]
async fn landing_page_no_longer_polls_health() {
    let h = harness().await;
    let a = call(&h, Method::GET, "/").await;
    assert_eq!(a.status, StatusCode::OK);
    let html = a.body_str();
    for call_form in ["fetch('/health", "fetch(\"/health", "fetch(`/health"] {
        assert!(
            !html.contains(call_form),
            "the landing page must not fetch /health ({call_form})"
        );
    }
    // The stat still has a source from page load: /v1/schedule.
    assert!(html.contains("/v1/schedule"));
    assert!(html.contains("stat-uptime"));
}
