//! Smoke test: spin up the real binary against a free port, hit /health,
//! /version, /v1/schedule and /, assert 200 + the expected payload shape.
//! `/health` follows the inblockio service endpoint contract (aqua-ops
//! `docs/service-endpoints/health-and-version.md`).

use std::{
    process::{Command, Stdio},
    time::Duration,
};

fn workspace_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

async fn wait_for(url: &str, attempts: u32) -> Option<reqwest::Response> {
    let client = reqwest::Client::new();
    for _ in 0..attempts {
        if let Ok(r) = client.get(url).send().await {
            return Some(r);
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    None
}

/// Well-known Hardhat test mnemonic. Address derived at `m/44'/60'/0'/0/0`
/// is `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`. Never used in
/// production; never funded.
const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";

#[tokio::test]
async fn smoke_health_and_landing() {
    let root = workspace_root();
    let port = free_port();
    let cfg_path = std::env::temp_dir().join(format!("aqua-timestamp-{port}.toml"));
    let state_path = std::env::temp_dir().join(format!("aqua-timestamp-{port}-state"));
    let _ = std::fs::remove_dir_all(&state_path);
    let state_str = state_path.to_string_lossy().replace('\\', "/");
    std::fs::write(
        &cfg_path,
        format!(
            "[server]\nlisten = \"127.0.0.1:{port}\"\n\
             [identity]\nchain_id = 1\ntrust_domain = \"timestamp\"\n\
             dns = \"timestamp.test\"\nip = \"127.0.0.1\"\n\
             [auth]\nchallenge_ttl_secs = 60\nsession_ttl_secs = 600\n\
             allowed_dids = []\n\
             [storage]\npath = \"{state_str}\"\n\
             [epoch]\nduration_secs = 600\nmax_leaves_per_request = 10000\n"
        ),
    )
    .unwrap();

    let bin = root.join("target/debug/aqua-timestamp");
    assert!(
        bin.exists(),
        "expected binary at {} - run `cargo build` first",
        bin.display()
    );

    let mut child = Command::new(&bin)
        .args(["--config", cfg_path.to_str().unwrap()])
        .env("AQUA_TIMESTAMP_ANCHOR_MNEMONIC", TEST_MNEMONIC)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn server");

    let health_url = format!("http://127.0.0.1:{port}/health");
    let landing_url = format!("http://127.0.0.1:{port}/");

    let health = wait_for(&health_url, 60)
        .await
        .expect("server never became reachable");
    assert_eq!(health.status(), 200);
    assert_eq!(
        health
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/health+json")
    );
    assert_eq!(
        health
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(health.text().await.unwrap(), r#"{"status":"pass"}"#);

    // HEAD answers like GET without a body; any other method is a 405 that
    // names GET and HEAD.
    let client = reqwest::Client::new();
    let head = client.head(&health_url).send().await.unwrap();
    assert_eq!(head.status(), 200);
    assert_eq!(
        head.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/health+json")
    );
    assert!(head.bytes().await.unwrap().is_empty());
    let post = client.post(&health_url).send().await.unwrap();
    assert_eq!(post.status(), 405);
    let allow = post
        .headers()
        .get("allow")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_uppercase();
    assert!(
        allow.contains("GET") && allow.contains("HEAD"),
        "Allow was {allow}"
    );

    // Uptime is not part of /health; the landing page reads it from /v1/schedule.
    let schedule: serde_json::Value = reqwest::get(format!("http://127.0.0.1:{port}/v1/schedule"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(schedule["uptime_secs"].is_u64());

    // /version names the running source revision (aqua-ops derives the deployed
    // pins from it). A git checkout or a GIT_SHA build arg yields a full commit.
    let version = reqwest::get(format!("http://127.0.0.1:{port}/version"))
        .await
        .unwrap();
    assert_eq!(version.status(), 200);
    assert_eq!(
        version
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let v: serde_json::Value = version.json().await.unwrap();
    assert_eq!(v["service"], "aqua-timestamp");
    assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
    assert!(v["protocol_version"]
        .as_str()
        .is_some_and(|p| p.starts_with("4.")));
    assert!(v["dirty"].is_boolean());
    let revision = v["revision"].as_str().expect("revision is a string");
    assert!(
        revision == "unknown"
            || (revision.len() == 40 && revision.bytes().all(|b| b.is_ascii_hexdigit())),
        "revision must be a full commit or unknown, got {revision}"
    );

    let landing = reqwest::get(&landing_url).await.unwrap();
    assert_eq!(landing.status(), 200);
    let ct = landing
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(ct.starts_with("text/html"), "content-type was {ct}");
    let html = landing.text().await.unwrap();
    assert!(html.contains("OpenWitness.org"));

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_file(&cfg_path);
    let _ = std::fs::remove_dir_all(&state_path);
}
