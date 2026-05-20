//! In-process smoke test: spin up the binary against a free port, hit
//! /health and /, assert 200 + expected payload shape.

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
    let body: serde_json::Value = health.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert!(body["uptime_secs"].is_number());

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
