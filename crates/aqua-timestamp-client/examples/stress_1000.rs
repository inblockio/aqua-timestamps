//! Stress test: submit 1000 hashes aligned to the start of a fresh epoch,
//! then fetch every witness once the epoch seals.
//!
//! Run with:
//! ```bash
//! cargo run -p aqua-timestamp-client --features live-tests --example stress_1000
//! ```
//!
//! Environment:
//! - `TIMESTAMP_BASE_URL` (default `https://timestamp.inblock.io`)
//! - `STRESS_COUNT` (default `1000`)
//! - `STRESS_METHOD` (default `evm`; also accepts `qtsa`)
//! - `STRESS_PARALLEL` (default `32`; how many witness fetches run in parallel)
//! - `STRESS_EPOCH_ALIGN_BUFFER_SECS` (default `2`; wait this much past the
//!   reported epoch_closes_at before submitting, to be sure we land in the
//!   new epoch and not race the seal)
//!
//! The exit code is non-zero if any single submission or witness verification
//! fails. Witness signatures are verified by the client during fetch, so a
//! successful return guarantees the recovered signer matches the pinned
//! server DID for every leaf.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use aqua_timestamp_client::{AnchorMethod, ClientError, TimestampClient};
use rand::RngCore;
use tokio::sync::Semaphore;
use tokio::time::sleep;

fn env(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn env_parsed<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env("RUST_LOG", "info,aqua_timestamp_client=info"))
        .try_init();

    let base_url = env("TIMESTAMP_BASE_URL", "https://timestamp.inblock.io");
    let count: usize = env_parsed("STRESS_COUNT", 1000usize);
    let method = match env("STRESS_METHOD", "evm").to_lowercase().as_str() {
        "evm" => AnchorMethod::Evm,
        "qtsa" => AnchorMethod::Qtsa,
        other => return Err(format!("STRESS_METHOD must be evm or qtsa, got {other}").into()),
    };
    let parallel: usize = env_parsed("STRESS_PARALLEL", 32usize);
    let align_buffer: u64 = env_parsed("STRESS_EPOCH_ALIGN_BUFFER_SECS", 2u64);

    // ── ephemeral keypair ────────────────────────────────────────────────
    let mut key_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    let wallet = PrivateKeySigner::from_bytes(&key_bytes.into())?;
    let address = wallet.address();
    let did = format!("did:pkh:eip155:1:{}", address.to_checksum(None));
    let wallet_for_signer = wallet.clone();
    let signer = move |msg: &str| -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let sig = wallet_for_signer.sign_message_sync(msg.as_bytes())?;
        Ok(format!("0x{}", hex::encode(sig.as_bytes())))
    };

    println!("== stress_1000 ==");
    println!("base_url      = {base_url}");
    println!("count         = {count}");
    println!("method        = {}", method.as_str());
    println!("parallel      = {parallel}");
    println!("align_buffer  = {align_buffer}s");
    println!("ephemeral DID = {did}");

    let client = TimestampClient::builder()
        .base_url(&base_url)
        .my_did(did.clone())
        .signer(signer)
        .poll_interval(Duration::from_secs(5))
        .request_timeout(Duration::from_secs(20))
        .build()
        .await?;

    println!("server DID    = {}", client.server_identity().did);

    // ── align to the start of the next epoch ─────────────────────────────
    let sched = client.schedule().await?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let wait_secs = sched
        .current_epoch_closes_at
        .saturating_sub(now)
        + align_buffer;
    println!(
        "current epoch = {} (closes at {}, in {}s); waiting + {}s buffer = {}s",
        sched.current_epoch_id, sched.current_epoch_closes_at, sched.current_epoch_closes_at - now, align_buffer, wait_secs
    );
    if wait_secs > 0 {
        sleep(Duration::from_secs(wait_secs)).await;
    }

    let sched_after = client.schedule().await?;
    println!(
        "fresh epoch   = {} (closes at {}, duration {}s)",
        sched_after.current_epoch_id,
        sched_after.current_epoch_closes_at,
        sched_after.epoch_duration_secs
    );

    // ── generate and submit ──────────────────────────────────────────────
    println!("generating {count} random 32-byte leaves...");
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(count);
    for _ in 0..count {
        let mut b = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut b);
        leaves.push(b);
    }

    let submit_started = Instant::now();
    let receipts = client.submit_many(&leaves).await?;
    let submit_elapsed = submit_started.elapsed();
    println!(
        "submitted {} leaves in {:.2}s (server epoch_id={}, closes_at={})",
        receipts.len(),
        submit_elapsed.as_secs_f64(),
        receipts[0].epoch_id,
        receipts[0].epoch_closes_at
    );
    assert_eq!(receipts.len(), count);
    let target_epoch = receipts[0].epoch_id;
    assert!(
        receipts.iter().all(|r| r.epoch_id == target_epoch),
        "all receipts must share one epoch_id"
    );

    // ── wait for seal ────────────────────────────────────────────────────
    println!("waiting for epoch {target_epoch} to seal...");
    let seal_started = Instant::now();
    loop {
        let s = client.schedule().await?;
        if s.last_sealed_epoch_id.map(|id| id >= target_epoch).unwrap_or(false) {
            break;
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let remaining = receipts[0].epoch_closes_at.saturating_sub(now);
        println!(
            "  not sealed yet (last_sealed={:?}, ~{}s to close)",
            s.last_sealed_epoch_id, remaining
        );
        sleep(Duration::from_secs(10)).await;
    }
    let seal_elapsed = seal_started.elapsed();
    println!("epoch sealed in {:.1}s", seal_elapsed.as_secs_f64());

    // ── fetch all witnesses in parallel, bounded by Semaphore ────────────
    let fetch_started = Instant::now();
    let sem = Arc::new(Semaphore::new(parallel));
    let client = Arc::new(client);
    let mut handles = Vec::with_capacity(count);
    for (idx, receipt) in receipts.iter().enumerate() {
        let permit = sem.clone().acquire_owned().await?;
        let client = client.clone();
        let leaf = receipt.leaf;
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            let mut tries = 0;
            loop {
                match client.try_fetch_witness(&leaf, method).await {
                    Ok(Some(pair)) => return Ok::<(usize, _), ClientError>((idx, pair)),
                    Ok(None) => {
                        // Seal-vs-witness materialisation lag. Retry briefly.
                        tries += 1;
                        if tries > 6 {
                            return Err(ClientError::WitnessMissing {
                                leaf: hex::encode(leaf),
                                method,
                            });
                        }
                        sleep(Duration::from_millis(500 * tries as u64)).await;
                    }
                    Err(e) => return Err(e),
                }
            }
        }));
    }

    let mut ok = 0usize;
    let mut errors = Vec::new();
    for h in handles {
        match h.await {
            Ok(Ok((_idx, _pair))) => ok += 1,
            Ok(Err(e)) => errors.push(format!("{e}")),
            Err(e) => errors.push(format!("join error: {e}")),
        }
    }
    let fetch_elapsed = fetch_started.elapsed();

    println!();
    println!("== summary ==");
    println!("submitted     : {}", count);
    println!("witness ok    : {}", ok);
    println!("witness fail  : {}", errors.len());
    println!("submit time   : {:.2}s ({:.0} hashes/s)", submit_elapsed.as_secs_f64(), count as f64 / submit_elapsed.as_secs_f64().max(0.001));
    println!("seal wait     : {:.1}s", seal_elapsed.as_secs_f64());
    println!("fetch time    : {:.2}s ({:.0} witnesses/s, parallel={})", fetch_elapsed.as_secs_f64(), ok as f64 / fetch_elapsed.as_secs_f64().max(0.001), parallel);
    if !errors.is_empty() {
        println!();
        println!("first up to 5 failures:");
        for e in errors.iter().take(5) {
            println!("  - {e}");
        }
        std::process::exit(1);
    }
    println!("OK");
    Ok(())
}
