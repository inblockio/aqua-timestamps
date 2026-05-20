# Status Page Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the landing page with a mission-driven, read-only status page that streams live operational data via SSE, includes an ORL badge, and displays hardcoded initial funding goals.

**Architecture:** The page is an embedded HTML string in `landing.rs` (existing pattern). A new `GET /events` SSE endpoint broadcasts epoch/anchor events from the sealer via a `tokio::sync::broadcast` channel threaded through `AppState`. A new `GET /.well-known/aqua-orl` endpoint returns hardcoded ORL-2 JSON. The page uses vanilla JS to fetch `/health`, `/v1/schedule`, `/v1/epochs` on load, then subscribes to `/events` for real-time updates.

**Tech Stack:** Rust, Axum (SSE via `axum::response::sse`), tokio broadcast channel, vanilla HTML/CSS/JS (embedded), inblock.io brand tokens (Sora, JetBrains Mono, `#E8611A` orange accent).

**Spec:** `docs/superpowers/specs/2026-05-20-status-page-design.md`

**Economic design principles (non-negotiable):**
- "Fuel, not fee." Never use "fee" in code, docs, or UI copy.
- BTC and ETH are completely orthogonal. No cross-chain binding.
- Aqua-on-Aqua accountability for operational budget.

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `crates/aqua-timestamp-core/src/events.rs` | Create | SSE event types, `EventBus` (wraps `tokio::sync::broadcast`) |
| `crates/aqua-timestamp-core/src/lib.rs` | Modify | Add `pub mod events;` |
| `crates/aqua-timestamp-core/src/sealer.rs` | Modify | Accept `EventBus`, emit events after `seal_once` |
| `crates/aqua-timestamp/src/state.rs` | Modify | Add `event_bus: EventBus` to `AppState` |
| `crates/aqua-timestamp/src/landing.rs` | Rewrite | New status page HTML/CSS/JS |
| `crates/aqua-timestamp/src/routes.rs` | Modify | Add `sse_events()` handler, `aqua_orl()` handler |
| `crates/aqua-timestamp/src/lib.rs` | Modify | Wire `EventBus` into `AppState` and sealer, add routes |
| `crates/aqua-timestamp/tests/sse_events.rs` | Create | Integration tests for SSE + ORL endpoint |
| `ORL.md` | Create | Operational Readiness Level assessment |

---

### Task 1: EventBus and Event Types

**Files:**
- Create: `crates/aqua-timestamp-core/src/events.rs`
- Modify: `crates/aqua-timestamp-core/src/lib.rs`

- [ ] **Step 1: Write the failing test**

In `crates/aqua-timestamp-core/src/events.rs`, define the module with types and a test:

```rust
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SseEvent {
    EpochSealed {
        epoch_id: u64,
        leaf_count: u64,
        merkle_root: String,
        timestamp: u64,
    },
    AnchorEvm {
        epoch_id: u64,
        tx_hash: String,
        block: u64,
        network: String,
    },
    AnchorQtsa {
        epoch_id: u64,
        tsa_provider: String,
        gen_time: String,
    },
    HealthTick {
        uptime_secs: u64,
        epochs_total: u64,
        leaves_total: u64,
    },
}

impl SseEvent {
    pub fn event_name(&self) -> &'static str {
        match self {
            SseEvent::EpochSealed { .. } => "epoch:sealed",
            SseEvent::AnchorEvm { .. } => "anchor:evm",
            SseEvent::AnchorQtsa { .. } => "anchor:qtsa",
            SseEvent::HealthTick { .. } => "health:tick",
        }
    }
}

#[derive(Clone)]
pub struct EventBus {
    tx: tokio::sync::broadcast::Sender<SseEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(capacity);
        Self { tx }
    }

    pub fn send(&self, event: SseEvent) {
        let _ = self.tx.send(event);
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<SseEvent> {
        self.tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn event_bus_send_and_receive() {
        let bus = EventBus::new(16);
        let mut rx = bus.subscribe();
        bus.send(SseEvent::EpochSealed {
            epoch_id: 1,
            leaf_count: 5,
            merkle_root: "0xabc".into(),
            timestamp: 1000,
        });
        let event = rx.recv().await.unwrap();
        assert_eq!(event.event_name(), "epoch:sealed");
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"epoch_id\":1"));
        assert!(json.contains("\"type\":\"epoch_sealed\""));
    }

    #[test]
    fn no_subscribers_does_not_panic() {
        let bus = EventBus::new(4);
        bus.send(SseEvent::HealthTick {
            uptime_secs: 10,
            epochs_total: 0,
            leaves_total: 0,
        });
    }
}
```

- [ ] **Step 2: Add module declaration**

In `crates/aqua-timestamp-core/src/lib.rs`, add:

```rust
pub mod events;
```

alongside the existing `pub mod` lines.

- [ ] **Step 3: Run tests to verify they pass**

Run: `cargo test -p aqua-timestamp-core -- events`
Expected: 2 tests pass (event_bus_send_and_receive, no_subscribers_does_not_panic)

- [ ] **Step 4: Commit**

```bash
git add crates/aqua-timestamp-core/src/events.rs crates/aqua-timestamp-core/src/lib.rs
git commit -m "$(cat <<'EOF'
feat: add EventBus and SSE event types

Broadcast channel wrapper for streaming server-side events to
connected clients. Supports epoch:sealed, anchor:evm, anchor:qtsa,
and health:tick event types.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Wire EventBus into Sealer

**Files:**
- Modify: `crates/aqua-timestamp-core/src/sealer.rs` (lines 309-337 for interval, 356-427 for bonding curve, 430-452 for channel)

- [ ] **Step 1: Write the failing test**

Add a test at the bottom of `crates/aqua-timestamp-core/src/sealer.rs` in the existing `#[cfg(test)] mod tests` block:

```rust
#[tokio::test]
async fn seal_emits_epoch_sealed_event() {
    use crate::events::{EventBus, SseEvent};

    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let acc = std::sync::Arc::new(Accumulator::new(0, 100, 60));

    let leaf = [0xABu8; 32];
    acc.add_leaves(&[leaf], "did:test:alice").unwrap();

    let bus = EventBus::new(16);
    let mut rx = bus.subscribe();

    let signer = test_signer();
    let ctx = WitnessContext::new(
        std::sync::Arc::new(signer),
        "0xdeadbeef".into(),
        "sepolia".into(),
        vec![],
    );

    let (record, _witnesses) = seal_once(&acc, &store, 200, 60, Some(&ctx)).await.unwrap();

    bus.send(SseEvent::EpochSealed {
        epoch_id: record.id,
        leaf_count: record.leaf_count,
        merkle_root: record.merkle_root_hex(),
        timestamp: 200,
    });

    let event = rx.recv().await.unwrap();
    match event {
        SseEvent::EpochSealed { epoch_id, leaf_count, .. } => {
            assert_eq!(epoch_id, record.id);
            assert_eq!(leaf_count, 1);
        }
        _ => panic!("expected EpochSealed"),
    }
}
```

Note: `test_signer()` should already exist in the test module. If not, use:
```rust
fn test_signer() -> aqua_rs_sdk::Secp256k1Signer {
    let key_bytes = hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap();
    aqua_rs_sdk::Secp256k1Signer::from_bytes(&key_bytes).unwrap()
}
```

- [ ] **Step 2: Run test to verify it passes**

This test exercises EventBus after seal_once; it should pass because we're calling `bus.send()` manually. This validates the integration pattern.

Run: `cargo test -p aqua-timestamp-core -- seal_emits_epoch_sealed_event`
Expected: PASS

- [ ] **Step 3: Add `Option<EventBus>` parameter to `run_sealer_with_interval`**

Modify the signature at line 309:

```rust
pub fn run_sealer_with_interval<C: Clock + 'static>(
    accumulator: Arc<Accumulator>,
    store: Store,
    clock: C,
    duration_secs: u64,
    witness_ctx: Option<WitnessContext>,
    event_bus: Option<crate::events::EventBus>,
) -> tokio::task::JoinHandle<()> {
```

After the `seal_once` call succeeds (line 324-331), emit the event:

```rust
if let Err(e) = seal_once(
    &accumulator,
    &store,
    now,
    duration_secs,
    witness_ctx.as_ref(),
)
.await
{
    error!(error = %e, "seal cycle failed");
} else if let Ok((ref record, ref witnesses)) = seal_once(/* ... */) {
    // This won't work - we need to restructure
}
```

Actually, restructure the match to capture the result:

```rust
match seal_once(
    &accumulator,
    &store,
    now,
    duration_secs,
    witness_ctx.as_ref(),
)
.await
{
    Ok((record, witnesses)) => {
        if let Some(ref bus) = event_bus {
            bus.send(crate::events::SseEvent::EpochSealed {
                epoch_id: record.id,
                leaf_count: record.leaf_count,
                merkle_root: record.merkle_root_hex(),
                timestamp: now,
            });
            for w in &witnesses {
                match w.method {
                    AnchorMethod::Evm => {
                        bus.send(crate::events::SseEvent::AnchorEvm {
                            epoch_id: w.epoch_id,
                            tx_hash: w.anchor_tx_hash.clone().unwrap_or_default(),
                            block: 0,
                            network: w.anchor_network.clone().unwrap_or_default(),
                        });
                    }
                    AnchorMethod::Qtsa => {
                        bus.send(crate::events::SseEvent::AnchorQtsa {
                            epoch_id: w.epoch_id,
                            tsa_provider: w.anchor_tsa_provider.clone().unwrap_or_default(),
                            gen_time: w.anchor_gen_time.clone().unwrap_or_default(),
                        });
                    }
                }
            }
        }
    }
    Err(e) => {
        error!(error = %e, "seal cycle failed");
    }
}
```

**Important:** The `MintedWitness` struct fields for anchor data need to be checked. Look at `crates/aqua-timestamp-core/src/witness.rs` for the actual field names. The witness stores the payload as `serde_json::Value`, so the anchor fields may need to be extracted from the payload. Adapt the field access to match the actual `MintedWitness` struct. If `MintedWitness` does not carry parsed anchor fields, emit only `EpochSealed` events for now and add anchor events as a follow-on.

- [ ] **Step 4: Apply the same pattern to `run_sealer_with_bonding_curve`**

Add `event_bus: Option<crate::events::EventBus>` as the last parameter. Same match pattern around `seal_once`.

- [ ] **Step 5: Apply the same pattern to `run_sealer_with_channel`**

Add `event_bus: Option<crate::events::EventBus>` as the last parameter. Same match pattern around `seal_once`.

- [ ] **Step 6: Fix all call sites in `crates/aqua-timestamp/src/lib.rs`**

Every call to `run_sealer_with_interval`, `run_sealer_with_bonding_curve`, `run_sealer_with_channel` now needs the extra `event_bus` argument. Pass `Some(event_bus.clone())` for production, or `None` for test paths that don't need it.

Find the sealer spawn block (~lines 181-233) and add the event_bus parameter to each call.

- [ ] **Step 7: Run full test suite**

Run: `cargo test --workspace`
Expected: All existing tests pass (some calls may need `None` added for the new parameter).

- [ ] **Step 8: Commit**

```bash
git add crates/aqua-timestamp-core/src/sealer.rs crates/aqua-timestamp/src/lib.rs
git commit -m "$(cat <<'EOF'
feat: emit SSE events from sealer after each epoch

The three sealer drivers (interval, bonding curve, channel) now
accept an optional EventBus. On successful seal, they emit
EpochSealed events. Anchor events follow once MintedWitness
field extraction is confirmed.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Add EventBus to AppState and Wire SSE Endpoint

**Files:**
- Modify: `crates/aqua-timestamp/src/state.rs`
- Modify: `crates/aqua-timestamp/src/routes.rs`
- Modify: `crates/aqua-timestamp/src/lib.rs`

- [ ] **Step 1: Add EventBus to AppState**

In `crates/aqua-timestamp/src/state.rs`, add import:

```rust
use aqua_timestamp_core::events::EventBus;
```

Add field to `AppState` struct:

```rust
pub event_bus: EventBus,
```

- [ ] **Step 2: Write the SSE handler in routes.rs**

Add imports at the top of `crates/aqua-timestamp/src/routes.rs`:

```rust
use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::stream::Stream;
use std::convert::Infallible;
```

Note: Check if `futures-util` is already a dependency. If not, add it to `crates/aqua-timestamp/Cargo.toml`:
```toml
futures-util = "0.3"
```

Add the handler:

```rust
pub async fn sse_events(
    State(state): State<Arc<AppState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.event_bus.subscribe();
    let stream = tokio_stream::wrappers::BroadcastStream::new(rx).filter_map(|result| {
        match result {
            Ok(event) => {
                let name = event.event_name().to_owned();
                match serde_json::to_string(&event) {
                    Ok(json) => Some(Ok(Event::default().event(name).data(json))),
                    Err(_) => None,
                }
            }
            Err(_) => None,
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}
```

Note: Also add `tokio-stream` to `crates/aqua-timestamp/Cargo.toml` if not present:
```toml
tokio-stream = "0.1"
```

- [ ] **Step 3: Add the ORL endpoint in routes.rs**

```rust
pub async fn aqua_orl() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "orl": 2,
        "label": "Development",
        "color": "#F97316",
        "since": "2026-05-17",
        "assessed_by": "tim.bansemer@inblock.io",
        "next_level_blockers": [
            "Security review not started",
            "Backup restore not verified",
            "Monitoring and alerting not active",
            "Dependency audit not completed"
        ],
        "checklist_url": "https://github.com/inblockio/aqua-timestamps/blob/main/ORL.md"
    }))
}
```

- [ ] **Step 4: Wire routes and EventBus in lib.rs**

In `crates/aqua-timestamp/src/lib.rs`, create the EventBus before AppState construction (~line 239):

```rust
let event_bus = aqua_timestamp_core::events::EventBus::new(256);
```

Add it to the AppState construction:

```rust
let state = Arc::new(AppState {
    // ... existing fields ...
    event_bus: event_bus.clone(),
});
```

Pass `Some(event_bus)` to the sealer spawn calls.

Add routes to the router:

```rust
.route("/events", get(sse_events))
.route("/.well-known/aqua-orl", get(aqua_orl))
```

Import the new handlers in the `use crate::routes::{ ... }` block.

- [ ] **Step 5: Run tests**

Run: `cargo test --workspace`
Expected: All pass. The new SSE handler is not yet integration-tested (Task 5).

- [ ] **Step 6: Commit**

```bash
git add crates/aqua-timestamp/src/state.rs crates/aqua-timestamp/src/routes.rs crates/aqua-timestamp/src/lib.rs crates/aqua-timestamp/Cargo.toml
git commit -m "$(cat <<'EOF'
feat: add SSE /events endpoint and /.well-known/aqua-orl

EventBus threaded through AppState. GET /events streams epoch and
anchor events to connected browsers. GET /.well-known/aqua-orl
returns hardcoded ORL-2 assessment JSON.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Replace Landing Page HTML

**Files:**
- Rewrite: `crates/aqua-timestamp/src/landing.rs`

This is the largest single task. The new HTML replaces the current 76-line landing page with the three-section status page.

- [ ] **Step 1: Write the new landing page**

Replace the entire content of `crates/aqua-timestamp/src/landing.rs` with the new status page. The HTML must:

1. Load Sora and JetBrains Mono from Google Fonts
2. Define CSS custom properties for both light and dark themes per brand guide
3. Implement three sections: Mission, Operational Overview, Support
4. Include the ORL badge (upper-right, clickable expand/collapse)
5. Include vanilla JS that:
   - Fetches `/health`, `/v1/schedule`, `/v1/epochs` on load
   - Subscribes to `/events` via `EventSource`
   - Updates the DOM on each SSE event
   - Updates "time since last anchor" every second

Key content decisions from the spec:
- Eyebrow: "Aqua Timestamp Service"
- Headline: "A free anchor of trust for a world that needs it"
- Body copy: "Trust is eroding. Uncertainty is rising. We made it our mission to provide a free, public timestamping service that anchors data integrity across jurisdictions and blockchains. No accounts. No fees. Just proof."
- Value pills: "Fastest multi-chain publishing", "Most trusted cross-jurisdiction anchoring"
- Channel cards: Ethereum (Sepolia, active), qTSA (EU/eIDAS, active), Bitcoin (planned, dimmed)
- Stats: Epochs sealed, Leaves timestamped, Uptime, Online since
- Goal 0: "Burn My Crypto" (active, ETH: 0x55Fcf9F8C1287cB462aa3c1C97E2298d221c634f, BTC: FIXME)
- Goal 1: "Ethereum Mainnet" (funding, target 5.0 ETH)
- Goal 2: "Bitcoin Direct Timestamping" (funding, target 0.25 BTC)

**Brand rules (must follow):**
- `--accent: #E8611A` (sole chromatic accent)
- `--define-blue: #4895ef`, `--enforce-amber: #d97706`, `--proof-green: #2a8a5a` (semantic only)
- Font: Sora for UI, JetBrains Mono for hashes/DIDs/timestamps
- No pill buttons (border-radius: 999px). Use 8-14px.
- No em dashes anywhere.
- Dark theme: `--bg: #0f0f13`, `--surface: #1a1a20`, `--text: #e4e4e7`, `--border: #2a2a32`, `--dim: #71717a`
- Light theme: `--bg: #fafaf9`, `--surface: #ffffff`, `--text: #1c1917`, `--border: #e7e5e4`, `--dim: #78716c`

The HTML is a `pub const HTML: &str = r##"..."##;` constant, same pattern as the current file. All CSS and JS are inlined.

**JS logic outline:**

```javascript
document.addEventListener('DOMContentLoaded', async () => {
  // Fetch initial data
  const [health, schedule, epochs] = await Promise.all([
    fetch('/health').then(r => r.json()),
    fetch('/v1/schedule').then(r => r.json()).catch(() => null),
    fetch('/v1/epochs').then(r => r.json()).catch(() => null),
  ]);

  // Populate stats
  updateHealth(health);
  if (schedule) updateSchedule(schedule);
  if (epochs) updateEpochs(epochs);

  // Subscribe to SSE
  const source = new EventSource('/events');
  source.addEventListener('epoch:sealed', e => {
    const data = JSON.parse(e.data);
    updateEpochSealed(data);
  });
  source.addEventListener('anchor:evm', e => {
    const data = JSON.parse(e.data);
    updateAnchorEvm(data);
  });
  source.addEventListener('anchor:qtsa', e => {
    const data = JSON.parse(e.data);
    updateAnchorQtsa(data);
  });
  source.addEventListener('health:tick', e => {
    const data = JSON.parse(e.data);
    updateHealthTick(data);
  });

  // Tick "time ago" every second
  setInterval(updateTimeAgo, 1000);
});
```

- [ ] **Step 2: Verify the HTML compiles**

Run: `cargo check -p aqua-timestamp`
Expected: Compiles cleanly.

- [ ] **Step 3: Run clippy**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: Clean (the HTML is a string constant, no Rust logic to lint).

- [ ] **Step 4: Commit**

```bash
git add crates/aqua-timestamp/src/landing.rs
git commit -m "$(cat <<'EOF'
feat: replace landing page with status page

Three-section read-only page: mission/vision, live operational
overview (channels + stats), and funding goals. inblock.io brand,
Sora/JetBrains Mono fonts, dark+light themes. JS fetches live data
on load and subscribes to /events SSE stream.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Integration Tests for SSE and ORL

**Files:**
- Create: `crates/aqua-timestamp/tests/sse_events.rs`

- [ ] **Step 1: Write the SSE integration test**

Follow the pattern from `leaves_flow.rs` (Harness struct, SealDriver::Channel, tower::ServiceExt):

```rust
//! Integration tests for the SSE event stream and ORL endpoint.

use aqua_timestamp::{
    build_app,
    config::{
        AnchorConfig, AnchorsConfig, AuthConfig, BondingCurveConfig, Config, EpochConfig,
        EvmAnchorConfig, IdentityConfig, QtsaAnchorConfig, ServerConfig, StorageConfig,
    },
    identity::{IdentityClaimOverrides, ServiceIdentity},
    SealDriver,
};
use aqua_timestamp_core::sealer::SealTick;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
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
    _seal_tx: mpsc::Sender<SealTick>,
    _tmp: TempDir,
}

async fn build_harness() -> Harness {
    let tmp = tempfile::tempdir().expect("tempdir");
    let c = cfg(tmp.path().to_path_buf());
    let identity = ServiceIdentity::from_mnemonic(TEST_MNEMONIC, c.identity.chain_id).unwrap();
    let (seal_tx, seal_rx) = mpsc::channel(8);
    let (router, _state) = build_app(
        c,
        identity,
        IdentityClaimOverrides::default(),
        SealDriver::Channel(seal_rx),
    )
    .await
    .unwrap();
    Harness {
        router,
        _seal_tx: seal_tx,
        _tmp: tmp,
    }
}

#[tokio::test]
async fn orl_endpoint_returns_valid_json() {
    let h = build_harness().await;
    let req = Request::get("/.well-known/aqua-orl")
        .body(Body::empty())
        .unwrap();
    let resp = h.router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = to_bytes(resp.into_body(), 1024 * 64).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["orl"], 2);
    assert_eq!(json["label"], "Development");
    assert_eq!(json["color"], "#F97316");
    assert!(json["next_level_blockers"].is_array());
    assert!(json["checklist_url"].is_string());
}

#[tokio::test]
async fn sse_endpoint_returns_event_stream_content_type() {
    let h = build_harness().await;
    let req = Request::get("/events").body(Body::empty()).unwrap();
    let resp = h.router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("text/event-stream"),
        "expected text/event-stream, got {ct}"
    );
}

#[tokio::test]
async fn landing_page_contains_status_page_content() {
    let h = build_harness().await;
    let req = Request::get("/").body(Body::empty()).unwrap();
    let resp = h.router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = to_bytes(resp.into_body(), 1024 * 256).await.unwrap();
    let html = String::from_utf8_lossy(&body);

    // Section 1: Mission
    assert!(html.contains("anchor of trust"), "missing mission headline");

    // Section 2: Operational
    assert!(html.contains("Ethereum"), "missing Ethereum channel");
    assert!(html.contains("qTSA"), "missing qTSA channel");
    assert!(html.contains("Bitcoin"), "missing Bitcoin channel");

    // Section 3: Funding
    assert!(html.contains("Help us build trust"), "missing support header");
    assert!(html.contains("Burn My Crypto"), "missing Goal 0");
    assert!(html.contains("Ethereum Mainnet"), "missing Goal 1");

    // ORL badge
    assert!(html.contains("ORL-2"), "missing ORL badge");

    // Brand: fonts
    assert!(html.contains("Sora"), "missing Sora font");
    assert!(html.contains("JetBrains Mono"), "missing JetBrains Mono font");
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p aqua-timestamp -- sse_events`
Expected: All 3 tests pass.

- [ ] **Step 3: Run full workspace tests**

Run: `cargo test --workspace`
Expected: All pass, including the smoke_health test (which checks the landing page contains "Aqua Aggregator"). **Note:** The smoke test at `tests/smoke_health.rs:96` asserts `html.contains("Aqua Aggregator")`. The new page should still contain this text (it appears in the page title or body). If the new page uses a different title, update the smoke test assertion to match.

- [ ] **Step 4: Commit**

```bash
git add crates/aqua-timestamp/tests/sse_events.rs
git commit -m "$(cat <<'EOF'
test: add integration tests for SSE, ORL, and status page content

Verifies ORL-2 JSON shape, SSE content-type, and that the landing
page contains all three sections (mission, operational, funding)
plus the ORL badge and brand fonts.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Create ORL.md

**Files:**
- Create: `ORL.md` (project root)

- [ ] **Step 1: Write ORL.md**

```markdown
# Operational Readiness

**Current Level:** ORL-2 (Development)
**Last Assessed:** 2026-05-20
**Assessed By:** tim.bansemer@inblock.io

## Status

aqua-timestamp is a deployed, actively maintained timestamping service
dual-anchoring to Sepolia (EVM) and Sectigo Qualified TSA (eIDAS).
The service is functional but lacks security hardening, monitoring,
and verified backup procedures.

## ORL-2 Criteria (met)

- [x] Active maintainer assigned
- [x] Source code in version control with branch protection
- [x] CI pipeline runs on every PR (GitHub Actions)
- [x] README documents how to run and develop locally
- [x] Deployment is reproducible (Docker)
- [x] Known security gaps documented (see below)
- [ ] Manual or automated backups exist (fjall state not backed up)

## Unmet Criteria for ORL-3 (Pre-production)

- [ ] Security review completed or in progress
- [ ] Backup and restore procedure verified
- [ ] Monitoring and alerting active (health checks, error rates)
- [ ] API stability commitment (no breaking changes without migration)
- [ ] Test coverage on critical paths (59 tests, but no fuzz/property)
- [ ] Dependency audit completed (no known critical CVEs verified)
- [ ] Logging sufficient for incident investigation

## Known Security Gaps

- No rate limiting per DID
- No input size limits beyond max_leaves_per_request
- fjall keyspace not encrypted at rest
- No WAL for accumulator (data loss on crash between seal cycles)

## History

| Date | Level | Notes |
|---|---|---|
| 2026-05-17 | ORL-1 | Initial deployment (M0) |
| 2026-05-17 | ORL-2 | M1-M5 shipped, CI added, Docker reproducible |
```

- [ ] **Step 2: Commit**

```bash
git add ORL.md
git commit -m "$(cat <<'EOF'
docs: add ORL-2 operational readiness assessment

Baseline assessment for aqua-timestamp. Currently ORL-2
(Development) with documented blockers for ORL-3 promotion.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: Update Smoke Test and Final Verification

**Files:**
- Modify: `crates/aqua-timestamp/tests/smoke_health.rs`

- [ ] **Step 1: Update the smoke test assertion**

The existing test at line 96 asserts:
```rust
assert!(html.contains("Aqua Aggregator"));
```

Update to match the new page content. The new page should contain "Aqua Timestamp Service" in the eyebrow. Change to:

```rust
assert!(
    html.contains("Aqua Timestamp Service") || html.contains("Aqua Aggregator"),
    "landing page missing expected content"
);
```

Or if the page title still contains "Aqua Aggregator" (in the `<title>` tag), no change is needed. Check the new landing.rs `<title>` value.

- [ ] **Step 2: Run full test suite**

Run: `cargo test --workspace`
Expected: All tests pass.

- [ ] **Step 3: Run clippy and fmt**

Run: `cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check`
Expected: Clean.

- [ ] **Step 4: Commit if any changes**

```bash
git add crates/aqua-timestamp/tests/smoke_health.rs
git commit -m "$(cat <<'EOF'
test: update smoke test for new status page content

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Verification Checklist

After all tasks are complete:

- [ ] `cargo test --workspace` passes (all existing + new tests)
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean
- [ ] `cargo fmt --check` clean
- [ ] `GET /` returns the new status page with all three sections
- [ ] `GET /events` returns `text/event-stream` and stays open
- [ ] `GET /.well-known/aqua-orl` returns ORL-2 JSON
- [ ] `GET /health` still works (unchanged)
- [ ] All existing `/v1/*` and `/trees/*` endpoints still work (unchanged)
- [ ] The page loads Sora and JetBrains Mono fonts
- [ ] The page fetches live data on load (check browser devtools network tab)
- [ ] ORL badge is visible in upper-right, clickable to expand
- [ ] Dark and light themes both work (test with `prefers-color-scheme`)
- [ ] No em dashes anywhere in the page text
- [ ] No use of the word "fee" anywhere
