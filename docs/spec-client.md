# Aqua Timestamp Client: Design Specification

**Version:** 0.1.0-draft
**Date:** 2026-05-17
**Status:** Planning. No code yet. Supersedes nothing; this is a new crate proposal.

## 1. Purpose and scope

`aqua-timestamp-client` is a reusable Rust crate that talks to a deployed
Aqua Timestamp Aggregator (e.g. `timestamp.inblock.io`). It exposes the
submit + poll + fetch + verify flow as a small, async API. Consumers use it
to hand the aggregator a 32-byte hash and later retrieve a server-signed
witness pair (TimestampObject + Signature revisions) that they splice into
their own Aqua-tree using existing `aqua-rs-sdk` primitives.

The crate's job is the **protocol**. The caller's job is the **workflow**:
when to submit, where to persist receipts, how often to poll, and how to
attach witnesses to whichever tree the caller already owns.

### 1.1 In scope

- Authenticated HTTP wire client for the endpoints defined in
  [`docs/success-criteria.md`](success-criteria.md): `/auth/*`, `/v1/leaves`,
  `/v1/schedule`, `/trees/by-leaf/{leaf}`, `/trees/{tip}`,
  `/.well-known/aqua-identity`.
- CAIP-122 auth handshake via `aqua_auth::client::authenticate` (using
  the canonical `aqua_auth::wire::ChallengeEnvelope`), with token
  caching and single-flight refresh layered on top.
- Server identity discovery via `/.well-known/aqua-identity` and in-memory
  pinning for the client's lifetime.
- SSH-style rotation detection across client instances (caller-driven).
- Witness retrieval, signature verification against the pinned server DID,
  and a typed witness-pair return value.
- Optional file-backed `KnownServersFile` helper (feature-gated) modelled
  on `~/.ssh/known_hosts`.

### 1.2 Out of scope

- No `aqua_rs_sdk::core::timestamp::TimestampProvider` implementation. The
  SDK trait is the abstraction for **synchronous, per-hash** timestamping
  (one transaction per submission). This crate fronts an **async, batched**
  service whose unit of work is an epoch. Pretending to be a
  `TimestampProvider` would smuggle a multi-minute block into every SDK
  call site that uses the trait. See [§2](#2-strategic-context).
- No persistence layer. The crate holds no database, no file beyond the
  optional known-servers helper, no session state across processes. Callers
  persist receipts, witnesses, and prior server DIDs in whatever store they
  already have.
- No portal integration code, no aquafire integration code. Those are
  consumer-side wiring and live in their respective repos.
- No retry policy, no exponential-backoff schedules, no circuit breakers.
  These are workflow concerns. The crate exposes single-shot calls and a
  bounded `await_witness` helper; everything else composes on top.
- No re-implementation of SDK verification. The crate verifies signatures
  on the wire (witness signature recovers to pinned server DID); deep
  tree verification belongs to `verify_aqua_tree_util`.

## 2. Strategic context

The Aqua ecosystem has **two** timestamping service tiers, producing the
same artefact shape but with different cost and latency profiles. They are
not interchangeable. The choice between them is a deployment decision, not
a code decision.

| Service tier | Backed by | Latency per hash | On-chain tx | Evidence layers |
|---|---|---|---|---|
| **SDK-direct** | a caller-provided `TimestampProvider` impl (talks to a TSA or an EVM contract directly) | seconds | one per hash | 1 anchor |
| **Aggregator** (this client) | `timestamp.inblock.io` | up to one epoch (~10 min) | one per epoch, regardless of submission count | 4 layers per hash: server signature + Merkle inclusion proof + EVM transaction + qTSA token, all bound to the same epoch root |

For high-volume or non-real-time workloads (session-close seals, identity
claims at boot, signed contracts in bulk), the aggregator is strictly
better on cost and evidence strength, at the price of one epoch of
latency. Anything user-facing and synchronous should keep using SDK-direct
timestamping; this client is the path to the cheaper, stronger tier.

The closest prior art is Certificate Transparency log clients
(RFC 6962 / 9162). The server uses RFC 9162 for its Merkle tree, the
submit-then-poll-then-fetch shape is identical, and the inclusion-proof
verification path is structurally the same.

## 3. Dependencies

| Crate | Version | Use |
|---|---|---|
| `aqua-rs-sdk` | workspace path dep | `AnyRevision`, `AquaTree`, `EvmTimestampPayload`, `TsaTimestampPayload` for witness types; `verification::Linkable` for signature recovery |
| `aqua-auth` | workspace path dep, feature `client` | `client::authenticate` for the CAIP-122 handshake, now consuming `aqua_auth::wire::ChallengeEnvelope` (no `did` field) and returning a `Session`. The wire envelope was added in aqua-rs-auth `0.1.x` after this client's first live test surfaced a server/client wire mismatch; see `aqua-rs-auth/SPEC.md` for the canonical CAIP-122 Aqua wire contract. |
| `reqwest` | 0.12 (rustls, json) | HTTP transport |
| `tokio` | 1 (rt, time, sync) | Async runtime primitives (mutex for token cache, `Notify` for single-flight) |
| `serde`, `serde_json` | 1 | Wire types |
| `hex` | 0.4 | Hash encoding (with-and-without `0x` prefix tolerant) |
| `sha3` | 0.10 | Local Merkle root reconstruction in tests; not used in production verification path |
| `thiserror` | 2 | Error enum |
| `tracing` | 0.1 | Observability (rotation warnings, retry attempts) |
| `async-trait` | 0.1 | For optional caller-provided trust callback |

Optional dev/test deps:

| Crate | Use |
|---|---|
| `wiremock` | HTTP-level unit tests without a live server |
| `proptest` | Hex round-trip, prefix tolerance, length validation |
| `tempfile` | `KnownServersFile` tests |

No new workspace-level deps required. Everything is already pulled in by
the existing `aqua-timestamp` crate or by `aqua-rs-sdk`.

## 4. Boundaries and non-goals

| Boundary | Rule |
|---|---|
| **Server contract** | If the wire format needs to change, change `aqua-timestamp` (server) first. The client mirrors. |
| **SDK types** | The crate re-exports `AnyRevision`, `AquaTree`, and the timestamp payload types as needed in the public API. It does not wrap them. Callers operate on SDK types directly. |
| **Persistence** | The crate has no DB. The optional `KnownServersFile` is the only on-disk artefact and it is opt-in. |
| **Threading** | `TimestampClient` is `Clone + Send + Sync` via internal `Arc`. Concurrent submissions and fetches from a single instance are supported. The token refresh is single-flight. |
| **Auth** | Only the three CAIP-122 namespaces the server's verifier accepts (`eip155`, `ed25519`, `p256`). API keys are not supported by the server, so not by the client. |
| **Hash type** | Only FIPS_202-SHA3-256 (32-byte, the server's only accepted hash type today). Public API takes `&[u8; 32]`. |
| **Anchor methods** | `Evm` and `Qtsa`. The caller picks which to fetch; the crate does not bundle them. |

## 5. Trust model

The trust model is the load-bearing part of this design and is worth its
own section.

### 5.1 What the server provides

Every authenticated endpoint returns artefacts signed by the server's
secp256k1 key (the same key that anchors to Sepolia). The server's identity
is published at `https://timestamp.inblock.io/.well-known/aqua-identity` as
a signed `service_claim_server` Aqua-tree. TLS authenticates the FQDN; the
signed claim asserts "this DID belongs to this domain".

### 5.2 In-session pinning (always on)

At `build().await?` the client fetches `/.well-known/aqua-identity` over
HTTPS, verifies the returned Aqua-tree is a self-consistent signed
`service_claim_server`, extracts the server DID, and pins it in memory for
the lifetime of the `TimestampClient` instance. Every subsequent witness
signature must recover to that pinned DID, or the call fails with
`ClientError::SignatureMismatch`. There is no per-call leeway.

This catches: MITM on individual fetches, server bugs that return wrong
signatures, tampered responses in transit.

### 5.3 Cross-session rotation detection (caller-driven, SSH-style)

The client does not persist anything. The caller is responsible for
recording the discovered DID after `build()` succeeds and passing it back
in on the next construction.

Three modes, by builder argument:

| Builder call | Behavior |
|---|---|
| (none, default) | Pure bootstrap. Fetch well-known, pin discovered DID, proceed. No prior to compare against. |
| `.expect_server_did(prior, OnRotation::Warn)` | Compare discovered DID against `prior`. On match: proceed silently. On mismatch: emit `tracing::warn!`, expose the rotation via `client.rotation_detected()`, pin the **new** DID, proceed. |
| `.expect_server_did(prior, OnRotation::Refuse)` | Compare. On mismatch: build fails with `ClientError::ServerIdentityRotated { prior, discovered }`. |
| `.expect_server_did(prior, OnRotation::Custom(cb))` | Caller-defined decision. Callback receives `&ServerRotation`, returns `RotationDecision::Accept` or `Reject`. |

This is the SSH `known_hosts` model. First contact bootstraps via HTTPS
plus the signed claim. Subsequent contacts detect drift. The strictness of
the response to drift is the caller's choice, because the right answer
depends on operational context (a dev machine wants Warn; a production
deployment with a stable host wants Refuse).

### 5.4 Threat model summary

| Attack | Detection |
|---|---|
| Active MITM forging a witness in transit (within one session) | EIP-191 recovery does not match pinned DID. Fails immediately. |
| Server returns malformed signature | Same, by the same path. |
| Domain takeover + new TLS cert + new DID, between sessions | First request after takeover discovers the new DID. If caller used `Refuse`, build fails. If `Warn`, banner fires. If neither, undetected (caller chose not to track). |
| Server operator legitimately rotates the secp256k1 key | Same paths as takeover. The caller's `OnRotation` policy decides whether rotation is acceptable. |
| TLS-stripping MITM at first contact | Caught by HTTPS itself; the client always uses HTTPS for the well-known fetch. (Caller can override `base_url` to HTTP for dev; this is the caller's problem.) |

### 5.5 KnownServersFile (optional helper)

Behind feature flag `known-servers-file`. A minimal JSON-line file (default
path `$XDG_CONFIG_HOME/aqua/known_servers`, falling back to
`~/.config/aqua/known_servers`) that records `(base_url, discovered_did,
first_seen_at, last_seen_at)`. About 50 lines of code. Provides:

```rust
impl KnownServersFile {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self>;
    pub fn open_default() -> io::Result<Self>;
    pub fn lookup(&self, base_url: &str) -> Option<&str>;        // returns prior DID if known
    pub fn record(&mut self, base_url: &str, did: &str) -> io::Result<()>;
}
```

Callers with a database ignore this. Callers writing CLIs or small services
get the SSH ergonomics for free.

## 6. Public API

```rust
// === Top-level handle ===

#[derive(Clone)]
pub struct TimestampClient { /* Arc<Inner> */ }

impl TimestampClient {
    pub fn builder() -> TimestampClientBuilder;
}

// === Builder ===

pub struct TimestampClientBuilder { /* ... */ }

impl TimestampClientBuilder {
    /// Required. e.g. "https://timestamp.inblock.io". HTTPS strongly recommended;
    /// the client will accept HTTP for dev but the trust model assumes HTTPS.
    pub fn base_url(self, url: impl Into<String>) -> Self;

    /// Required. The caller's DID, used in the CAIP-122 handshake.
    pub fn my_did(self, did: impl Into<String>) -> Self;

    /// Required. Closure that signs a CAIP-122 message and returns hex.
    /// Caller signs the canonical CAIP-122 message and returns a hex signature.
    pub fn signer<F>(self, signer: F) -> Self
    where F: Fn(&str) -> Result<String, BoxError> + Send + Sync + 'static;

    /// Optional. Cross-session rotation handling. If omitted: pure bootstrap.
    pub fn expect_server_did(self, prior: impl Into<String>, on_rotation: OnRotation) -> Self;

    /// Optional. Override the default 10s HTTP timeout for individual requests.
    pub fn request_timeout(self, dur: Duration) -> Self;

    /// Optional. Override the default `tokio::time::interval` cadence (5s) used by
    /// `await_witness` while polling `/v1/schedule`.
    pub fn poll_interval(self, dur: Duration) -> Self;

    /// Performs the well-known fetch, validates the signed identity claim,
    /// applies the rotation policy, and runs the initial CAIP-122 handshake to
    /// confirm the signer can authenticate. Returns a ready-to-use client.
    pub async fn build(self) -> Result<TimestampClient, ClientError>;
}

// === Operations ===

impl TimestampClient {
    /// Submit a single 32-byte hash to the currently-open epoch.
    pub async fn submit(&self, hash: &[u8; 32]) -> Result<SubmissionReceipt, ClientError>;

    /// Submit a batch in one request. Receipts are returned in input order.
    /// Dedup against the same epoch is handled server-side; duplicates appear
    /// in the response with the same `epoch_id` as the original submitter.
    pub async fn submit_many(&self, hashes: &[[u8; 32]]) -> Result<Vec<SubmissionReceipt>, ClientError>;

    /// Non-blocking witness lookup.
    /// - Returns `Ok(None)` if the epoch has not sealed yet.
    /// - Returns `Ok(Some(_))` with a verified witness if available.
    /// - Returns `Err` on auth, transport, or signature-verification failures.
    pub async fn try_fetch_witness(
        &self, leaf: &[u8; 32], method: AnchorMethod
    ) -> Result<Option<WitnessPair>, ClientError>;

    /// Blocking witness lookup with a caller-provided timeout. Polls
    /// `/v1/schedule` at the configured cadence until the receipt's epoch
    /// is sealed, then fetches and verifies the witness.
    pub async fn await_witness(
        &self, receipt: &SubmissionReceipt, method: AnchorMethod, timeout: Duration
    ) -> Result<WitnessPair, ClientError>;

    /// Current epoch schedule. Public, no auth required.
    pub async fn schedule(&self) -> Result<EpochSchedule, ClientError>;

    /// The server identity captured at `build()`. Sync, no I/O.
    pub fn server_identity(&self) -> &ServerIdentity;

    /// Returns `Some(_)` if the discovered DID at build time differed from the
    /// `expect_server_did` prior. Useful when `OnRotation::Warn` was chosen.
    pub fn rotation_detected(&self) -> Option<&ServerRotation>;
}

// === Wire types ===

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmissionReceipt {
    pub leaf: [u8; 32],
    pub epoch_id: u64,
    pub epoch_closes_at: u64,    // unix seconds
    pub submitter_did: String,
}

#[derive(Clone, Debug)]
pub struct WitnessPair {
    pub object_revision: aqua_rs_sdk::schema::AnyRevision,
    pub signature_revision: aqua_rs_sdk::schema::AnyRevision,
    pub object_hash: String,         // hex, links signature_revision's previous_revision
    pub signature_hash: String,      // hex, becomes the new tree tip
    pub anchor_method: AnchorMethod,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochSchedule {
    pub current_epoch_id: u64,
    pub current_epoch_opened_at: u64,
    pub current_epoch_closes_at: u64,
    pub epoch_duration_secs: u64,
    pub last_sealed_epoch_id: Option<u64>,
    pub last_sealed_at: Option<u64>,
    pub anchor_methods: Vec<AnchorMethod>,
}

#[derive(Clone, Debug)]
pub struct ServerIdentity {
    pub did: String,
    pub address: String,                                 // EIP-55 derived from DID
    pub identity_tree: aqua_rs_sdk::AquaTree,            // full signed service_claim_server
}

#[derive(Clone, Debug)]
pub struct ServerRotation {
    pub prior_did: String,
    pub discovered_did: String,
    pub discovered_identity_tree: aqua_rs_sdk::AquaTree,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AnchorMethod { Evm, Qtsa }

// === Trust policy ===

pub enum OnRotation {
    Refuse,
    Warn,
    Custom(Arc<dyn Fn(&ServerRotation) -> RotationDecision + Send + Sync>),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RotationDecision { Accept, Reject }

// === Errors ===

#[derive(thiserror::Error, Debug)]
pub enum ClientError {
    #[error("transport error: {0}")] Http(#[from] reqwest::Error),
    #[error("authentication failed: {0}")] Auth(String),
    #[error("server returned {status}: {body}")] Server { status: u16, body: String },

    #[error("server identity at {base_url} could not be discovered: {source}")]
    IdentityDiscovery { base_url: String, #[source] source: Box<dyn std::error::Error + Send + Sync> },

    #[error("server identity rotated from {prior} to {discovered}")]
    ServerIdentityRotated { prior: String, discovered: String },

    #[error("witness signature does not recover to pinned server DID")]
    SignatureMismatch,

    #[error("witness for leaf {leaf} via {method:?} not yet available")]
    NotYetSealed { leaf: String, method: AnchorMethod },

    #[error("witness for leaf {leaf} via {method:?} not found (epoch sealed but no witness present)")]
    WitnessMissing { leaf: String, method: AnchorMethod },

    #[error("timeout waiting for witness after {elapsed:?}")] Timeout { elapsed: Duration },

    #[error("invalid input: {0}")] Invalid(String),
}
```

That is the complete surface. One builder, one client, eight client
methods, six wire types, two policy types, one error enum. Behind a
feature flag: `KnownServersFile` with two methods.

## 7. Internal architecture

```
TimestampClient (Arc<Inner>)
├── http: reqwest::Client                            // pooled, rustls
├── base_url: Url                                    // immutable
├── server: ServerTrust                              // immutable post-build
│     ├── pinned_did: String
│     ├── pinned_address: String                     // EIP-55, derived from DID
│     ├── identity_tree: AquaTree                    // cached from build-time fetch
│     └── rotation: Option<ServerRotation>           // populated if drift was accepted
├── auth: AuthState
│     ├── my_did: String
│     ├── signer: Arc<dyn Fn(&str) -> Result<String, BoxError> + Send + Sync>
│     ├── token: Mutex<Option<(String, valid_until_unix: u64)>>
│     └── refresh_in_flight: Notify                  // single-flight broadcaster
└── config: ClientConfig { request_timeout, poll_interval }
```

### 7.1 Build sequence

1. Validate required builder fields. Reject if `base_url`, `my_did`, or
   `signer` missing.
2. Construct `reqwest::Client` with `request_timeout`.
3. `GET {base_url}/.well-known/aqua-identity` (no auth).
4. Parse the response: extract `server_did`, parse `identity_claim` as an
   `AquaTree`, verify it is a self-consistent signed `service_claim_server`
   (signature recovers to `server_did`). Reject otherwise.
5. Apply rotation policy:
   - If `expect_server_did(prior, policy)` was set, compare prior vs
     discovered. Apply `policy`.
   - Else proceed with discovered.
6. Run one CAIP-122 handshake (`GET /auth/challenge` → caller signs →
   `POST /auth/session`). Confirms the signer works and seeds the token
   cache. Failure here fails `build()`.
7. Return the client.

### 7.2 Token cache and single-flight refresh

The cache is a `Mutex<Option<(token, valid_until)>>`. Every authenticated
call goes through `ensure_token() -> String`:

```text
ensure_token():
  loop:
    read cache under mutex.
    if Some(token) and now < valid_until - 60s: return token.
    drop mutex; wait on refresh_in_flight notification.
    [or, if I'm the first to notice expiry] perform refresh:
      run CAIP-122 handshake
      write new (token, valid_until) into cache
      notify_all on refresh_in_flight
      return token
```

Single in-flight refresh; concurrent callers wait and pick up the new
token from the cache. Refresh failures bubble as `ClientError::Auth`.

### 7.3 Witness verification

For any returned `WitnessPair`:

1. Extract the EIP-191 signature from `signature_revision`.
2. Recover the signer address from the signature over
   `signature_revision.previous_revision` (which is `object_hash`).
3. Compare recovered address to `pinned_address`. Reject on mismatch.
4. Check `signature_revision.previous_revision == object_hash`. Reject
   on mismatch (catches transposed responses).
5. Return the verified pair.

Deeper checks (Merkle inclusion proof, EVM transaction inclusion, qTSA
token validation) are deferred to `verify_aqua_tree_util` once the caller
has attached the witness to their tree. The client validates the **wire**;
the SDK validates the **chain**.

## 8. Submission and witness flow

### 8.1 Happy path, single submission

```rust
let client = TimestampClient::builder()
    .base_url("https://timestamp.inblock.io")
    .my_did(my_did)
    .signer(my_signer)
    .expect_server_did(stored_did, OnRotation::Warn)
    .build().await?;

let leaf: [u8; 32] = my_hash;

let receipt = client.submit(&leaf).await?;
// Persist receipt; return to user immediately.
my_db.record_pending(&receipt, "evm")?;

// Later, in a background sweep, or in the same task with await_witness:
let witness = client.await_witness(&receipt, AnchorMethod::Evm, Duration::from_secs(900)).await?;

// Splice into the original tree using SDK primitives.
let mut tree: AquaTree = my_store.load_tree(&receipt.leaf)?;
tree.revisions.insert(witness.object_hash.clone(), witness.object_revision);
tree.revisions.insert(witness.signature_hash.clone(), witness.signature_revision);
my_store.save_tree(&tree)?;
```

### 8.2 Poll-driven workflow (typical for background reconcilers)

```rust
for pending in my_db.pending_due_for_check()? {
    match client.try_fetch_witness(&pending.leaf, pending.method).await? {
        Some(witness) => {
            my_store.attach_and_persist(&pending, witness)?;
            my_db.mark_witnessed(&pending)?;
        }
        None => {
            // epoch not sealed yet; leave row pending, retry next sweep
        }
    }
}
```

### 8.3 Dual-anchor pattern

```rust
let (evm, qtsa) = tokio::join!(
    client.await_witness(&receipt, AnchorMethod::Evm,  Duration::from_secs(900)),
    client.await_witness(&receipt, AnchorMethod::Qtsa, Duration::from_secs(900)),
);
let evm = evm?;
let qtsa = qtsa?;
// Splice both into the tree.
```

The two witnesses are independent; failing to fetch one does not
invalidate the other. Callers decide whether one anchor is sufficient or
both are required.

## 9. Error semantics

| Error variant | Meaning | Retryable? |
|---|---|---|
| `Http(_)` | Transport-level failure (DNS, TLS, connection reset, timeout) | Yes, by the caller. Transient. |
| `Auth(_)` | Handshake failed (signer rejected, server returned bad challenge, token request 4xx) | Maybe; if the caller's signer is wrong, no. |
| `Server { status, body }` | HTTP 4xx or 5xx outside the auth path. Body is the server's error payload verbatim. | 5xx: yes. 4xx: investigate. |
| `IdentityDiscovery { .. }` | `/.well-known/aqua-identity` unreachable or malformed | Usually no; the server is misconfigured. |
| `ServerIdentityRotated { .. }` | `OnRotation::Refuse` matched a rotation | No; requires operator intervention. |
| `SignatureMismatch` | A returned signature did not recover to the pinned server DID | No; this is a security event. Caller should log and alert, not retry. |
| `NotYetSealed { .. }` | `try_fetch_witness` was called before the epoch sealed | Yes, after waiting. |
| `WitnessMissing { .. }` | Epoch is sealed but the server has no witness for that leaf | Investigate; usually means the leaf was never accepted (check submission). |
| `Timeout { .. }` | `await_witness` exhausted the caller-supplied timeout | Yes, with a longer timeout. |
| `Invalid(_)` | Caller error (e.g. malformed hash) | No. |

The crate does no automatic retries. Every failed call returns to the
caller, which decides policy.

## 10. Testing strategy

| Tier | What | How |
|---|---|---|
| Unit | Builder validation, hex parsing tolerance, error mapping, token refresh, single-flight behavior, signature verification | Pure functions and `wiremock` for HTTP |
| Wire compatibility | Every endpoint shape against a `wiremock` fixture matching the [`success-criteria.md`](success-criteria.md) contract | `wiremock` |
| Integration | Live happy path against `timestamp.inblock.io` | Feature-gated `live-tests`; needs an allowlisted DID and `TIMESTAMP_BASE_URL` env var; default off in CI |
| Trust | Rotation policies, MITM (forged signature in fixture), TOFU bootstrap, `OnRotation::Refuse` | `wiremock` returning crafted bad signatures |
| Concurrency | 64 concurrent submit + fetch from a single client; assert token refresh runs once | `tokio::test` + `wiremock` with a slow `/auth/session` |
| Property | Hash byte arrays round-trip through hex with and without `0x` prefix; epoch ID parsing | `proptest` |

Coverage target: 80% line coverage in the crate; 100% on signature
verification and rotation policy paths (they are the trust surface).

## 11. Rollout

Two waves. After these, the crate is shipped and consumers wire it on
their own schedule.

### Wave A: crate scaffold and offline correctness

Goal: crate builds, every public method has a unit test that exercises
its happy path and at least one failure mode, no live network required.

Deliverables:
- New workspace member `crates/aqua-timestamp-client/`.
- Public API matching [§6](#6-public-api).
- `wiremock`-backed unit tests for the eight client methods and the three
  rotation policies.
- README inside the crate with a five-line example.
- `lib.rs` top-of-file docstring that explicitly contrasts the crate with
  SDK-direct timestamping (paraphrasing [§2](#2-strategic-context)) so the
  "when to use this versus the SDK" question is answered in the first
  paragraph anyone reads.

Exit criteria: `cargo test -p aqua-timestamp-client` green; `cargo clippy
-p aqua-timestamp-client -- -D warnings` clean.

### Wave B: live integration

Goal: prove the crate works end-to-end against the deployed server.

Deliverables:
- Allowlist a test DID on the deployed `timestamp.inblock.io` (operational,
  not code).
- One integration test under `tests/live_roundtrip.rs` (feature-gated)
  that mirrors `tests/e2e/live_roundtrip.sh` from the server repo: submit
  one hash, await the EVM witness, await the qTSA witness, verify both.
- Update the server's `runbooks/` with a "verifying the client against
  the live deployment" page.

Exit criteria: `cargo test -p aqua-timestamp-client --features live-tests
--test live_roundtrip` green against the deployed server, both anchor
methods.

### Out of scope for this rollout (deliberate)

- `agent-customer-portal` `session_timestamps` table and reconciler sweep.
- Portal server-identity timestamping at boot.
- Aquafire integration.
- Any TimestampProvider impl.

These ship later as consumer work in their respective repos. They depend
on this crate, not the other way around.

## 12. Open questions

1. **Crate naming.** `aqua-timestamp-client` is descriptive but verbose.
   Alternative: `aqua-timestamp-rs` follows the convention of `aqua-rs-sdk`
   and `aqua-rs-auth`. Pick before publishing.
2. **`KnownServersFile` location default.** XDG-compliant
   (`$XDG_CONFIG_HOME/aqua/known_servers`) is the right choice on Linux;
   macOS and Windows may want platform-native defaults. Decide once the
   first non-Linux consumer appears; until then, XDG with a fallback.
3. **Re-export surface.** Whether to re-export `aqua_rs_sdk::AquaTree`
   and `AnyRevision` from this crate as a convenience, or require
   consumers to depend on `aqua-rs-sdk` directly. Lean towards "depend
   directly", to keep this crate from becoming a re-export hub.
4. **Tracing spans.** Every public method should produce a span, but the
   span attribute set (e.g. should `submit` log the leaf hash?) needs a
   privacy review. Leaf hashes are not PII but are linkable to caller
   identity via the submitter DID.
5. **Future: streaming submissions.** If a caller has thousands of hashes
   per epoch, batching them into a single `POST /v1/leaves` is preferable
   to N individual calls. `submit_many` covers this, but a streaming
   `submit_stream(impl Stream<Item = [u8; 32]>)` could buffer + flush by
   either count or time. Defer; revisit when a real consumer hits the
   limit.

## 13. References

- [`docs/design-spec.md`](design-spec.md): server design (read with the
  skepticism note at the top).
- [`docs/success-criteria.md`](success-criteria.md): authoritative server
  contract per milestone.
- [`docs/runbooks/`](runbooks/): live transcripts of the server's E2E flow.
- `aqua-rs-sdk/src/core/timestamp/traits.rs`: the `TimestampProvider`
  trait we deliberately do **not** implement.
- `aqua-rs-sdk/src/schema/timestamp.rs`: `TimestampValue`,
  `EvmTimestampPayload`, `TsaTimestampPayload` (the witness payload
  shapes; the server already emits these via the SDK).
- `aqua-rs-auth/src/client.rs`: `authenticate()` (the CAIP-122 handshake
  we wrap).
- RFC 9162 (Certificate Transparency 2.0): the closest CS prior art for
  the submit-then-poll-then-fetch shape.
