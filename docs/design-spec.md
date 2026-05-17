# Aqua Aggregator: Design Specification

**Version:** 0.3.0-draft
**Date:** 2026-05-16
**Status:** Historical (pre-implementation). Superseded by what actually shipped.

> **Read this with skepticism.** This document predates the
> implementation. Several decisions captured below were deliberately
> overridden during the M0..M5 build; the `aqua-rs-sdk` is the
> authoritative source of truth where the two disagree. For the
> shipped reality:
>
> - per-milestone contract: [`success-criteria.md`](success-criteria.md);
> - per-milestone runbooks with live transcripts: [`runbooks/`](runbooks/);
> - operational context for the next session: [`../CLAUDE.md`](../CLAUDE.md).
>
> Known divergences from this document:
>
> - Service identity uses **secp256k1 + EIP-191** (the aquafire
>   reference shape), not Ed25519.
> - The identity tree is built from the SDK's
>   `service_claim_server` template (not a hand-rolled service_claim).
> - `aqua-rs-auth` accepts all three CAIP-122 namespaces (`eip155`,
>   `ed25519`, `p256`); clients are not restricted to one curve.
> - `aqua-node` does not expose `/trees/by-leaf/...` or
>   `/trees?epoch=&method=...`; aqua-timestamp adds those as
>   additive extensions returning the same `Tree` shape so aqua-node
>   clients consume them transparently.
> - The qTSA endpoint is Sectigo qualified
>   (`http://timestamp.sectigo.com/qualified`), not D-Trust.

## 1. Purpose

The Aqua Aggregator is a high-throughput timestamping service that batches revision hashes from multiple Aqua-enabled services into Merkle trees and dual-anchors them to both an EVM Layer 1 blockchain AND an eIDAS-qualified TSA in periodic epochs. It optimizes cost and throughput by amortizing two anchor operations (one on-chain transaction + one qTSA request) across thousands of hashes per epoch.

**Primary clients at launch:**
- `aquafire.inblock.io` (aquafier-rs) - document verification engine
- `agentic.inblock.io` (agent-customer-portal) - agentic session audit trails

Both produce high volumes of revision hashes (T1-T8 artifacts, sealed rounds, session closes) that benefit from anchoring but cannot justify per-hash on-chain cost.

**Key design decisions:**
- Proof responses are **witness revisions** (TimestampObject + AggregatorSignature) that chain directly off the client's submitted leaf hash via `previous_revision`. Served via aqua-node-compatible REST API (`GET /trees/{tip}`).
- Every epoch is **always dual-anchored** (EVM + eIDAS qTSA); the client chooses which witness revisions to retrieve
- The aggregator has its own **service identity** (Ed25519 DID), published as a service_claim tree at `.well-known/aqua-identity`
- Every witness revision is **signed by the aggregator** (Ed25519), providing offline-verifiable authorship, trust store integration, and forgery resistance
- Submitters can **only retrieve witness revisions for leaves they submitted** (DID-scoped access)

---

## 2. Core Concepts

### 2.1 Epoch Model

The aggregator operates in fixed-duration **epochs** (configurable, default: 10 minutes). Each epoch:

1. **Accumulation phase** - clients submit hashes; aggregator buffers them
2. **Seal phase** - epoch closes, Merkle tree is built from all buffered hashes
3. **Dual-anchor phase** - Merkle root is submitted to BOTH EVM contract AND eIDAS qTSA simultaneously
4. **Revision minting phase** - per-leaf witness revisions (TimestampObject + Signature) are produced and signed
5. **Distribution phase** - witness revisions become available for client retrieval

```
Timeline:
  ─────[Epoch N]──────┬─────[Epoch N+1]──────┬─────
  accumulate          seal                    accumulate
                      dual-anchor (EVM + qTSA)
                      mint witness revisions
                      distribute (pull)
```

### 2.2 Pull Model

Clients **pull** results rather than receiving push notifications:

- Clients query the aggregator's schedule to learn when the current epoch closes
- After the epoch anchors, clients fetch their witness revisions
- This eliminates webhook infrastructure, retry logic, and firewall traversal problems
- Clients can be offline during anchoring and retrieve witness revisions at any later time

### 2.3 Dual Trust Model

Every epoch root is submitted to **both** anchor providers simultaneously:

| Provider | Trust Basis | Legal Standing |
|----------|------------|----------------|
| **EVM (Ethereum/L2)** | Cryptographic consensus, immutable ledger | Technical proof of existence |
| **eIDAS-qualified TSA** | EU-regulated, legally binding timestamps | Legal proof of existence (eIDAS Art. 41) |

Clients receive separate witness trees for each anchor method. They choose which to incorporate based on their use case:
- Regulatory/legal compliance: use qTSA witness tree
- Crypto-native/decentralized trust: use EVM witness tree
- Maximum assurance: incorporate both

### 2.4 Terminology

| Term | Definition |
|------|-----------|
| **Epoch** | Fixed time window during which hashes are accumulated |
| **Leaf** | A single `RevisionLink` (SHA3-256, 32 bytes) submitted by a client |
| **Batch** | The set of all leaves in one epoch |
| **Anchor** | The on-chain or qTSA-submitted Merkle root of a batch |
| **Witness Revisions** | A pair of revisions (TimestampObject + Signature) that chain off the client's leaf via `previous_revision`, proving inclusion and authenticating the aggregator as author |
| **Inclusion Proof** | RFC 9162 path from leaf to Merkle root (embedded in TimestampObject payload) |

---

## 3. Aggregator Identity

### 3.1 Service DID

The aggregator holds a persistent **Ed25519 keypair** that defines its identity:

```
did:pkh:ed25519:0x<64-hex-pubkey>
```

This key is used to:
- Sign all witness trees it produces (server signature on every proof)
- Sign its service_claim (identity attestation)
- Authenticate to upstream providers if needed

### 3.2 Service Claim (`.well-known/aqua-identity`)

The aggregator publishes a **service_claim Aqua tree** at:

```
GET /.well-known/aqua-identity
```

This tree follows the same pattern as aqua-node and aquafier-rs:

```json
{
  "revisions": {
    "0x<genesis>": { ... },
    "0x<claim_object>": {
      "payloads": {
        "service_type": "aqua-aggregator",
        "service_url": "https://aggregator.aqua-protocol.org",
        "service_did": "did:pkh:ed25519:0x...",
        "operator": "inblock.io",
        "witness_methods": ["evm", "qtsa"],
        "evm_network": "sepolia",
        "qtsa_provider": "D-Trust TSA"
      }
    },
    "0x<signature>": { "signer": "did:pkh:ed25519:0x...", ... }
  }
}
```

Clients add the aggregator's DID to their **trust store**. When verifying a witness tree, the SDK checks that the signing DID is trusted, exactly as it does for any other Aqua signature.

### 3.3 Trust Establishment

1. Client operator obtains aggregator's DID (out-of-band or via `.well-known`)
2. Client adds DID to its trust store configuration
3. All witness trees signed by this DID are accepted during verification
4. If the aggregator rotates keys, it publishes a new service_claim; clients update trust stores

---

## 4. Authentication

Authentication uses **CAIP-122 challenge-response** via the `aqua-rs-auth` crate, identical to the flow used by aqua-node, aquafier-rs, and agent-customer-portal.

### 4.1 Client Identity

Each client authenticates with a **service DID**:
- `did:pkh:eip155:1:0x...` (EIP-191, secp256k1)
- `did:pkh:ed25519:0x...` (Ed25519)
- `did:pkh:p256:0x...` (P-256/passkey)

This is the same DID the client uses for signing Aqua trees. The aggregator does not issue separate API keys; the client's existing cryptographic identity is its credential.

### 4.2 Authentication Flow

```
Client                              Aggregator
  |                                     |
  |  GET /auth/challenge?did=...        |
  |------------------------------------>|
  |                                     |
  |  { nonce, message, expires_at }     |
  |<------------------------------------|
  |                                     |
  |  [sign message with service key]    |
  |                                     |
  |  POST /auth/session                 |
  |  { did, nonce, signature }          |
  |------------------------------------>|
  |                                     |
  |  { token, valid_until }             |
  |<------------------------------------|
  |                                     |
  |  [use Bearer token on all requests] |
```

### 4.3 Session Semantics

- Challenge TTL: 5 minutes (single-use nonce)
- Session TTL: 24 hours (long-lived for server-to-server)
- Background cleanup: expired sessions purged every 60 seconds
- Clients must re-authenticate on 401 (token expired or revoked)

### 4.4 Access Control

- The aggregator maintains an **allowlist** of DIDs permitted to submit hashes
- Configuration-driven list (no self-registration)
- **Isolation invariant:** a client can only retrieve witness trees for leaves it submitted (enforced by DID-scoped index)
- Future: rate limits per DID, tiered service levels

---

## 5. API Design

The aggregator exposes the **same REST API surface as aqua-node** for tree retrieval. Submission and scheduling use dedicated endpoints.

All endpoints require `Authorization: Bearer <session_token>` except `/health`, `/auth/*`, `/v1/schedule`, and `/.well-known/*`.

### 5.1 Hash Submission

```
POST /v1/leaves
Content-Type: application/json

{
  "leaves": [
    "0x<64-hex-chars>",
    "0x<64-hex-chars>",
    ...
  ]
}

Response 202 Accepted:
{
  "epoch_id": 1847,
  "accepted": 150,
  "epoch_closes_at": "2026-05-16T14:20:00Z"
}
```

**Constraints:**
- Each leaf is exactly 66 characters (`0x` + 64 hex = SHA3-256)
- Maximum 10,000 leaves per request
- Duplicate leaves within an epoch are deduplicated (idempotent)
- Leaves submitted after epoch seal are buffered into the next epoch

### 5.2 Schedule Query (Public)

```
GET /v1/schedule

Response 200:
{
  "current_epoch": 1847,
  "epoch_duration_secs": 600,
  "epoch_closes_at": "2026-05-16T14:20:00Z",
  "last_anchored_epoch": 1846,
  "last_anchor_time": "2026-05-16T14:10:12Z",
  "witness_methods": ["evm", "qtsa"],
  "evm_network": "sepolia",
  "qtsa_provider": "D-Trust"
}
```

### 5.3 Witness Revision Retrieval (aqua-node compatible)

Clients retrieve their witness revisions using aqua-node-compatible endpoints. The response is a minimal tree fragment (2 revisions) that the client merges into their own tree.

**List available witnesses for an epoch:**

```
GET /trees?epoch={epoch_id}&method={evm|qtsa}
Authorization: Bearer <token>

Response 200:
{
  "witnesses": [
    {
      "leaf": "0x<submitted_hash>",
      "tip": "0x<signature_revision_hash>",
      "method": "evm"
    },
    ...
  ]
}
```

**Fetch witness revisions by tip (aqua-node compatible):**

```
GET /trees/{tip_hex}
Authorization: Bearer <token>

Response 200:
{
  "revisions": {
    "0x<timestamp_object_hash>": {
      "previous_revision": "0x<client_submitted_leaf>",
      "revision_type": "0xc5f14954...",
      "nonce": "0x...",
      "local_timestamp": 1747404612,
      "version": "V4",
      "method": "scalar",
      "hash_type": "Fips_202-SHA3-256",
      "payloads": {
        "type": "timestamp",
        "merkle_root": "0x<epoch_root>",
        "merkle_proof": ["0x...", "0x...", ...],
        "batch_tree_size": 4200,
        "batch_leaf_index": 1337,
        "network": "sepolia",
        "smart_contract_address": "0x...",
        "transaction_hash": "0x...",
        "sender_account_address": "0x..."
      }
    },
    "0x<aggregator_signature_hash>": {
      "previous_revision": "0x<timestamp_object_hash>",
      "revision_type": "0x<ed25519_sig_template>",
      "nonce": "0x...",
      "local_timestamp": 1747404612,
      "version": "V4",
      "method": "scalar",
      "hash_type": "Fips_202-SHA3-256",
      "signer": "did:pkh:ed25519:0x<aggregator_pubkey>",
      "signature": { "Ed25519": { "signature": "...", "signature_public_identifier": "..." } }
    }
  },
  "file_index": {}
}
```

**Access control:** The endpoint verifies the requesting DID owns the leaf referenced in `previous_revision` of the TimestampObject. Unauthorized requests return 403.

### 5.4 Lookup by Leaf Hash

For clients that know the leaf hash but not the epoch or tip:

```
GET /trees/by-leaf/{leaf_hex}?method={evm|qtsa}
Authorization: Bearer <token>

Response 200:
{
  "leaf": "0x...",
  "epoch_id": 1846,
  "method": "evm",
  "tip": "0x<signature_revision_hash>",
  "revisions": { ... }
}
```

Returns the most recent witness revisions for this leaf. If anchored by both methods, `method` parameter selects which.

### 5.5 Epoch History

```
GET /v1/epochs?from={epoch_id}&limit=10

Response 200:
{
  "epochs": [
    {
      "epoch_id": 1846,
      "leaf_count": 4200,
      "merkle_root": "0x...",
      "anchored_at": "2026-05-16T14:10:12Z",
      "evm_tx_hash": "0x...",
      "qtsa_serial": "ABC123..."
    },
    ...
  ]
}
```

### 5.6 Identity Endpoint (Public)

```
GET /.well-known/aqua-identity

Response 200:
{ full service_claim Aqua tree JSON }
```

### 5.7 Health (Public)

```
GET /health

Response 200:
{
  "status": "ok",
  "current_epoch": 1847,
  "uptime_secs": 86400,
  "total_leaves_processed": 2100000,
  "last_anchor_status": {
    "evm": "confirmed",
    "qtsa": "confirmed"
  }
}
```

---

## 6. Witness Revision Structure

### 6.1 What the Aggregator Produces

For each leaf in a sealed epoch, the aggregator produces **two revisions per anchor method** that chain directly off the client's submitted hash:

```
Client's tree:     ... -> [their_tip: 0xABC...]
                                |
Aggregator adds:                +-> [TimestampObject]  (previous_revision = 0xABC...)
                                         |
                                         +-> [AggregatorSignature]  (previous_revision = <ts_obj_hash>)
```

The client receives these two revisions and **merges them directly into their own tree**. No genesis, no standalone tree. The `previous_revision` pointer on the TimestampObject already links them into the client's revision chain.

Per leaf, the aggregator can produce up to 4 revisions (2 per anchor method):
- EVM: TimestampObject (EvmTimestampPayload) + Signature
- qTSA: TimestampObject (TsaTimestampPayload) + Signature

The client chooses which pair to fetch (or both).

### 6.2 TimestampObject Revision

Uses the existing SDK `Object` structure with no modifications:

```rust
Object {
    previous_revision: Some(<client_submitted_leaf_hash>),  // chains off client's tip
    revision_type: EvmTimestampPayload::TEMPLATE_LINK,      // or TsaTimestampPayload::TEMPLATE_LINK
    nonce: Nonce::random(),
    local_timestamp: <epoch_seal_time>,
    version: V4,
    method: Method::Scalar,
    hash_type: HashType::Sha3_256,
    payloads: { ... },  // see 6.3
    leaves: None,
}
```

### 6.3 Payload Contents

**EVM variant** (uses existing `EvmTimestampPayload` template from SDK):
```rust
EvmTimestampPayload {
    timestamp_type: "timestamp",
    merkle_root: "0x<epoch_root>",
    merkle_proof: vec!["0x...", ...],    // RFC 9162 inclusion path
    batch_tree_size: 4200,               // Leaves in epoch
    batch_leaf_index: 1337,              // This leaf's position
    network: "sepolia",
    smart_contract_address: "0x...",
    transaction_hash: "0x...",
    sender_account_address: "0x...",     // Aggregator's EVM address
    timestamp: 1747404612,              // Block timestamp
}
```

**qTSA variant** (uses existing `TsaTimestampPayload` template from SDK):
```rust
TsaTimestampPayload {
    timestamp_type: "timestamp",
    merkle_root: "0x<epoch_root>",
    merkle_proof: vec!["0x...", ...],
    batch_tree_size: 4200,
    batch_leaf_index: 1337,
    network: "D-Trust",                 // TSA provider name
    transaction_hash: "0x...",          // RFC 3161 token digest
    tsa_provider: "https://tsa.d-trust.net/...",
    timestamp: 1747404612,
}
```

### 6.4 Aggregator Signature Revision

Every TimestampObject is followed by a Signature revision signed with the aggregator's Ed25519 key:

```rust
Signature {
    previous_revision: <timestamp_object_hash>,
    revision_type: SignatureEd25519::TEMPLATE_LINK,
    nonce: Nonce::random(),
    local_timestamp: <sign_time>,
    version: V4,
    method: Method::Scalar,
    hash_type: HashType::Sha3_256,
    signer: "did:pkh:ed25519:0x<aggregator_pubkey>",
    signature: SignatureValue::Ed25519 {
        signature: [u8; 64],
        signature_public_identifier: [u8; 32],
    },
}
```

### 6.5 Why the Signature is Required

The `sender_account_address` in the EVM payload is a string field, not a cryptographic binding. Without the Signature revision:

| Property | Without Signature | With Signature |
|----------|-------------------|----------------|
| Offline authorship verification | Requires blockchain query | Local Ed25519 verify |
| Forgery resistance | Anyone with on-chain data can construct valid-looking Object | Only aggregator's key can produce valid pair |
| Trust store integration | Inert (no signer DID to check) | Full (signer checked against client's trust store) |
| Protocol invariant | Violated (unsigned Object = unauthenticated datum) | Satisfied (authenticated data always has Signature) |
| Identity coherence | EVM address != aggregator DID (different keys) | Ed25519 signature links Object to aggregator's canonical identity |

Cost: ~200 bytes + ~20 microseconds (Ed25519 sign) per leaf. At 1M leaves/epoch, signing adds ~20 seconds.

### 6.6 Client Incorporation

After retrieving witness revisions, the client merges them into their tree's `revisions` map:

```rust
// Client's tree before:
tree.revisions = {
    "0x<genesis>": ...,
    "0x<obj1>": ...,
    "0x<sig1>": ...,
    "0x<tip>": ...,       // client's current tip (the submitted leaf)
}

// After merging EVM witness revisions:
tree.revisions = {
    "0x<genesis>": ...,
    "0x<obj1>": ...,
    "0x<sig1>": ...,
    "0x<tip>": ...,
    "0x<ts_obj>": Object { previous_revision: "0x<tip>", ... },     // NEW
    "0x<agg_sig>": Signature { previous_revision: "0x<ts_obj>", ... }, // NEW
}
```

The witness revisions form a **branch** off the client's tip (same topology as any other signature in Aqua: fork from the signed revision). The client's tree tip remains unchanged; the timestamp + signature are a side-branch proving the timestamp event.

### 6.7 Verification Flow (Client-Side)

When a verifier processes the client's tree:

1. **L1 (Hash integrity):** Confirms `0x<ts_obj>` hash matches its content
2. **L2 (Batch inclusion):** `verify_batch_inclusion()` validates Merkle proof against `merkle_root`
3. **Signature check:** Validates `0x<agg_sig>` against `signer: "did:pkh:ed25519:0x<agg>"`
4. **Trust store:** Confirms aggregator DID is in the verifier's trusted set
5. **On-chain validation (optional):** Can independently verify `transaction_hash` on-chain for additional assurance

Steps 1-4 are fully offline. Step 5 is optional belt-and-suspenders.

---

## 7. Architecture

### 7.1 Component Diagram

```
+---------------------------------------------------------------------------+
|                           Aqua Aggregator                                 |
|                                                                           |
|  +----------+   +--------------+   +-------------+   +----------------+  |
|  |  Axum    |   |  Epoch       |   |  Merkle     |   | Dual-Anchor    |  |
|  |  REST    |-->|  Accumulator |-->|  Builder    |-->| Engine         |  |
|  |  Layer   |   |  (in-memory) |   |  (RFC 9162) |   | (EVM + qTSA)  |  |
|  +----------+   +--------------+   +-------------+   +-------+--------+  |
|       |                                                       |           |
|       |          +--------------+   +---------------+         |           |
|       |          | Witness Rev  |<--| Rev Minter    |<--------+           |
|       +--------->| Store (fjall)|   | (Object+Sign) |                     |
|       |          +--------------+   +---------------+                     |
|       |                                                                   |
|       |          +--------------+                                         |
|       +--------->| Identity     |   (service_claim tree + signing key)    |
|                  | Module       |                                         |
|                  +--------------+                                         |
|                                                                           |
|  +------------------------------------------------------------------+    |
|  |  Auth Layer (aqua-rs-auth): ChallengeStore + SessionStore         |    |
|  +------------------------------------------------------------------+    |
+---------------------------------------------------------------------------+
         |                               |                    |
         | CAIP-122                      | EVM Witness        | qTSA Witness
         v                               v                    v
+-----------------+         +----------------+    +---------------------+
| Clients         |         | EVM Chain      |    | eIDAS qTSA          |
| (aquafier,      |         | (Sepolia,      |    | (D-Trust, SwissSign |
|  portal, etc.)  |         |  Mainnet, L2)  |    |  DigiCert, etc.)    |
+-----------------+         +----------------+    +---------------------+
```

### 7.2 Internal Components

| Component | Responsibility |
|-----------|---------------|
| **Axum REST Layer** | HTTP server, routing, request validation, auth middleware, aqua-node-compatible `/trees` endpoints |
| **Epoch Accumulator** | In-memory buffer of leaves per epoch; tracks submitter DID per leaf |
| **Merkle Builder** | Constructs RFC 9162 Merkle tree from epoch leaves; generates all inclusion proofs |
| **Dual-Anchor Engine** | Submits Merkle root to BOTH EVM contract AND qTSA simultaneously; awaits both confirmations |
| **Revision Minter** | Per leaf: constructs TimestampObject (with `previous_revision` = client leaf) + signs with aggregator Ed25519 key. Produces 2 revisions per leaf per anchor method. |
| **Witness Revision Store** | Persists revision pairs in fjall, indexed by (tip, leaf, submitter_did, method) |
| **Identity Module** | Manages aggregator's Ed25519 keypair, signs all witness revisions, serves `.well-known/aqua-identity` |
| **Auth Layer** | CAIP-122 challenge/response, session management (aqua-rs-auth) |

### 7.3 Crate Dependencies

```toml
[dependencies]
aqua-rs-auth = { path = "../aqua-rs-auth" }           # CAIP-122 auth
aqua-rs-sdk  = { path = "../aqua-rs-sdk" }            # Merkle, Tree, Object, Signature, templates
axum = "0.8"                                           # HTTP framework
fjall = "2"                                            # Persistent storage
tokio = { version = "1", features = ["full"] }         # Async runtime
dashmap = "6"                                          # Concurrent in-memory maps
serde = { version = "1", features = ["derive"] }       # Serialization
serde_json = "1"
tracing = "0.1"                                        # Structured logging
ed25519-dalek = "2"                                    # Aggregator signing key
```

---

## 8. Data Flow

### 8.1 Submission Path

```
Client POST /v1/leaves { leaves: [...] }
  |
  v
Auth middleware: validate Bearer token -> extract DID
  |
  v
Epoch Accumulator:
  - Determine current epoch_id from wall clock
  - Insert each leaf into epoch buffer (DashMap<EpochId, Vec<Leaf>>)
  - Track submitter: DashMap<(EpochId, LeafHash), DID>
  - Deduplicate within epoch (first submitter wins)
  |
  v
Return 202 { epoch_id, accepted, epoch_closes_at }
```

### 8.2 Epoch Seal + Dual-Anchor Path (Timer-Driven)

```
Tokio interval timer fires (every epoch_duration_secs):
  |
  v
Freeze current epoch:
  - Swap accumulator buffer (new epoch starts immediately)
  - Sealed epoch leaves are now immutable
  |
  v
Merkle Builder:
  - Sort leaves lexicographically (deterministic ordering)
  - Build RFC 9162 tree: merkle_root(sorted_leaves, SHA3-256)
  - Compute inclusion_proof for every leaf
  |
  v
Dual-Anchor Engine (parallel):
  - EVM: submit merkle_root to witness contract -> await tx receipt
  - qTSA: submit TimeStampReq(merkle_root) to eIDAS TSA -> await TimeStampToken
  - Both run concurrently (tokio::join!)
  |
  v
Revision Minter (for each leaf, for each anchor method):
  - Build TimestampObject:
      previous_revision = client's submitted leaf hash
      payloads = EvmTimestampPayload (or TsaTimestampPayload)
      includes inclusion proof + anchor data
  - Compute TimestampObject hash
  - Build Signature revision:
      previous_revision = TimestampObject hash
      signer = aggregator DID
      sign canonical JSON with aggregator Ed25519 key
  - Compute Signature hash (this becomes the "tip" for retrieval)
  |
  v
Persist (fjall):
  - Epoch metadata -> epochs partition
  - Per-leaf revision pairs -> witness_revisions partition (keyed by sig hash / tip)
  - Index: (submitter_did, epoch_id, leaf_hash) -> (evm_tip, qtsa_tip)
  - Index: leaf_hash -> latest epoch_id
  |
  v
Epoch marked as "anchored" (witness revisions now retrievable)
```

### 8.3 Retrieval Path

```
Client GET /trees/by-leaf/{leaf_hex}?method=evm
  |
  v
Auth middleware: validate Bearer token -> extract DID
  |
  v
Submitter index lookup:
  - Find (leaf_hash, method) -> tip (signature revision hash)
  - Verify submitter DID matches stored DID for this leaf
  - If mismatch: 403 Forbidden
  |
  v
Witness Revision Store:
  - Load revision pair (TimestampObject + Signature) by tip
  - Return as minimal tree JSON (2 entries in "revisions" map)
  |
  v
Return 200 { revisions: { ts_obj_hash: {...}, sig_hash: {...} }, file_index: {} }
```

---

## 9. Storage Design

### 9.1 Fjall Partitions

| Partition | Key | Value |
|-----------|-----|-------|
| `epochs` | `epoch_id` (u64 BE) | `EpochRecord { merkle_root, leaf_count, anchored_at, evm_tx_hash, qtsa_serial, evm_timestamp, qtsa_timestamp }` |
| `witness_revisions` | `tip_hash` (32 bytes) | Serialized revision pair: `(Object JSON, Signature JSON)` |
| `leaf_to_tips` | `leaf_hash ++ method_byte` (33 bytes) | `tip_hash` (signature revision hash) for this leaf+method |
| `submitter_index` | `did_hash ++ epoch_id` (40 bytes) | `Vec<leaf_hash>` (all leaves this DID submitted in this epoch) |
| `leaf_owner` | `leaf_hash ++ epoch_id` (40 bytes) | `did_hash` (who submitted this leaf; for access control) |
| `leaf_epochs` | `leaf_hash` (32 bytes) | `Vec<epoch_id>` (all epochs containing this leaf) |

### 9.2 Capacity Estimates

At 10,000 leaves per epoch (10-minute epochs):
- Revision pairs per epoch: 10,000 x 2 methods = 20,000 pairs
- Average revision pair size: ~800 bytes (TimestampObject ~500B + Signature ~300B)
- Per-epoch storage: ~16 MB (revisions) + ~2 MB (indices)
- Daily (144 epochs): ~2.6 GB
- **Retention policy:** 90 days rolling (configurable), older epochs and revisions pruned

At 100,000 leaves per epoch (scale target):
- Per-epoch: ~160 MB
- Daily: ~23 GB
- Requires SSD; fjall's LSM compaction handles this well

---

## 10. Dual-Anchor Engine

### 10.1 EVM Provider

Uses the SDK's `CliEthTimestamper` (or equivalent `TimestampProvider` implementation):

- Submits Merkle root as calldata to a witness smart contract
- Awaits transaction receipt (block confirmation)
- Extracts: `transaction_hash`, `block_timestamp`, `sender_account_address`
- Network: configurable (Sepolia for testing, Mainnet/L2 for production)

### 10.2 eIDAS Qualified TSA Provider

Uses the SDK's `TsaTimestamper` with an **eIDAS-qualified** endpoint:

- Submits RFC 3161 `TimeStampReq` containing SHA3-256 hash of Merkle root
- Receives signed `TimeStampToken` (PKCS#7/CMS structure)
- Extracts: `serial_number`, `gen_time` (authoritative timestamp), `tsa_name`
- Provider examples: D-Trust (Bundesdruckerei), SwissSign, DigiCert

**Legal significance:** eIDAS Article 41 grants qualified timestamps a presumption of accuracy and integrity across all EU member states. This provides legal standing that blockchain timestamps alone cannot offer.

### 10.3 Parallel Execution

```rust
let (evm_result, qtsa_result) = tokio::join!(
    evm_provider.create_timestamp(&merkle_root_hex),
    tsa_provider.create_timestamp(&merkle_root_hex),
);
```

**Failure handling:**
- If EVM fails but qTSA succeeds: mint only qTSA witness trees; retry EVM in background
- If qTSA fails but EVM succeeds: mint only EVM witness trees; retry qTSA in background
- If both fail: epoch marked `anchor_failed`; leaves rolled into next epoch
- Partial anchoring is acceptable (client gets whichever succeeded)

---

## 11. Client Integration Pattern

### 11.1 Aquafier-rs (aquafire.inblock.io)

The aquafier already has per-user `witness_method` and `witness_network` settings. Integration:

1. New witness method: `"aggregator"` alongside existing `"tsa"`, `"eth"`, `"nostr"`
2. Config fields: `aggregator_url`, `aggregator_preferred_method` (evm|qtsa|both)
3. On document operations that produce new revision hashes:
   - Buffer hashes locally (batch per user action or timer)
   - `POST /v1/leaves` to aggregator (submit tip hashes)
4. Background task polls `GET /v1/schedule` to learn when next epoch closes
5. After epoch anchors, `GET /trees/by-leaf/{hash}?method=evm` retrieves witness revisions
6. Merge the two revisions (TimestampObject + Signature) directly into the user's tree

### 11.2 Agent-Customer-Portal (agentic.inblock.io)

The portal produces T1-T8 artifacts with revision hashes stored in `turn_artifact_hash`. Integration:

1. On round seal (all turn artifacts collected):
   - Collect all revision hashes from the round
   - `POST /v1/leaves` with the batch
2. On session close:
   - Submit session-close seal hash
   - Poll for witness revisions after next epoch
3. Witness revision retrieval runs as background task (does not block session)
4. Retrieved revisions merged into respective artifact trees before disclosure bundle export
5. Portal's trust store includes aggregator DID for verification

### 11.3 Client SDK Module

A thin client library (`aqua-aggregator-client` crate):

```rust
pub struct AggregatorClient {
    http: reqwest::Client,
    base_url: String,
    session: Option<Session>,
    did: String,
    sign_fn: Box<dyn Fn(&str) -> Result<String, Error> + Send + Sync>,
}

/// Witness revision pair returned by the aggregator
pub struct WitnessRevisions {
    pub timestamp_object: (RevisionLink, Object),
    pub signature: (RevisionLink, Signature),
}

impl AggregatorClient {
    pub async fn new(base_url: &str, did: &str, sign_fn: impl ...) -> Self;
    pub async fn submit_leaves(&self, leaves: &[RevisionLink]) -> Result<SubmitResponse, Error>;
    pub async fn get_schedule(&self) -> Result<Schedule, Error>;
    pub async fn get_witness_revisions(
        &self,
        leaf: &RevisionLink,
        method: WitnessMethod,  // Evm | Qtsa
    ) -> Result<WitnessRevisions, Error>;
    pub async fn get_epoch_witnesses(
        &self,
        epoch: u64,
        method: WitnessMethod,
    ) -> Result<Vec<(RevisionLink, WitnessRevisions)>, Error>;
    pub async fn get_identity(&self) -> Result<Tree, Error>;
}
```

### 11.4 Integration as TimestampProvider

For seamless SDK integration, the aggregator client implements `TimestampProvider`:

```rust
#[async_trait]
impl TimestampProvider for AggregatorClient {
    async fn create_timestamp(&self, merkle_root: &str) -> Result<TimestampValue, TimestampError> {
        // 1. Submit leaf (the revision hash passed as merkle_root)
        // 2. Poll schedule until epoch closes
        // 3. Retrieve witness revisions
        // 4. Extract TimestampValue from TimestampObject payloads
        // Note: caller must separately merge revisions into their tree
    }
}
```

This allows `batch_timestamp_with_provider()` in the SDK to work transparently with the aggregator. However, the preferred production pattern is the explicit pull model via `get_witness_revisions()`, which gives the client full control over when to merge revisions and which anchor method to use.

---

## 12. Scalability Design

### 12.1 Throughput Targets

| Metric | Target |
|--------|--------|
| Leaves per epoch | 1,000,000 |
| Concurrent authenticated clients | 100 |
| Submission latency (p99) | < 50ms |
| Witness tree retrieval latency (p99) | < 20ms |
| Merkle tree build time (1M leaves) | < 2s |
| Witness revision minting (1M leaves) | < 30s (parallelized signing) |

### 12.2 Memory Model

- Accumulator buffer: 1M leaves x 32 bytes = 32 MB per epoch (trivial)
- Revision minting: streaming per-leaf, does not hold all revision pairs in memory simultaneously
- DashMap overhead: ~100 bytes per entry (hash + metadata)
- Total working memory at peak: < 300 MB

### 12.3 Concurrency

- Submission: lock-free append via `DashMap` (sharded concurrent HashMap)
- Epoch seal: atomic swap of accumulator reference (new epoch starts instantly, zero downtime)
- Merkle build: single-threaded (CPU-bound, ~2s for 1M leaves)
- Dual-anchor: parallel async I/O (EVM + qTSA concurrent)
- Revision minting: parallelized with rayon (CPU-bound Ed25519 signing, ~50K signs/sec/core)
- Revision retrieval: fjall read (LSM-tree, concurrent readers)

### 12.4 Availability

- Epoch timer is monotonic (does not drift with wall-clock adjustments)
- Partial anchor failure: mint revisions only for the method that succeeded (see Section 10.3)
- Server restart: reload state from fjall; current-epoch leaves in accumulator are lost (clients re-submit on 404)
- Mitigation: write-ahead log for accumulator (append leaf hashes to fjall immediately, reconstruct on restart)

---

## 13. Verification Compatibility

Witness revisions produced by the aggregator use the **same templates** (`EvmTimestampPayload`, `TsaTimestampPayload`) and **same revision types** (Object, Signature) as direct SDK timestamping. Once merged into the client's tree, the SDK's existing verification pipeline handles them without modification:

1. **L1 (Hash integrity):** `verify_revision_hash()` confirms each revision's content matches its declared hash
2. **L2 (Batch inclusion):** `verify_batch_inclusion()` validates the Merkle proof in the TimestampObject's payloads against the stated root
3. **Signature verification:** Standard Ed25519 signature check on the Signature revision
4. **Trust store:** Confirms the aggregator's signer DID (`did:pkh:ed25519:0x...`) is in the verifier's trusted set
5. **Template ancestry:** Confirms the timestamp template (`EvmTimestampPayload::TEMPLATE_LINK` or `TsaTimestampPayload::TEMPLATE_LINK`) is a recognized built-in

**No changes to the verification engine are required.**

The witness revisions appear in the client's tree as a standard timestamp branch (Object + Signature forking from a content revision). This is the same topology the SDK already produces when timestamping directly via `Aquafier::timestamp()`. The only difference is the signer: the aggregator's DID instead of the client's own.

---

## 14. Deployment

### 14.1 Configuration

```toml
[server]
listen = "0.0.0.0:8080"
epoch_duration_secs = 600
store_path = "/var/lib/aqua-aggregator"
retention_days = 90

[identity]
key_path = "/etc/aqua-aggregator/ed25519.key"    # Aggregator's signing key
service_url = "https://aggregator.aqua-protocol.org"
operator = "inblock.io"

[auth]
domain = "aggregator.aqua-protocol.org"
uri = "https://aggregator.aqua-protocol.org"
session_ttl_secs = 86400
allowed_dids = [
  "did:pkh:ed25519:0x<aquafier_pubkey>",
  "did:pkh:ed25519:0x<portal_pubkey>",
]

[anchor.evm]
network = "sepolia"
contract_address = "0x..."
private_key_env = "AGGREGATOR_EVM_KEY"

[anchor.qtsa]
url = "https://tsa.d-trust.net/qualified"
# No auth needed for RFC 3161 (hash-only submission)
# Some providers require mTLS client cert:
# client_cert = "/etc/aqua-aggregator/qtsa-client.pem"
# client_key = "/etc/aqua-aggregator/qtsa-client-key.pem"
```

### 14.2 Binary

Single static binary (`aqua-aggregator`), no runtime dependencies beyond network access.

```
aqua-aggregator --config /etc/aqua-aggregator/config.toml
aqua-aggregator init-identity --output /etc/aqua-aggregator/ed25519.key
```

### 14.3 Observability

- Structured tracing (same pattern as aqua-node)
- Prometheus metrics endpoint (`/metrics`):
  - `aggregator_epoch_total` (counter)
  - `aggregator_leaves_per_epoch` (histogram)
  - `aggregator_anchor_latency_seconds{method="evm|qtsa"}` (histogram)
  - `aggregator_anchor_failures_total{method="evm|qtsa"}` (counter)
  - `aggregator_witness_revisions_minted_total` (counter)
- Health endpoint (`/health`) for load balancer probes

---

## 15. Security Considerations

| Concern | Mitigation |
|---------|-----------|
| Unauthorized submission | DID allowlist + CAIP-122 session auth |
| Cross-client data leakage | DID-scoped access: clients only see witness revisions for their own leaves |
| Replay attacks | Single-use challenge nonces; session tokens are random 256-bit |
| Leaf flooding (DoS) | Per-DID rate limit (configurable leaves/epoch) |
| Merkle root manipulation | Deterministic leaf ordering (lexicographic sort); proofs verifiable client-side |
| Aggregator key compromise | Rotate key, publish new service_claim; old witness revisions remain valid (signatures were correct at time of minting) |
| Witness revision forgery | Clients verify Ed25519 signature against trusted DID; forged revisions fail verification |
| qTSA unavailability | EVM anchor still proceeds; partial results are acceptable |

---

## 16. Compatibility Matrix

| Component | Changes Required |
|-----------|-----------------|
| `aqua-rs-sdk` | None (Merkle primitives, TimestampProvider, Tree/Object/Signature types all exist) |
| `aqua-rs-auth` | None (used as-is for CAIP-122 auth) |
| `aquafier-rs` | Add `"aggregator"` witness method + `aggregator_url` config + merge witness revisions into tree on retrieval |
| `agent-customer-portal` | Add background task: submit turn hashes, poll/retrieve witness revisions, merge into artifact trees before disclosure export |
| `aqua-node` | None (aggregator is a separate service, not embedded) |
| Verification (any client) | None (witness revisions use standard templates + signature types; existing pipeline handles natively) |

---

## 17. Open Questions

1. **Leaf ordering:** Lexicographic sort guarantees determinism. Alternative: insertion order (requires consensus if multi-node). Recommendation: lexicographic (simpler, verifiable).

2. **Multi-instance:** Single-writer for V1. Horizontal scaling requires epoch leader election or sharded accumulation with merge. Defer to V2.

3. **Payment/metering:** Currently allowlist-only. Future: per-leaf pricing, prepaid credit balance, Stripe integration. Out of scope for V1.

4. **Nested Merkle trees:** Clients may submit their own batch roots (e.g., portal seals a round into one hash, then submits that hash). The aggregator treats all leaves uniformly; nested verification is the client's responsibility.

5. **Epoch duration tuning:** 10 minutes balances latency vs. cost. Shorter epochs (1 min) for time-sensitive use cases could be a premium tier.

6. **Witness revision caching:** Once merged into the client's tree, witness revisions are part of the tree and persist with it. The aggregator is only needed for initial retrieval. Clients should merge promptly and not rely on the aggregator for long-term storage.

7. **qTSA provider selection:** D-Trust (Bundesdruckerei) is the natural choice for a German company. Alternative: SwissSign (Swiss jurisdiction). Decision needed based on pricing and API availability.

---

## 18. Non-Goals (V1)

- Push notifications / webhooks to clients
- Multi-region / multi-instance clustering
- Client self-registration (admin provisions DIDs)
- Storing client tree content (aggregator only handles leaf hashes and produces witness revisions)
- Serving as a general-purpose aqua-node (no file storage, no cloud sync, no forest)
- Cross-chain anchoring beyond the configured EVM network (single chain + qTSA)
- Long-term witness revision archival (clients merge revisions into their trees; aggregator retains for retrieval window only)
