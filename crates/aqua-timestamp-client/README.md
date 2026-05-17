# aqua-timestamp-client

Async Rust client for the [Aqua Timestamp Aggregator](https://timestamp.inblock.io).

Submit 32-byte hashes for batched timestamping; receive server-signed witness pairs (timestamp object + EIP-191 signature) once the epoch is sealed. The witness pair splices directly into your existing aqua-tree using `aqua-rs-sdk` primitives.

## When to use this versus SDK-direct timestamping

The Aqua ecosystem has two timestamping tiers:

| Path | Latency per hash | Cost per hash | Evidence layers |
|---|---|---|---|
| `aqua-rs-sdk` direct (`TimestampProvider`) | seconds | one anchor transaction | 1 |
| **aqua-timestamp aggregator** (this crate) | up to one epoch (~10 min) | one transaction per epoch, amortized | 4 (server signature + Merkle inclusion proof + EVM tx + qTSA token, all bound to one epoch root) |

These are different service tiers, not interchangeable implementations. This crate **deliberately does not implement** `aqua_rs_sdk::core::timestamp::TimestampProvider`: that trait expects synchronous, per-hash semantics and would smuggle a multi-minute block into every SDK call site. Use this crate for non-real-time workloads where one-epoch latency is acceptable in exchange for cheap bulk anchoring.

Closest prior art: Certificate Transparency log clients (RFC 6962 / 9162). The server uses RFC 9162 for its Merkle tree, and the submit-then-poll-then-fetch shape is identical.

## Quick start

```rust
use std::time::Duration;
use aqua_timestamp_client::{AnchorMethod, OnRotation, TimestampClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = TimestampClient::builder()
        .base_url("https://timestamp.inblock.io")
        .my_did("did:pkh:eip155:1:0x...")
        .signer(|message: &str| {
            // Sign `message` with your CAIP-122 key, return hex.
            Ok("0xdeadbeef".to_string())
        })
        .build()
        .await?;

    let leaf = [0xab; 32];
    let receipt = client.submit(&leaf).await?;
    let witness = client
        .await_witness(&receipt, AnchorMethod::Evm, Duration::from_secs(900))
        .await?;

    // Attach witness.object_revision and witness.signature_revision
    // to your own AquaTree using `aqua_rs_sdk` primitives.
    Ok(())
}
```

## Trust model

On `build()`, the client fetches `/.well-known/aqua-identity` over HTTPS, verifies the embedded `service_claim_server` Aqua-tree, and pins the server DID for the client's lifetime. Every witness signature is checked against the pinned DID.

For cross-session rotation detection (SSH `known_hosts` style), persist the discovered DID from `client.server_identity().did` and pass it back next time via `.expect_server_did(prior, OnRotation::Refuse)` (strict) or `.expect_server_did(prior, OnRotation::Warn)` (logged, proceeds with new DID).

A small file-backed helper (`KnownServersFile`) is available behind the optional `known-servers-file` feature for callers who do not have their own persistence layer.

## Features

- `known-servers-file` — enables `KnownServersFile`, an `~/.ssh/known_hosts` analogue for the discovered DID.

## See also

- `docs/spec-client.md` in this workspace for the full design specification.
- The server lives in `crates/aqua-timestamp/`. Wire compatibility is maintained at the workspace level.
