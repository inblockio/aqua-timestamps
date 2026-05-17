# Runbook: verifying `aqua-timestamp-client` against the live deployment

How to run the client crate's live tests and the 1000-hash stress example
against the deployed `timestamp.inblock.io` aggregator. Both are gated
behind the `live-tests` Cargo feature and stay out of the default test
suite so CI remains offline-only.

## Prerequisites

- Network egress to `https://timestamp.inblock.io` (or whichever
  `TIMESTAMP_BASE_URL` you point the tests at).
- Server running and reachable; check first:
  ```bash
  curl -sS https://timestamp.inblock.io/health
  curl -sS https://timestamp.inblock.io/v1/schedule
  ```
- An ephemeral secp256k1 key is generated inside each run. **No
  preconfigured DID is needed:** the deployed allowlist is empty, which
  the server treats as "accept any authenticated DID" (see
  `crates/aqua-timestamp/src/state.rs::is_allowed`).

## 1. Single-leaf roundtrip (`live_roundtrip`)

Submits one random 32-byte hash, waits for the current epoch to seal,
fetches the EVM witness, then the qTSA witness. Verifies both signatures
recover to the pinned server DID.

```bash
cargo test -p aqua-timestamp-client \
    --features live-tests --test live_roundtrip \
    -- --nocapture
```

Environment overrides:

| Variable | Default | Purpose |
|---|---|---|
| `TIMESTAMP_BASE_URL` | `https://timestamp.inblock.io` | Target server. |
| `LIVE_TIMEOUT_SECS` | `900` (15 min) | Max wall-clock to wait for the witness. Generous so an unlucky submission right before epoch close still passes. |

Expected behaviour:

- Build phase: well-known fetch + identity verification + CAIP-122
  handshake. A few seconds. Prints discovered server DID.
- Submit: ~200 ms. Prints `epoch_id` and `epoch_closes_at`.
- Await EVM witness: up to one epoch (~10 min) of polling at the
  configured `poll_interval` (10 s in this test).
- Await qTSA witness: nearly immediate after EVM (both are produced in
  the same seal pass).
- Total wall-clock: typically 4-11 min depending on where in the epoch
  the submission lands.

Failure modes worth knowing:

- `ClientError::Auth(...)`: signer is broken or DID format is wrong.
- `ClientError::ServerIdentityRotated`: only if `expect_server_did` was
  set; this test does not set it, so the failure shape is bootstrap-only.
- `ClientError::SignatureMismatch`: the server returned a witness that
  does not recover to the pinned DID. Treat as a security event; do not
  retry.
- `ClientError::Timeout`: the epoch did not seal within
  `LIVE_TIMEOUT_SECS`. Either the deployment has a stuck sealer or the
  timeout is too tight for the configured epoch duration.

## 2. 1000-leaf stress example (`stress_1000`)

Submits 1000 random hashes in a single `submit_many` call, **aligned to
the start of a fresh epoch**, then fetches all 1000 witnesses in parallel
once the epoch seals.

```bash
cargo run -p aqua-timestamp-client \
    --features live-tests --example stress_1000 \
    --release
```

Use `--release` if you care about local-side throughput; the bottleneck
is almost always the server side anyway, so `--debug` works fine for
correctness checks.

Environment overrides:

| Variable | Default | Purpose |
|---|---|---|
| `TIMESTAMP_BASE_URL` | `https://timestamp.inblock.io` | Target server. |
| `STRESS_COUNT` | `1000` | Number of leaves to submit. Bound by the server's `max_leaves_per_request` (10000 by default). |
| `STRESS_METHOD` | `evm` | Anchor method to fetch (`evm` or `qtsa`). Both witnesses are produced regardless; this only controls which one we retrieve. |
| `STRESS_PARALLEL` | `32` | Max concurrent witness fetches. |
| `STRESS_EPOCH_ALIGN_BUFFER_SECS` | `2` | Padding added after `epoch_closes_at` before submitting, to be sure we have landed in the new epoch and are not racing the sealer. |

### What "epoch-aligned" means here

After `build()`, the example:

1. Calls `/v1/schedule` to learn `current_epoch_closes_at`.
2. Sleeps until `current_epoch_closes_at + STRESS_EPOCH_ALIGN_BUFFER_SECS`.
3. Re-fetches the schedule to confirm we are now in the new epoch.
4. Submits all 1000 leaves in one POST.
5. Records `receipt.epoch_id` (now the new epoch's ID).
6. Polls `/v1/schedule` until `last_sealed_epoch_id >= target_epoch`.
7. Fetches all 1000 witnesses concurrently.

Why align: starting mid-epoch with only a few seconds left can split a
batch across the seal boundary or race the sealer; this guarantees one
clean test interval per run.

### Expected output

The example prints a per-run header (DID, count, parallelism, buffer),
the epoch alignment wait, submission timings, seal wait, fetch timings,
and a final summary:

```
== summary ==
submitted     : 1000
witness ok    : 1000
witness fail  : 0
submit time   : 0.45s (2222 hashes/s)
seal wait     : 593.2s
fetch time    : 8.2s  (122 witnesses/s, parallel=32)
OK
```

Exit code is 0 on full success, non-zero if any submission or witness
verification fails. The first five failures (if any) are printed.

Total wall-clock is approximately `EPOCH_DURATION + 30s`. With the
default 600 s epoch, expect ~10-11 minutes per run.

### Useful invocations

A fast smoke test against a local dev server (not the production
deployment):

```bash
TIMESTAMP_BASE_URL=http://localhost:7777 \
STRESS_COUNT=50 \
cargo run -p aqua-timestamp-client --features live-tests --example stress_1000
```

Both anchor methods, against production:

```bash
STRESS_METHOD=evm  cargo run -p aqua-timestamp-client --features live-tests --example stress_1000 --release
STRESS_METHOD=qtsa cargo run -p aqua-timestamp-client --features live-tests --example stress_1000 --release
```

## Operational notes

- **Cost.** Submissions are batched on the server side, so a 1000-leaf
  run contributes one Sepolia transaction's worth of gas plus one qTSA
  request to the next epoch the server seals, regardless of count.
  Effective per-leaf cost is essentially zero.
- **Allowlist.** Currently empty (`deploy/config.toml`); the server
  accepts any authenticated DID. If that ever changes, populate
  `[auth].allowed_dids` on the server and have the test's ephemeral DID
  added there before running.
- **Server identity rotation.** Neither test pins a prior server DID, so
  both flows accept whatever the server advertises. A real consumer
  should persist the discovered DID and pass it back via
  `expect_server_did` on subsequent connects. See `docs/spec-client.md`
  §5 for the full trust model.
- **Cleanup.** Neither flow writes anywhere on the server beyond the
  normal epoch storage; submissions are append-only and indexed by DID,
  so subsequent runs do not collide.
