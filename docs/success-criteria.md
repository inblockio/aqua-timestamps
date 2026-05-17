# Aqua Aggregator: Success Criteria

**Version:** 0.2.0-draft
**Date:** 2026-05-17
**Status:** Draft for owner review

This document defines what "done" means for the aqua-timestamp project at
each milestone. The [design spec](design-spec.md) describes the target
system; this document defines the bar each milestone must clear before
being declared complete.

A criterion is met only when it is **verifiable**: a command someone can
run, a URL someone can curl, a test that passes in CI. Aspirational
language ("should be performant", "should be secure") does not belong
here.

## Hard requirements (apply to every milestone)

These are non-negotiable architectural constraints set by the owner.
A milestone that meets every checkbox in its own section but violates one
of these is **not** done.

- **Single secp256k1 service key.** The aggregator's identity DID, EIP-191
  witness signatures, and Sepolia anchor transactions all use the same
  secp256k1 keypair (BIP39 mnemonic, derivation path `m/44'/60'/0'/0/0`).
  Generated and stored before M0 ships; see "Wallet provisioning" below.
- **Use the SDK, do not reimplement.** The implementation consumes
  [`aqua-rs-sdk`](https://github.com/inblockio/aqua-rs-sdk) for Merkle
  primitives, `Object` / `Signature` / template types, `Tree` shape, and
  `TimestampProvider` traits. It consumes
  [`aqua-rs-auth`](https://github.com/inblockio/aqua-rs-auth) for SIWE /
  CAIP-122 challenge-response. Where the SDK and the design-spec.md
  disagree, **the SDK is authoritative**.
- **Aqua REST API contract.** Tree-retrieval endpoints
  (`GET /trees/{tip}`, `GET /trees/by-leaf/{leaf}?method=...`,
  `GET /trees?epoch=...&method=...`) match the
  [`aqua-node`](https://github.com/inblockio/aqua-node) REST API byte for
  byte. A response is correct only if an aqua-node client accepts it
  without modification.
- **Identity endpoint mirrors aquafire.** `GET /.well-known/aqua-identity`
  returns a JSON document with the same top-level shape as
  `https://aquafire.inblock.io/.well-known/aqua-identity` (fields
  `protocol`, `version`, `server_did`, `ethereum_address`, `trust_level`,
  `trust_domain`, `supported_claims`, `auth_method: "siwe"`, `endpoints`,
  `identity_claim`), with `identity_claim` being a valid Aqua tree whose
  signature revision uses `signature_type: "ethereum:eip-191"`.
- **Authenticated, key-based API access only.** Every non-public endpoint
  rejects unauthenticated calls with 401, and the e2e test path proves
  it: the local client signs a SIWE challenge with its own key, presents
  the resulting Bearer token, and only then can submit or retrieve. No
  shared secret, no static API key.

## Canonical dependencies (owner-designated)

These six inblockio repos are the canonical sources of truth. Clone all
six into `~/projects/` so workspace paths (`../aqua-rs-sdk`) resolve, and
treat their code as the contract.

| Repo | Role |
|---|---|
| [`aqua-spec`](https://github.com/inblockio/aqua-spec) | Protocol spec + governance |
| [`aqua-rs-sdk`](https://github.com/inblockio/aqua-rs-sdk) | **Authoritative** reference implementation (Rust). Where this conflicts with `aqua-spec`, the SDK wins. |
| [`aqua-rs-cli`](https://github.com/inblockio/aqua-rs-cli) | CLI wrapping the SDK. Used by the e2e test client. |
| [`aqua-state-viewer`](https://github.com/inblockio/aqua-state-viewer) | Human-readable Aqua-tree visualizer (useful for debugging witness trees end-to-end). |
| [`aqua-rs-auth`](https://github.com/inblockio/aqua-rs-auth) | CAIP-122 / SIWE challenge-response. |
| [`aqua-node`](https://github.com/inblockio/aqua-node) | REST API contract that our `/trees/*` endpoints must match. |

**Access blocker (2026-05-17):** these repos are not visible to this
machine's `gh` client. `GH_TOKEN` is missing from the gnome-keyring under
`service=github user=clawi`. Owner action needed: either `gh auth login`
interactively, or `secret-tool store --label='clawi github PAT' service
github user clawi` with a PAT that has `repo:read` scope.

## Wallet provisioning (precondition for M4 onward)

Done once, at project start. Status flagged here:

- [x] **Service / anchor key generated.** Single secp256k1 wallet,
      BIP39 mnemonic stored in gnome-keyring under
      `service=aqua-timestamp-evm-anchor user=clawi kind=mnemonic`.
      Derivation `m/44'/60'/0'/0/0` (ethers default). Address roundtrip
      verified from keyring.
- [x] **Address surfaced for funding.** See operator handoff for the
      address (intentionally not duplicated in this doc to keep it
      grep-clean and avoid stale-copy drift if the key is ever rotated).
- [ ] **Sepolia funded.** Owner sends test ETH; `eth_getBalance` against
      the Sepolia RPC returns >= 0.05 ETH (enough for many anchor txs
      at testnet gas prices).
- [ ] **Rotation runbook documented.** A markdown procedure in
      `docs/runbooks/rotate-anchor-key.md` covering: revoke old key from
      keyring, generate new, fund new, publish new service_claim,
      decommission.

## Milestone ladder

The project is divided into milestones so progress is visible and each
deploy is meaningful on its own. Earlier milestones do not block later
ones from being scoped, but they do block them from being shipped.

| ID | Title | Outcome | State |
|---|---|---|---|
| **M0** | Skeleton on the wire | `https://timestamp.inblock.io/health` returns 200 with valid TLS, served by a Rust binary running in Docker on the agentic-hub host. Landing page at `/` describes the service and links to the identity endpoint. No business logic yet. | **shipped** 2026-05-17 |
| **M1** | Identity and SIWE auth | Service loads its secp256k1 key, serves a signed `service_claim` at `/.well-known/aqua-identity` that mirrors the aquafire shape exactly, accepts SIWE sessions via `aqua-rs-auth`, and rejects unauthenticated submission with 401. Verified for all three CAIP-122 DID methods (`eip155`, `ed25519`, `p256`). | **shipped** 2026-05-17 |
| **M2** | Accumulate and seal | Allowlisted clients submit leaves via `POST /v1/leaves`, the epoch timer fires, an RFC 9162 Merkle root is built deterministically (via `aqua-rs-sdk` primitives), and an `EpochRecord` is persisted to fjall. Anchor providers are stubbed at this milestone. | **shipped** 2026-05-17 |
| **M3** | Witness revisions retrievable | After seal, witness revisions (TimestampObject + EIP-191 Signature) are minted per leaf for each anchor method, persisted, and retrievable via the aqua-node-compatible `GET /trees/{tip}` and the aqua-timestamp-specific `GET /trees/by-leaf/{hash}?method=` and `GET /trees?epoch=&method=` endpoints, with DID-scoped access enforced. | **shipped** 2026-05-17 |
| **M-E2E** | **Live e2e round trip** | A local client built on `aqua-rs-sdk` runs against the *deployed* `https://timestamp.inblock.io`: signs a SIWE challenge with its own key, submits a leaf, waits for the epoch to seal, retrieves the witness revisions for both anchor methods, and verifies signature + Merkle proof on each, all without a single hand-edit. | **shipped** 2026-05-17 |
| **M4** | Real EVM anchor | The EVM stub is replaced with a real `TimestampProvider` submitting to Sepolia, signed by the service wallet. End-to-end: a submitted hash gets a witness revision containing a real on-chain `transaction_hash` that resolves on a Sepolia block explorer. | **shipped** 2026-05-17 |
| **M5** | Real qTSA anchor | The qTSA stub is replaced with a real RFC 3161 client against an eIDAS-qualified provider (`http://timestamp.sectigo.com/qualified`). End-to-end as M4 but for qTSA witness revisions. | **shipped** 2026-05-17 |
| **M6** | Production hardening | Metrics endpoint, structured tracing tightening, rate limits per DID, fjall retention pruning, write-ahead log for accumulator, restart durability proven by chaos test. | pending |

Per-milestone runbooks (with live transcripts) live in
`docs/runbooks/`:

- M0 deploy: [`m0-deploy-transcript-2026-05-17.md`](runbooks/m0-deploy-transcript-2026-05-17.md)
- M-E2E first live run: [`e2e-live-transcript-2026-05-17.md`](runbooks/e2e-live-transcript-2026-05-17.md)
- Multi-DID e2e + second Sepolia anchor: [`multi-method-e2e-and-anchor-2026-05-17.md`](runbooks/multi-method-e2e-and-anchor-2026-05-17.md)
- M5 qTSA anchor: [`m5-qtsa-anchor-2026-05-17.md`](runbooks/m5-qtsa-anchor-2026-05-17.md)
- Full overnight build: [`session-2026-05-17-overnight-build.md`](runbooks/session-2026-05-17-overnight-build.md)

The owner picks the bar for the current session. Default next session
target: **M6** (production hardening) unless redirected. The crab will
not silently expand scope.

## M0: Skeleton on the wire

**Definition of done:** the public internet can reach a Rust binary,
running in Docker on the **agentic-hub** host (`139.59.144.60`, which
also serves `agentic.inblock.io`), behind the existing **Caddy**
reverse-proxy container (`portal-caddy-1`, running `caddy:2-alpine`),
serving its health endpoint at `https://timestamp.inblock.io/health`
with a valid Let's Encrypt cert auto-provisioned by Caddy.

The current Caddyfile lives at `/home/portal/portal/Caddyfile` on the
host (bind-mounted into the container) and contains exactly one site
block today. M0 ships when an appended block for `timestamp.inblock.io`
is reverse-proxying to our container on the shared `portal-net` Docker
network.

### Functional

- [ ] Cargo workspace builds with `cargo build --release` on a clean clone.
- [ ] `cargo clippy --release -- -D warnings` is clean.
- [ ] `cargo fmt --check` is clean.
- [ ] `cargo test` passes (at minimum: one smoke test that starts the
      server in-process and hits `/health`).
- [ ] Binary serves `GET /health` → `200 OK` with JSON body
      `{"status":"ok","current_epoch":<int>,"uptime_secs":<int>,...}`.
- [ ] Binary serves `GET /` → `200 OK` with a minimal HTML landing page
      that states what the service is, names the operator (`inblock.io`),
      and links to `/.well-known/aqua-identity` and `/health`. No JS, no
      external assets — single self-contained HTML response.
- [ ] Binary respects `--config <path>` and loads `config.toml`.
- [ ] Binary respects `RUST_LOG` and emits structured tracing.
- [ ] `Cargo.toml` already lists `aqua-rs-sdk` and `aqua-rs-auth` as
      dependencies (even if unused at M0), proving the workspace can
      resolve them. Compilation of the M0 binary succeeds with both in
      the dep graph.

### Deployment

- [ ] `Dockerfile` is multi-stage; final image is `<100 MB` and runs as
      a non-root user.
- [ ] Image builds reproducibly with `docker buildx build .` from the
      repo root.
- [ ] Image published to `ghcr.io/inblockio/aqua-timestamp:<tag>`
      (`:dev` for the M0 ship; semantic tags later).
- [ ] `docker-compose.yml` under `deploy/` declares the service with a
      healthcheck, a named volume for fjall state, and attaches to the
      external `portal-net` network so the existing Caddy container can
      reach it by service name (`timestamp:8080`).
- [ ] A site block for `timestamp.inblock.io` is appended to
      `/home/portal/portal/Caddyfile` (or moved to an `import`-ed file
      under `/home/portal/portal/sites/` if the operator prefers
      per-service files), reverse-proxying to `timestamp:8080`.
- [ ] `docker exec portal-caddy-1 caddy reload --config /etc/caddy/Caddyfile`
      succeeds without warnings.
- [x] DNS: `timestamp.inblock.io` resolves to `139.59.144.60`. ✓ verified
- [ ] After `docker compose up -d` + Caddy reload, an off-box
      `curl https://timestamp.inblock.io/health` returns 200 with a
      valid Let's Encrypt chain.
- [ ] Container restart (`docker compose restart`) brings the service
      back without manual intervention; Caddy keeps routing without
      reload.

### Repo hygiene

- [ ] `README.md` documents how to build, run locally (`cargo run`),
      run in Docker (`docker compose up`), and deploy.
- [ ] `LICENSE` file matches the AGPL-3.0 stated in the existing README.
- [ ] `.gitignore` excludes `target/`, `.env`, fjall data dirs.
- [ ] `CLAUDE.md` (project-scoped) documents the deployment workflow,
      the GHCR push pattern, and any non-obvious gotchas.

## M1: Identity and SIWE auth

**Adds to M0.** The aggregator has its cryptographic identity (the
pre-provisioned wallet from "Wallet provisioning" above), serves it in
the same shape as aquafire, and rejects unauthenticated submission.

### Functional

- [x] On startup, the binary loads the service mnemonic from
      `AQUA_TIMESTAMP_ANCHOR_MNEMONIC` env var (sourced from the
      operator's `.env`), derives the secp256k1 key at
      `m/44'/60'/0'/0/0`, and computes the Ethereum address.
- [x] Service DID is computed as `did:pkh:eip155:<chain_id>:<address>`
      using the configured chain (Sepolia: `11155111`; mainnet for the
      identity claim payload: `1` — match aquafire's pattern).
- [x] `GET /.well-known/aqua-identity` returns a JSON document with the
      same top-level keys as the aquafire reference (`protocol`,
      `version`, `server_did`, `ethereum_address`, `trust_level`,
      `trust_domain`, `supported_claims`, `auth_method: "siwe"`,
      `endpoints`, `identity_claim`).
- [x] `identity_claim` is a valid Aqua tree (anchor → object → signature)
      built via `aqua-rs-sdk` types, signed with EIP-191 via the service
      key. Tree verifies cleanly when passed through the SDK's verifier.
- [x] `GET /auth/challenge?did=<did>` returns a SIWE challenge message
      with a single-use nonce (5-minute TTL). Implementation is
      `aqua-rs-auth`, not handrolled.
- [x] `POST /auth/session` with a valid EIP-191-signed challenge returns
      a Bearer token (1-hour TTL by default; configurable, the success
      criterion's 24h figure was a sketch; M1 uses the `aqua-auth`
      default of 3600s which is what production should keep).
- [x] `POST /v1/leaves` without a valid Bearer token returns 401.
- [x] DID allowlist enforced: a valid token from a non-allowlisted DID
      returns 403 on `POST /v1/leaves`.
- [x] Expired challenges and sessions are purged by a background task
      (`SessionStore::start_cleanup` spawned at startup, runs every 60s).

### Tests

- [x] Unit: mnemonic → address derivation matches a known-vector
      (golden test with a fixed test mnemonic, never the production one).
      See `crates/aqua-timestamp/tests/identity.rs::mnemonic_to_address_matches_known_vector`.
- [x] Unit: SIWE challenge construction and EIP-191 signature
      verification round-trip via `aqua-rs-auth`. See
      `crates/aqua-timestamp/tests/auth_flow.rs::caip122_round_trip_via_aqua_auth`.
- [x] Integration: full auth dance against a running server in-process.
      See `crates/aqua-timestamp/tests/auth_flow.rs::full_auth_dance`.
- [x] Snapshot test: `/.well-known/aqua-identity` response, with
      timestamps and nonces normalized, matches the expected shape
      (`crates/aqua-timestamp/tests/fixtures/identity_golden.json`).

## M2: Accumulate and seal

**Adds to M1.** Leaves submitted by allowlisted clients are accumulated,
the epoch timer fires, and a deterministic Merkle root is produced and
persisted.

### Functional

- [ ] `POST /v1/leaves` accepts up to 10_000 hashes per request, each
      `0x` + 64 hex chars, returns 202 with epoch_id and
      `epoch_closes_at`.
- [ ] Duplicates within an epoch are deduplicated (first-submitter wins).
- [ ] Submissions after seal land in the next epoch.
- [ ] Epoch timer fires every `epoch_duration_secs` (default 600), swaps
      the accumulator atomically, and produces an `EpochRecord` with the
      Merkle root.
- [ ] Merkle build is deterministic: leaves are sorted lexicographically
      before hashing, per RFC 9162.
- [ ] `EpochRecord` is persisted to the `epochs` fjall partition.
- [ ] `GET /v1/schedule` returns current epoch, close time, last anchored
      epoch.
- [ ] `GET /v1/epochs?from=N&limit=M` returns paginated epoch history.

### Tests

- [ ] Property test: Merkle root is independent of submission order.
- [ ] Unit: inclusion proofs verify back to the root.
- [ ] Integration: submit batch → wait for seal → assert
      `EpochRecord` in storage with expected root.

## M3: Witness revisions

**Adds to M2.** Per-leaf witness revisions are minted, signed, persisted,
and retrievable with the documented access control.

### Functional

- [ ] On epoch seal, for each anchor method (initially stub-evm and
      stub-qtsa), the minter produces a (TimestampObject, Signature) pair
      per leaf, chained as `previous_revision = client_leaf` →
      `previous_revision = ts_obj_hash`.
- [ ] Signature uses the aggregator's Ed25519 key and verifies against
      the published DID.
- [ ] Both revisions are persisted to the `witness_revisions` partition;
      `leaf_to_tips` and `leaf_owner` indexes are populated.
- [ ] `GET /trees/{tip_hex}` returns the revision pair in aqua-node
      format (`{"revisions": {...}, "file_index": {}}`).
- [ ] `GET /trees/by-leaf/{leaf}?method=evm|qtsa` returns the same pair
      keyed by submitted leaf.
- [ ] `GET /trees?epoch=N&method=evm|qtsa` returns the list of witnesses
      for the calling DID.
- [ ] **Isolation invariant:** a DID receives 403 when requesting
      witnesses for a leaf it did not submit.

### Tests

- [ ] Round trip: submit leaf → seal → fetch witness → verify signature
      and Merkle proof.
- [ ] Negative: DID A submits leaf, DID B receives 403 on retrieval.
- [ ] Restart durability: kill container after seal, restart, witnesses
      still retrievable.

## M-E2E: Live end-to-end witness round trip

**Adds to M3.** Proves the deployed service works end-to-end against a
real client running on a different machine, with no manual data shuttling
and no test-only shortcuts. The first milestone where the whole pipeline
is exercised over the wire as a real user would experience it.

### Definition of the test

A script `tests/e2e/live_roundtrip.sh` (or `tests/e2e/live_roundtrip.rs`
if a binary is cleaner) does the following, against `https://timestamp.inblock.io`:

1. Loads a test client key (a second secp256k1 keypair, generated and
   stored in the keyring under
   `service=aqua-timestamp-test-client user=clawi kind=mnemonic`).
2. `GET /.well-known/aqua-identity` and asserts the response shape
   matches the aquafire reference shape.
3. `GET /auth/challenge?did=did:pkh:eip155:1:0x<client_addr>` to get a
   SIWE challenge.
4. Signs the challenge with the client key (EIP-191), `POST /auth/session`
   to receive a Bearer token.
5. Constructs a random 32-byte leaf hash (SHA3-256 of random bytes),
   `POST /v1/leaves` with the token. Asserts 202 and captures
   `epoch_id` + `epoch_closes_at`.
6. Polls `GET /v1/schedule` until `last_anchored_epoch >= epoch_id`,
   then waits one extra second for write completion. Polling cap: 2x
   the configured epoch duration; failure beyond that is a test failure.
7. `GET /trees/by-leaf/{leaf}?method=evm` with the same token, retrieves
   the (TimestampObject, Signature) revision pair.
8. Verifies the pair using `aqua-rs-sdk`:
   - L1: each revision's content hashes to its declared hash.
   - L2: the inclusion proof in the TimestampObject's payloads validates
     back to the stated `merkle_root`.
   - L3: the Signature's EIP-191 sig validates against
     `did:pkh:eip155:1:<aggregator_addr>`, and that DID matches the
     `server_did` from step 2.
9. Negative tests:
   - Same `GET` with a *different* client DID's token returns 403
     (isolation invariant).
   - `POST /v1/leaves` without a Bearer token returns 401.

### Done criteria

- [ ] The script above runs to completion (`exit 0`) against the
      live `https://timestamp.inblock.io`, with no manual steps.
- [ ] The client key was generated and stored before the run; the test
      reads it from the keyring (no key in the script).
- [ ] The test is added to the project's CI as a manual workflow
      (workflow_dispatch), with the keyring access mocked out via a
      `TEST_CLIENT_MNEMONIC` secret in repo settings. The local run is
      the canonical proof-of-life; CI is the regression net.
- [ ] A short transcript of a successful live run is captured in
      `docs/runbooks/e2e-live-transcript-<date>.md` so the bar is
      visible.

## M4 / M5: Real anchor providers

**Definition deferred to a separate sub-spec** authored when sister-repo
access (`aqua-rs-sdk`, especially its `TimestampProvider` /
`TsaTimestamper` traits) is sorted out. The same shape applies: the stub
provider is swapped for a real implementation, end-to-end verification of
a submitted hash through to an on-chain or RFC 3161 timestamp.

Open questions to answer before M4/M5 are tracked in
[design-spec.md §17](design-spec.md#17-open-questions).

## M6: Production hardening

Tracked separately once the system is end-to-end on testnet.

## Cross-cutting standards (apply at every milestone)

These are not a milestone; they are the baseline every deploy must meet.

### Build and CI

- `cargo clippy --release -- -D warnings` clean.
- `cargo fmt --check` clean.
- `cargo test` green.
- GitHub Actions workflow runs lint, format, test, and Docker build on
  every push to a PR branch; image push on tag.

### Security

- No secrets in the repo, the image, or the Compose file. Everything
  sensitive comes from env vars sourced from a `.env` on the server that
  is `chmod 600` and outside any Compose source tree.
- The identity key is mounted from a host path or a Docker secret, never
  baked into the image.
- The image runs as a non-root user.
- HTTPS-only externally; nginx-proxy handles TLS termination.

### Observability

- All structured logs go to stdout in JSON when `LOG_FORMAT=json`, plain
  text otherwise. Default: plain.
- Health endpoint reflects subsystem status (current_epoch, last anchor
  status per method) honestly.

### Deployment safety

- `docker compose up -d` is idempotent and never destroys volume data.
- Rollback is `docker compose pull && docker compose up -d` against an
  older image tag; the new image must read state written by the
  immediately previous version without migration.
- A failed deploy must leave the previous version running. (Achieved by
  pulling the new image first, then doing the up; never down-then-up.)

## How to use this document

- The owner adjusts the milestone scopes as needed.
- Clawi works through them in order, declaring a milestone done only
  when every checkbox in that section passes a verifiable check.
- When a checkbox cannot be met as written (e.g. an SDK trait does not
  exist yet), Clawi surfaces the gap and proposes a revised criterion
  before silently dropping or weakening it.
