# aqua-timestamp (Aqua Aggregator)

A high-throughput timestamping service that batches revision hashes from
Aqua-enabled services into Merkle trees and dual-anchors them to an EVM
chain and an eIDAS-qualified TSA. See [`README.md`](README.md) for the
user-facing pitch and [`docs/design-spec.md`](docs/design-spec.md) for the
full architecture.

This file is the project-scoped bootstrapper. It refines the global
`~/.claude/CLAUDE.md`; defaults from there still apply.

## Brand: OpenWitness.org

The public-facing identity of this service is **OpenWitness.org**, with its
own visual language distinct from inblock.io. Use the `brand-design-open-witness`
skill (not the generic `brand-guide`) for all design, color, and copy decisions
on the landing page and any future OpenWitness-branded surfaces. The skill is
authoritative for OpenWitness brand choices.

## Read these first (in order)

1. [`docs/success-criteria.md`](docs/success-criteria.md) — the contract.
   Defines what "done" means at each milestone (M0 → M6 + M-E2E) and the
   "Hard requirements" section that overrides anything in the design spec.
2. [`docs/design-spec.md`](docs/design-spec.md) — the architecture. **Read
   with skepticism**: it predates the implementation and disagrees with
   the SDK in places (see "Hard requirements" below).
3. [`README.md`](README.md) — the elevator pitch.

## Economic design principles

- **Fuel, not fee.** The service is free. Contributions are "fuel" that
  powers the machine. Never use "fee" in specs, code, or docs.
- **Complete orthogonality.** BTC and ETH are the same model in two
  separate worlds. No cross-chain binding, no exchange rates, no shared
  balances. They share only the BTC difficulty epoch as a clock.
- **Forkability is governance.** The spec and service are open and meant
  to be copied. Operational accountability comes from competitive
  pressure, not from formulas or authorities. Never design for lock-in.
  See `Spec_Aqua_Trust_Competition_Model.md`.
- **Aqua-on-Aqua accountability.** The operational budget must be tracked
  using the Aqua Protocol itself. This is structural, not optional.

## Hard requirements (recap; see success-criteria for the full list)

- **One secp256k1 key** is the service identity, EIP-191 signer, and
  Sepolia anchor key. Mnemonic lives in gnome-keyring under
  `service=aqua-timestamp-evm-anchor user=clawi kind=mnemonic`.
  Address: `0x55Fcf9F8C1287cB462aa3c1C97E2298d221c634f` (verify against
  keyring before trusting; this address is informational, the keyring
  is source of truth).
- **SDK is authoritative over spec.** Where `aqua-rs-sdk` (Rust ref impl)
  disagrees with `aqua-spec`, the SDK wins. The aquafire identity tree
  at `https://aquafire.inblock.io/.well-known/aqua-identity` is the
  canonical shape to mirror — uses `did:pkh:eip155:1:0x...` +
  `signature_type: "ethereum:eip-191"` + `version:
  "https://aqua-protocol.org/docs/v4/schema"`, **not** the Ed25519 +
  CAIP-122 + V4 framing in `docs/design-spec.md`.
- **Aqua REST API contract.** `/trees/*` endpoints must match `aqua-node`
  byte for byte. Identity endpoint mirrors aquafire shape.
- **Auth is SIWE/EIP-191** via `aqua-rs-auth`, not handrolled.

## Canonical deps (private repos, owner-named)

All under `github.com/inblockio/`:

| Repo | Role |
|---|---|
| `aqua-spec` | Protocol spec + governance (less authoritative than the SDK) |
| `aqua-rs-sdk` | **Authoritative** Rust reference impl — Merkle, Object, Signature, templates, TimestampProvider |
| `aqua-rs-cli` | CLI wrapping the SDK; e2e test client should be built on this |
| `aqua-state-viewer` | Human-readable Aqua-tree visualizer |
| `aqua-rs-auth` | SIWE / CAIP-122 challenge-response crate |
| `aqua-node` | REST API contract our `/trees/*` endpoints follow |

These repos are **private**. As of handoff, 5 of 6 are cloned into
`~/projects/` via SSH: `aqua-rs-sdk`, `aqua-rs-auth`, `aqua-rs-cli`,
`aqua-state-viewer`, `aqua-spec`. **`aqua-node` is still missing** and
should be cloned before M3 (REST API contract reference).

`gh auth login` is still pending; not blocking for M0 (build locally,
push image to server directly), but needed later for GHCR / PRs.

## Dependency pins and `/version` (2026-10-02)

The three trains (`aqua-rs-sdk`, `aqua-auth`, `aqua-node`) are owned in the private
`inblockio/aqua-ops` repo (`train/train.toml`); the rule is
`development-conventions/CONVENTIONS-dependency-pins.md`: pin by annotated tag, never
more than 14 days behind. This repo pins, in the workspace `Cargo.toml`:

| Dependency | Pin | Notes |
|---|---|---|
| `aqua-rs-sdk`, `aqua-evm-provider`, `aqua-tsa-provider` | `v5.0.0` | one git source, `https://github.com/inblockio/aqua-rs-sdk` |
| `aqua-auth` | `v0.7.0` | `https://github.com/inblockio/aqua-auth` |
| `aqua-node` | n/a | not a dependency; only its `/trees` REST contract is mirrored (v0.1.7) |

Move a pin only when the train moves (read aqua-ops `origin/main`, not a stale local
checkout), in one PR, and check `cargo tree -d` shows no `aqua-*` crate.

`GET /version` (public) returns the running source `revision` (full commit, stamped by
`crates/aqua-timestamp/build.rs`, from git or the `GIT_SHA` build arg), `dirty`, the crate
`version` and the `protocol_version`; the image carries the same commit as the OCI label
`org.opencontainers.image.revision`. aqua-ops derives the deployed pins from that
commit's `Cargo.lock`. A dependency bump is not done until it is deployed and `/version`
names the merged commit (`deploy.sh` checks this).

`GET /health` (public) follows the inblockio service endpoint contract (aqua-ops
`docs/service-endpoints/health-and-version.md`, probed hourly by aqua-ops
`probes/service-endpoints`): `200`, `Content-Type: application/health+json`,
`Cache-Control: no-store`, body exactly `{"status":"pass"}` and nothing else (no uptime,
no version); GET and HEAD, any other method is `405` with `Allow: GET,HEAD`; no I/O. The
service has no in-process state a restart fixes, so it never answers `503`. Uptime is
`uptime_secs` in the public `GET /v1/schedule`: the landing page reads its uptime stat from
there on load and from the SSE `health:tick` event afterwards. The Docker `HEALTHCHECK`
only needs the `200`.

SDK 5.0.0 changed the wire: a `RevisionLink` is the full multihash (`0x1620` + digest) and
revisions no longer carry `hash_type`. Storage keeps the 32-byte digest; `/trees` keys and
tip lists emit the SDK form (what aqua-node parses with `RevisionLink::from_str`), and
leaf and tip inputs accept both the bare digest and the multihash. The production data
(about 13.5k test witnesses from 2026-05-22 under the old shape) was deliberately wiped on
the 5.0.0 deploy, 2026-10-02: Tim decided complete data loss was acceptable, so there is
no legacy-witness handling and epochs restarted at 1. aqua-auth 0.7 clients refuse a
challenge whose `URI:` origin differs from the origin they dialed, so clients must use
`https://openwitness.org`. The old name without the s, `timestamp.inblock.io`, is NXDOMAIN
and nothing needs it; `timestamps.inblock.io` (with the s) resolves again and only redirects.

## Deployment target

| Field | Value |
|---|---|
| Server | `142.93.168.4` (DigitalOcean) |
| Primary domain | `openwitness.org` |
| DNS names pointing here | `openwitness.org`, `timestamps.inblock.io` (`A 142.93.168.4`, TTL 300, set at checkdomain 2026-10-03; answers `301` to `https://openwitness.org/<path>?<query>` with a valid cert), `agentic.inblock.io`. `timestamp.inblock.io` (no s) is NXDOMAIN. |
| OS / Docker | Ubuntu 24.04, Docker 29.3, Compose v5.1 |
| Reverse proxy | **Caddy 2** (`portal-caddy-1`), auto-TLS, owns `:80` and `:443` |
| Caddyfile location | `/home/portal/portal/Caddyfile` (bind-mounted) |
| Backend network | `portal-net` (Docker bridge) |
| Reload command | `docker exec portal-caddy-1 caddy reload --config /etc/caddy/Caddyfile` |
| Deploy SSH | `ssh agentic.inblock.io` (alias in `~/.ssh/config`: user `deploy`, port 8022; `deploy.sh` uses this alias, not `timestamps.inblock.io`, which resolves since 2026-10-03 but is only the redirect name; some resolver caches lagged up to an hour after the change) |
| Deploy compose | `/home/deploy/timestamps/deploy/docker-compose.yml` |
| Deploy config | `/home/deploy/timestamps/deploy/config.toml` |

Pattern for our service: container attaches to the external `portal-net`
network, a site block for `openwitness.org` is in the Caddyfile,
`timestamps.inblock.io` redirects permanently to `openwitness.org`.

See memory [[reference-server-agentic-hub]] for full server details and
[[reference-server-inblockio-dev]] for the *other* inblockio server
(don't confuse them).

## Workflow conventions for this project

- **Deploy with `deploy/deploy.sh`.** The train dependencies are git tag pins,
  so there are no sibling checkouts to rsync any more. The script builds the image
  on the dev host (the production box has 2 vCPU / 4 GB shared with the Matrix
  stack), from `git archive HEAD` plus the private `aqua-rs-sdk` source vendored
  from the local cargo checkout (so the server needs no GitHub credentials), with
  `GIT_SHA` stamped in. It ships the image with `docker save | docker load`,
  recreates the container, and checks that the public `/version` names the commit
  it just built. It only deploys `origin/main`; `--build-only --allow-unmerged`
  rehearses a branch without touching the service; `--wipe-data` deletes the data
  volume and exists for the one-time SDK 5.0.0 migration. SSH is the
  `agentic.inblock.io` alias (port 8022), user `deploy`. There is no CI/CD: the old
  `deploy.yml` never succeeded (port 22 closed, no secrets, server dirs were not git
  repos) and was removed; automating this needs an SSH key secret plus a token for
  the SDK vendoring.
- **`cargo clippy --workspace --all-targets -- -D warnings` and
  `cargo fmt --check`** before declaring any code work done. The
  workspace ships clean under both on toolchain 1.95.0.
- **Secrets handling:** the service mnemonic NEVER goes into the
  repo, the image, or any committed compose file. It's read at
  runtime from `AQUA_TIMESTAMP_ANCHOR_MNEMONIC`, sourced from
  `/root/timestamp/.env` on the server (chmod 600, not in git). The
  pipe-only seeding pattern from the gnome-keyring to the remote
  `.env` is documented in the session transcript; never echo the
  mnemonic as a command argument.

## Current state (handover, end of 2026-05-17)

**Shipped at end of 2026-05-17 (M0 through M5 + M-E2E):**
- M0: Rust + Axum skeleton, Dockerized, deployed at `https://timestamp.inblock.io`.
- M1: identity loader, `service_claim_server` aqua-tree at
  `/.well-known/aqua-identity`, SIWE auth via `aqua-rs-auth`. All
  three CAIP-122 namespaces are supported on the wire: `eip155`
  (secp256k1 + EIP-191), `ed25519`, `p256`. The service's own
  identity DID is on `eip155:1`.
- M2: leaf accumulator + epoch sealer + fjall storage (`epochs`,
  `epoch_leaves`). Empty epochs still seal but don't anchor; epoch
  numbering monotonic across restarts.
- M3: witness revision minter, aqua-node-compatible
  `GET /trees/{tip}`, plus the aqua-timestamp extensions
  `/trees/by-leaf/{leaf}?method=` and `/trees?epoch=&method=` that
  return the same `Tree` shape. DID isolation enforced (`403` on
  other-DID lookups; `404` on unknown).
- M4: real Sepolia anchor via `aqua_rs_sdk::CliEthTimestamper`.
  First live tx
  `0x0db2eb94217596ad39c59c27f54778cd53911186ceb759d8c13ba8cb3bf81f3c`
  at block 10866805. The sealer falls back to a stub on RPC failure
  and continues; sealing never fails because an anchor failed.
- **M5**: real eIDAS-qualified qTSA anchor via
  `aqua_rs_sdk::web::tsa::TsaTimestamper` against
  `http://timestamp.sectigo.com/qualified`. Every non-empty epoch
  now produces dual witnesses (`method=evm` + `method=qtsa`).
  Sectigo's documented 16s minimum spacing is honored by the
  built-in throttle. First live qTSA witness was epoch 33 with
  `genTime=1779012930`, signed under the Sectigo Qualified Time
  Stamping Root R45.
- M-E2E: live + selfcheck client at `crates/aqua-timestamp-e2e/`.
  Subcommands: `live`, `selfcheck`, `live-all`, `selfcheck-all`.
  The wrapper at `tests/e2e/live_roundtrip.sh` runs the full flow
  (SIWE -> submit -> wait for seal -> fetch evm witness -> fetch
  qtsa witness -> verify L1 / L2 / L3 on both -> negative isolation
  + no-bearer checks) and exits `STATUS = OK`.

**Session log:** [`docs/runbooks/session-2026-05-17-overnight-build.md`](docs/runbooks/session-2026-05-17-overnight-build.md).
**Multi-DID + second Sepolia anchor:** [`docs/runbooks/multi-method-e2e-and-anchor-2026-05-17.md`](docs/runbooks/multi-method-e2e-and-anchor-2026-05-17.md).
**M5 qTSA anchor:** [`docs/runbooks/m5-qtsa-anchor-2026-05-17.md`](docs/runbooks/m5-qtsa-anchor-2026-05-17.md).

**Test counts on `main` after M5:** 59 passing, 1 `#[ignore]`-gated
(`live_sepolia_anchor`, runs only under `AQUA_TIMESTAMP_LIVE_SEPOLIA=1`
because every run burns Sepolia gas).

**Deferred (not blocking):**
- M6 production hardening: metrics, rate limits per DID, fjall
  pruning, WAL for the accumulator, chaos test for restart
  durability.
- GHCR push (`gh auth login` still pending).
- Image size trim: 139 MB at M5; target was <100 MB. The bulk is
  `libssl3` + `ca-certificates` for the SDK's `web` feature.
- Em-dash sweep in legacy prose
  (`crates/aqua-timestamp/src/landing.rs`, several doc files).

**Resume here (next session):**
1. Read the session log above and the M5 qTSA runbook for context.
2. If M6 is the target: pick metrics first (Prometheus scrape on
   `/metrics`, mirror `aqua-node`'s shape if it has one); then rate
   limits per DID via a tower middleware; then fjall pruning and the
   WAL. Restart durability is already proven; the chaos test is the
   regression net for it.
3. If `gh auth login` lands, switch the deploy from rsync + build to
   GHCR pull. Update `deploy/docker-compose.yml` to `image:
   ghcr.io/inblockio/aqua-timestamp:<tag>` and add a GH Actions
   workflow.

## M3 addendum (shipped 2026-05-17)

M3 lands the witness revision minter, the `/trees/*` endpoints, and the
DID-isolation invariant. Notes for whoever takes M4 / M-E2E next.

### Endpoint contract vs. aqua-node

aqua-node's REST surface (verified against
`~/projects/aqua-node/crates/aqua-rest/src/routes.rs`) exposes
`GET /trees`, `GET /trees/{tip}`, `GET /trees/by-genesis/{genesis}`,
`POST /trees`, `DELETE /trees/{tip}`, plus a dependencies route. It does
**not** offer a per-leaf or per-epoch query. aqua-timestamp therefore:

* Implements `GET /trees` and `GET /trees/{tip}` byte-for-byte against
  aqua-node's shape (the response deserialises back into
  `aqua_rs_sdk::schema::tree::Tree` cleanly; the
  `tip_response_shape_matches_aqua_node` test enforces this).
* ADDS two aqua-timestamp extensions that reuse the same
  `{revisions, file_index}` shape so aqua-node clients consume them
  without modification:
  * `GET /trees/by-leaf/{leaf_hex}?method=evm|qtsa`
  * `GET /trees?epoch=N&method=evm|qtsa`

All four are bearer-gated and enforce the DID-isolation invariant:
fetching a tip or leaf that exists but was submitted by a different DID
returns 403 (not 404). The `unknown_tip_returns_404_known_tip_for_other_did_returns_403`
test asserts both codes explicitly.

### Witness shape

For every accepted leaf at seal time, the minter produces two revisions
per anchor method, chained as `client_leaf -> TimestampObject ->
Signature`:

* The TimestampObject's `previous_revision` is the client-submitted leaf
  hash itself (treated as a `RevisionLink`). Method is `Method::Scalar`
  for parity with aquafire.
* Payload is the SDK's `EvmTimestampPayload` / `TsaTimestampPayload`.
  M3 is a stub anchor: `transaction_hash = 0x0...0` (64 hex zeros),
  EVM-only `smart_contract_address = 0x0...0` (40 hex zeros), qTSA
  `tsa_provider = "stub"`, EVM `network = "sepolia"`,
  `sender_account_address = service eth addr`. `merkle_proof` is the
  RFC 9162 inclusion proof against the persisted root, verified inside
  the M3 round-trip test.
* The Signature is EIP-191 over the canonical pre-signature JSON
  (`Secp256k1Signer`), `signer = identity.server_did`.

The task spec asked for `epoch_id` inside the payload. The SDK template
schemas (`timestamp_evm.json` / `timestamp_tsa.json`) declare
`additionalProperties: false`, so a payload carrying `epoch_id` would
fail `create_object_util` validation. Because the project rule is
"SDK is authoritative", `epoch_id` lives only in storage
(`TipPairIndex.epoch_id`) and not in the witness payload. The information
is reachable via `GET /trees?epoch=...&method=...` and `GET /v1/epochs`.

### Storage partitions added

* `witness_revisions`: 32-byte revision hash -> `serde_json` bytes of the
  `AnyRevision`. JSON (not postcard) so the value is byte-equal to what
  goes into the HTTP response.
* `leaf_to_tips`: `leaf (32 bytes) || method_byte (1 byte)` ->
  signature-revision hash. `method_byte = 0x01` for `evm`, `0x02` for
  `qtsa`.
* `leaf_owner`: leaf -> submitter DID UTF-8. Lets `/trees/by-leaf/...`
  answer 404 vs 403 without scanning the per-epoch prefix.
* `tip_to_pair`: signature hash -> postcard-encoded `TipPairIndex`
  carrying `(object_hash, signature_hash, leaf, method_byte, epoch_id,
  submitter_did, object_file_name, signature_file_name)`.

The seal commits the `EpochRecord`, the full leaf-set, every
`leaf_owner` mapping, and every witness revision through a single fjall
`Batch` + `SyncAll` so the durability story is unchanged from M2.

### Files of interest

* `crates/aqua-timestamp-core/src/witness.rs` (new): minter.
* `crates/aqua-timestamp-core/src/sealer.rs`: `seal_once` is now async,
  takes `Option<&WitnessContext>`, returns `(EpochRecord, Vec<MintedWitness>)`.
* `crates/aqua-timestamp-core/src/storage.rs`: partitions + queries.
* `crates/aqua-timestamp/src/routes.rs`: `/trees`, `/trees/{tip}`,
  `/trees/by-leaf/{leaf}` handlers.
* `crates/aqua-timestamp/src/config.rs`: new `AnchorConfig`
  (`evm_network`, defaulting to `"sepolia"`).
* `crates/aqua-timestamp/tests/witness_flow.rs`: 9 integration tests
  covering the round trip, isolation, restart durability, response
  shape, and query validation.

### M4 hand-off (legacy notes; M4 is now shipped, see M4 addendum below)

The witness minter previously wrote stub anchor outputs. M4 swaps EVM
for a real Sepolia anchor via `aqua_rs_sdk::CliEthTimestamper`.

M5 swaps the qTSA stub for a real RFC 3161 client. Same shape.

## M4 addendum (shipped 2026-05-17)

M4 wires the real Sepolia anchor on top of the M3 witness pipeline.
Notes for whoever takes M5 / M-E2E next.

### Architecture

* `crates/aqua-timestamp-core/src/anchors.rs` (new): tiny
  `AnchorProvider` trait + a blanket impl over the SDK's
  `TimestampProvider` (so `aqua_rs_sdk::CliEthTimestamper` is a usable
  anchor provider without any glue). `MockProvider` and
  `FailingProvider` test fixtures live in the same module, exposed
  unconditionally so cross-crate tests can reach them.
* `WitnessContext` (in `sealer.rs`) now carries
  `evm_anchor: Option<Arc<dyn AnchorProvider>>` and
  `qtsa_anchor: Option<Arc<dyn AnchorProvider>>`. `with_evm_anchor` /
  `with_qtsa_anchor` are the builder hooks.
* `MethodAnchorOutcome` (in `witness.rs`) captures the per-method
  anchor result (transaction hash, sender, contract, network,
  tsa_provider). `mint_witnesses_for_epoch` takes
  `&[(AnchorMethod, MethodAnchorOutcome)]` and folds the matching
  outcome into every per-leaf witness payload.
* `seal_once` calls each `dyn AnchorProvider` once per non-empty
  epoch with the full Merkle root (`0x` + 64 hex). On success the
  returned `TimestampValue` becomes the per-method outcome; on failure
  `MethodAnchorOutcome::stub_evm` / `stub_qtsa` populates a stub
  outcome and a `warn!` is logged. **Sealing never fails because the
  anchor failed.** Empty epochs skip the live anchor entirely (no
  gas for a degenerate root); this is asserted by
  `sealer::tests::empty_epoch_skips_live_anchor`.

### Config shape

The legacy M3 `[anchor]` block is replaced by `[anchors.evm]`:

```toml
[anchors.evm]
enabled       = true
rpc_url       = "https://ethereum-sepolia-rpc.publicnode.com"
chain         = "sepolia"            # mainnet | sepolia | holesky | custom:<id>
network_label = "sepolia"            # `network` field in witness payload
```

The legacy `[anchor]` block is still accepted (and aliased onto a
`anchor_legacy` field on `Config`), so an M3 config still loads after
an M4 upgrade. If the legacy block sets a non-default `evm_network`,
that value is promoted into `anchors.evm.network_label` automatically.
M6 removes the legacy block.

### Mnemonic handling

The mnemonic is read once from `AQUA_TIMESTAMP_ANCHOR_MNEMONIC` at
boot in `ServiceIdentity::from_env`, kept inside `ServiceIdentity`
under `Arc<String>`, and passed into `CliEthTimestamper::new` exactly
once during `build_app`. It is never re-read at seal time, never
logged, never returned over HTTP. The `Debug` impl on
`ServiceIdentity` redacts it (same as `private_key`).

### Tests

Unit tests in `sealer.rs` (under `crates/aqua-timestamp-core`):

* `happy_path_live_evm_anchor_populates_payloads`: `MockProvider`
  returning a canned `TimestampValue`; assert payload carries the
  canned `transaction_hash` / sender / contract / network.
* `fall_back_path_failing_anchor_does_not_fail_seal`:
  `FailingProvider`; assert payload carries stub data and the seal
  still produces an `EpochRecord`.
* `disabled_path_no_provider_uses_stub`: no `with_evm_anchor`; assert
  the live provider is never constructed (no RPC traffic).
* `empty_epoch_skips_live_anchor`: counting provider asserts zero
  invocations on an empty epoch.

Integration test (gated):
`crates/aqua-timestamp/tests/live_sepolia_anchor.rs` is `#[ignore]`
AND checks `AQUA_TIMESTAMP_LIVE_SEPOLIA=1`. Run it manually with:

```sh
AQUA_TIMESTAMP_LIVE_SEPOLIA=1 \
AQUA_TIMESTAMP_ANCHOR_MNEMONIC="<funded mnemonic>" \
    cargo test -p aqua-timestamp --test live_sepolia_anchor \
        -- --ignored --nocapture
```

It submits one leaf, triggers a seal, polls `/trees/by-leaf/...`
until the witness appears, and asserts the on-chain
`transaction_hash` is non-zero hex AND the wallet's Sepolia balance
strictly decreased. Every run burns testnet gas, hence the gate.

### Operational notes for deploy

* No new env vars beyond M3. `AQUA_TIMESTAMP_ANCHOR_MNEMONIC` is the
  same key used for identity + SIWE signing + Sepolia anchor (one
  secp256k1 key, per hard requirements).
* First live seal after deploy burns Sepolia gas; the funded balance
  (0.02 ETH) covers many anchor txs at testnet gas prices.
* If Sepolia is down or RPC times out: epoch still seals, witnesses
  carry stub anchor data for that epoch, `warn!` logs surface the
  failure. The aggregator self-recovers on the next epoch.
* To temporarily disable live anchoring at runtime (e.g. RPC outage
  drained gas budget): set `[anchors.evm].enabled = false` on the
  server's `deploy/config.toml` and restart. Witnesses minted while
  disabled carry stub anchor data; the EVM contract is unaffected.

### M5 hand-off (legacy notes; M5 is now shipped, see M5 addendum below)

The qTSA stub stays in place at M4. M5 replaces it the same way:

1. Define an RFC 3161 client implementation of `AnchorProvider`.
2. Wire it under `[anchors.qtsa]` in config (new sub-table; mirror
   the `[anchors.evm]` shape).
3. Construct it in `build_app` (same pattern as the EVM branch) and
   attach via `WitnessContext::with_qtsa_anchor`.
4. The witness minter and storage paths need no change; the qTSA
   outcome already flows through `MethodAnchorOutcome`.

## M5 addendum (shipped 2026-05-17)

M5 turned the qTSA stub into a real RFC 3161 anchor pointing at
`http://timestamp.sectigo.com/qualified` (the operator-chosen
eIDAS-qualified Sectigo endpoint). The wiring matched the M4 hand-off
sketch above almost exactly; the only surprise was that
`aqua_rs_sdk::web::tsa::TsaTimestamper` already implements the
SDK's `TimestampProvider` trait, so step 1 was free.

Concrete changes:

- New `[anchors.qtsa]` block in `crates/aqua-timestamp/src/config.rs`
  with `enabled`, `url`, `min_request_interval_secs` (16 by default
  for the Sectigo qualified endpoint), and `network_label` fields.
  The SDK doc-comment on `TsaTimestamper::new` recommends 16s
  spacing for Sectigo specifically; setting
  `min_request_interval_secs = 0` disables the throttle for free
  standard TSAs like DigiCert / Sectigo standard.
- `MethodAnchorOutcome::from_tsa_timestamp_value()` folds the live
  `TimestampValue` (`transaction_hash` = the RFC 3161 TimeStampResp
  identifier, `tsa_provider` = publisher name from the response,
  `smart_contract_address` = the TSA URL as the SDK overloads it,
  `network` = configured label) into the witness payload.
- `sealer::resolve_qtsa_outcome` mirrors `resolve_evm_outcome`
  exactly: live call on non-empty epochs with the provider attached;
  fall-back to stub on RPC error, empty epoch, or
  `[anchors.qtsa].enabled = false`. Sealing never fails because the
  qTSA call failed.
- `build_app` constructs the `TsaTimestamper` once at boot and
  attaches it via `WitnessContext::with_qtsa_anchor`.
- Four new unit tests in `crates/aqua-timestamp-core/src/sealer.rs`
  cover happy / failing / disabled / empty-epoch paths for the qTSA
  branch, identical in shape to the EVM tests added at M4.
- The e2e flow (`crates/aqua-timestamp-e2e/src/flow.rs`) gained a
  new step 9d that fetches `/trees/by-leaf/{leaf}?method=qtsa` and
  runs L1 / L2 / L3 against it, plus a payload-surface log line
  printing the TSA provider name, genTime, and the RFC 3161
  response byte length so a transcript is readable at a glance.
  A `404` on the qtsa lookup skips gracefully so a deployment
  without qTSA still passes.

The qTSA response is a fully signed RFC 3161 TimeStampResp under
the Sectigo Qualified Time Stamping Root R45. Any EU verifier can
confirm eIDAS-qualified status from the cert policy OID
(`1.3.6.1.4.1.6449.1.2.1.9.1` is Sectigo's qualified policy) without
extra input from us. The whole DER blob is in the witness payload.

The `live_qtsa_anchor` `#[ignore]`-gated test that mirrors
`live_sepolia_anchor` is left as a small follow-on for the next
session (TsaTimestamper is free to call, so a non-ignored variant
running under a `LIVE_QTSA=1` env gate is also reasonable).

## M1 addendum (shipped 2026-05-17)

M1 added identity + SIWE auth on top of the M0 binary. Notes for the next
hand:

- Source layout grew: `config.rs`, `identity.rs`, `auth.rs`, `state.rs`,
  `routes.rs`, and a `lib.rs` that exposes `build_app(cfg, identity,
  overrides)` so integration tests drive the same router as `main`.
- The identity tree is built with `create_object_util(template_link,
  None, payload, Method::Scalar)` then signed with `Secp256k1Signer`.
  Method is `Scalar` for parity with the aquafire reference's byte
  shape. The SDK `IdentityTreeBuilder` does not expose a
  `service_claim_server` constructor, so the tree is assembled directly.
- Tests: `crates/aqua-timestamp/tests/identity.rs` (mnemonic vector +
  SDK round-trip + golden snapshot) and
  `crates/aqua-timestamp/tests/auth_flow.rs` (full SIWE dance over the
  in-process router). Snapshot golden lives at
  `crates/aqua-timestamp/tests/fixtures/identity_golden.json`; re-bless
  via `AQUA_TIMESTAMP_BLESS=1 cargo test identity_snapshot`.
- Deploy: same compose, but the operator must place the production
  mnemonic into `deploy/.env` on the server (chmod 600, never in git)
  as `AQUA_TIMESTAMP_ANCHOR_MNEMONIC="…"`. The container reads it via
  `env_file: - .env` already declared in `deploy/docker-compose.yml`.
  The server's mnemonic is in the gnome-keyring under
  `service=aqua-timestamp-evm-anchor user=clawi kind=mnemonic`; pull it
  there at deploy time, don't commit it anywhere.
- M2 should start by replacing the M1 `/v1/leaves` stub with the real
  accumulator.

The session before this one made non-trivial decisions about the
overall architecture (single key, SDK-over-spec, Caddy not nginx-proxy).
Those are now codified in `docs/success-criteria.md` and recapped above.
If a future session disagrees with any of them, change them deliberately,
not by drift.

## Contributors / Leaderboard (added 2026-05-20)

Public scoreboard on the landing page between "Operational Overview" and
"Help us build trust". Two orthogonal leaderboards (ETH | BTC), each
showing wallet DID, fuel contributed, hashes submitted, last active.

**Skill:** `contributors-leaderboard` (invoke before modifying leaderboard
UI, API, storage, or watcher). The skill tracks implementation status.

**Self-learning loop:** When any session changes a leaderboard component
(frontend JS in `landing.rs`, API handlers in `routes.rs`, storage
partitions, watcher, or config), update the Implementation Status table
in `~/.claude/skills/contributors-leaderboard/SKILL.md` to reflect the
new state. This keeps the skill current across sessions.

**v0.1 target:** Sepolia ETH sent to the server wallet
(`0x55Fcf9F8C1287cB462aa3c1C97E2298d221c634f`) appears on the ETH
leaderboard. No SIWE auth required for passive fuel contributors.

**Implementation gaps (v0.1):**
1. Config `[leaderboard]` section (trivial)
2. fjall partitions: `contributor_stats`, `watcher_watermark` (small)
3. Transaction watcher: poll Sepolia blocks for incoming txs (medium)
4. Background poll task alongside sealer (small)
5. `GET /v1/leaderboard?chain=eth` + `GET /v1/pool/status` handlers (small)
6. Frontend JS is already wired and renders from these endpoints.

**Spec:** [session-2026-05-20-capacity-wallet-pool.md (archived)](https://github.com/inblockio/aqua-timestamps/blob/cbffca440310effa79bf30cb98bbcbcc7cd1b278/docs/handover/session-2026-05-20-capacity-wallet-pool.md)
(Priority 3). Wallet pool design (MAX_POOL=500, 3-tier eviction) is
deferred beyond v0.1.
