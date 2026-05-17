# aqua-timestamp (Aqua Aggregator)

A high-throughput timestamping service that batches revision hashes from
Aqua-enabled services into Merkle trees and dual-anchors them to an EVM
chain and an eIDAS-qualified TSA. See [`README.md`](README.md) for the
user-facing pitch and [`docs/design-spec.md`](docs/design-spec.md) for the
full architecture.

This file is the project-scoped bootstrapper. It refines the global
`~/.claude/CLAUDE.md`; defaults from there still apply.

## Read these first (in order)

1. [`docs/success-criteria.md`](docs/success-criteria.md) — the contract.
   Defines what "done" means at each milestone (M0 → M6 + M-E2E) and the
   "Hard requirements" section that overrides anything in the design spec.
2. [`docs/design-spec.md`](docs/design-spec.md) — the architecture. **Read
   with skepticism**: it predates the implementation and disagrees with
   the SDK in places (see "Hard requirements" below).
3. [`README.md`](README.md) — the elevator pitch.

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

## Deployment target

| Field | Value |
|---|---|
| Server | `139.59.144.60` (DigitalOcean) |
| DNS names pointing here | `timestamp.inblock.io`, `agentic.inblock.io` |
| Internal hostname | `agentic-hub` (don't be confused; same box) |
| OS / Docker | Ubuntu 24.04, Docker 29.3, Compose v5.1 |
| Reverse proxy | **Caddy 2** (`portal-caddy-1`) — auto-TLS, owns `:80` and `:443` |
| Caddyfile location | `/home/portal/portal/Caddyfile` (bind-mounted) |
| Backend network | `portal-net` (Docker bridge, declared in `/home/portal/portal/docker-compose.yml`) |
| Reload command | `docker exec portal-caddy-1 caddy reload --config /etc/caddy/Caddyfile` |
| Disk headroom | 110 GB free |
| Root SSH | `ssh -i ~/.ssh/timestamp_deploy_ed25519 root@timestamp.inblock.io` |

Pattern for our service: container attaches to the external `portal-net`
network, a site block for `timestamp.inblock.io` gets appended to the
existing Caddyfile, Caddy reload.

See memory [[reference-server-agentic-hub]] for full server details and
[[reference-server-inblockio-dev]] for the *other* inblockio server
(don't confuse them).

## Workflow conventions for this project

- **Build locally, ship the image.** Owner doesn't want GH Actions wired
  up yet. Local `docker buildx build`, then either
  `docker save | ssh root@... docker load` or push to `ghcr.io/inblockio/aqua-timestamp` once GH auth is in.
- **No GH Actions CI yet.** Add later; not blocking M0.
- **`cargo clippy -- -D warnings` and `cargo fmt --check`** before
  declaring any code work done (global rule, reaffirmed).
- **Secrets handling:** the service mnemonic NEVER goes into the repo,
  the image, or any committed compose file. It's read at runtime from
  `AQUA_TIMESTAMP_ANCHOR_MNEMONIC` env var, sourced from a `.env` on the
  server (chmod 600, not in git).

## Current state (handover, end of 2026-05-17)

**Done this session:**
- Repo cloned into this directory.
- Deploy SSH key generated and authorized on both inblockio boxes.
- Service / Sepolia anchor wallet generated; mnemonic in keyring.
  **Owner action pending: fund `0x55Fcf9F8C1287cB462aa3c1C97E2298d221c634f`
  on Sepolia** (~0.05 ETH from any public faucet).
- `docs/success-criteria.md` extended with milestone ladder, e2e test
  definition, hard requirements section, and wallet-provisioning
  preconditions.
- Both inblockio servers inventoried; deploy target conventions captured.

**Not started:**
- `Cargo.toml`, source layout, Axum scaffold, Dockerfile, deploy compose.
- Sister-repo vendoring (blocked on `gh` auth).
- Sepolia funding (owner action).

**Resume here (next session):**
1. Clone `aqua-node` into `~/projects/` (5 of 6 sister repos already
   present; this is the missing one). `gh auth login` if convenient,
   else SSH clone.
2. Owner: fund `0x55Fcf9F8C1287cB462aa3c1C97E2298d221c634f` on Sepolia
   (only blocking once you reach M4).
3. Scaffold the Cargo workspace per success-criteria.md §M0. Add
   `aqua-rs-sdk` and `aqua-rs-auth` as path deps so resolution is
   proven from day one.
4. Build image locally (multi-stage Rust, non-root), ship via
   `docker save | ssh -i ~/.ssh/timestamp_deploy_ed25519 root@timestamp.inblock.io docker load`.
5. Drop a compose stack on the server (mirror `/home/portal/portal/`
   shape), attach to `portal-net`, append a site block to
   `/home/portal/portal/Caddyfile`, `docker exec portal-caddy-1 caddy reload`.
6. Verify `https://timestamp.inblock.io/health` returns 200 from off-box.

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

### M5 hand-off

The qTSA stub stays in place at M4. M5 replaces it the same way:

1. Define an RFC 3161 client implementation of `AnchorProvider`.
2. Wire it under `[anchors.qtsa]` in config (new sub-table; mirror
   the `[anchors.evm]` shape).
3. Construct it in `build_app` (same pattern as the EVM branch) and
   attach via `WitnessContext::with_qtsa_anchor`.
4. The witness minter and storage paths need no change; the qTSA
   outcome already flows through `MethodAnchorOutcome`.

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

<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **aqua-timestamp** (209 symbols, 225 relationships, 0 execution flows). Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

> If any GitNexus tool warns the index is stale, run `npx gitnexus analyze` in terminal first.

## Always Do

- **MUST run impact analysis before editing any symbol.** Before modifying a function, class, or method, run `gitnexus_impact({target: "symbolName", direction: "upstream"})` and report the blast radius (direct callers, affected processes, risk level) to the user.
- **MUST run `gitnexus_detect_changes()` before committing** to verify your changes only affect expected symbols and execution flows.
- **MUST warn the user** if impact analysis returns HIGH or CRITICAL risk before proceeding with edits.
- When exploring unfamiliar code, use `gitnexus_query({query: "concept"})` to find execution flows instead of grepping. It returns process-grouped results ranked by relevance.
- When you need full context on a specific symbol — callers, callees, which execution flows it participates in — use `gitnexus_context({name: "symbolName"})`.

## Never Do

- NEVER edit a function, class, or method without first running `gitnexus_impact` on it.
- NEVER ignore HIGH or CRITICAL risk warnings from impact analysis.
- NEVER rename symbols with find-and-replace — use `gitnexus_rename` which understands the call graph.
- NEVER commit changes without running `gitnexus_detect_changes()` to check affected scope.

## Resources

| Resource | Use for |
|----------|---------|
| `gitnexus://repo/aqua-timestamp/context` | Codebase overview, check index freshness |
| `gitnexus://repo/aqua-timestamp/clusters` | All functional areas |
| `gitnexus://repo/aqua-timestamp/processes` | All execution flows |
| `gitnexus://repo/aqua-timestamp/process/{name}` | Step-by-step execution trace |

## CLI

| Task | Read this skill file |
|------|---------------------|
| Understand architecture / "How does X work?" | `.claude/skills/gitnexus/gitnexus-exploring/SKILL.md` |
| Blast radius / "What breaks if I change X?" | `.claude/skills/gitnexus/gitnexus-impact-analysis/SKILL.md` |
| Trace bugs / "Why is X failing?" | `.claude/skills/gitnexus/gitnexus-debugging/SKILL.md` |
| Rename / extract / split / refactor | `.claude/skills/gitnexus/gitnexus-refactoring/SKILL.md` |
| Tools, resources, schema reference | `.claude/skills/gitnexus/gitnexus-guide/SKILL.md` |
| Index, status, clean, wiki CLI commands | `.claude/skills/gitnexus/gitnexus-cli/SKILL.md` |
| Work in the Tests area (4 symbols) | `.claude/skills/generated/tests/SKILL.md` |
| Work in the Cluster_0 area (3 symbols) | `.claude/skills/generated/cluster-0/SKILL.md` |

<!-- gitnexus:end -->
