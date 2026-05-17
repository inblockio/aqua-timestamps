# Overnight build session, 2026-05-17

The owner went to sleep with the instruction "execute without my
interference until you reach project goal". This document is the
session log: what shipped, how, and what's left.

## State at the start of the session

- M0 not yet written: only the architecture spec and README on `main`
  (`520d3c2`).
- Service / Sepolia anchor wallet (`0x55Fcf9F8C1287cB462aa3c1C97E2298d221c634f`)
  already generated; mnemonic in gnome-keyring; balance funded with
  ~0.02 ETH Sepolia.
- Sister repos all cloned (`aqua-rs-sdk`, `aqua-rs-auth`, `aqua-rs-cli`,
  `aqua-state-viewer`, `aqua-spec`; `aqua-node` was missing and got
  cloned at the start of this session).
- No local Docker (host policy gates `apt`); deploy server has buildx.

## What shipped

The orchestrator (this session) drove M0 through M4 plus M-E2E, using
isolated git worktrees for each implementation milestone. Each milestone
was implemented by a subagent off `main`, reviewed, fast-forwarded /
merged, redeployed to `https://timestamp.inblock.io`, and verified live
where applicable.

| Milestone | Commit | Tests | Live verification |
|---|---|---|---|
| **M0** Skeleton on the wire | `2da36ca` | 1 smoke | `/health` 200 + valid TLS |
| **M1** Identity + SIWE auth | `7823f17` | 8 (auth + identity + smoke) | `server_did` = `did:pkh:eip155:1:0x55Fcf9F8...634f`, challenge / session dance live |
| **M2** Accumulate + seal | `786a995` | 32 (fjall + accumulator + sealer + property) | `/v1/schedule` + `/v1/epochs` live, 600 s epochs sealing on the deployed box |
| **M3** Witness revisions + /trees | `e32f0cb` | 45 (witness flow + isolation + restart durability + aqua-node shape) | `/trees/{tip}` + `/trees/by-leaf/...?method=` + `/trees?epoch=&method=` |
| **M4** Real Sepolia anchor | `54f08c9` | 53 (mock + fall-back + disabled paths; live test `#[ignore]`-gated) | **real Sepolia tx** `0x0db2eb94...1f3c` at block `10866805` anchoring epoch 7 |
| **M-E2E** Live roundtrip | `06f25c5` (merge `2100acb`, post-fix `d6a8680`) | selfcheck + 53 inherited | full 10-step flow `tests/e2e/live_roundtrip.sh` passed against the deployed M4 service |

**Final test count on `main`:** 54 unit + integration + property tests, 1 ignored (the gas-burning live Sepolia anchor test that runs only under `AQUA_TIMESTAMP_LIVE_SEPOLIA=1`).

## Live E2E transcript (run after M4 was deployed)

Captured in `docs/runbooks/e2e-live-transcript-2026-05-17.md`. Summary of the post-M4 run:

```
[step 1]  derived test client did:pkh:eip155:1:0x5d6055694d98B5Bb888c3E51eC39877e927e0501
[step 2]  identity shape ok, server_did=did:pkh:eip155:1:0x55Fcf9F8C1287cB462aa3c1C97E2298d221c634f
[step 3]  auth/challenge signed, POST /auth/session returned a token
[step 5]  generated random leaf 0xe5638244...4bbf
[step 6]  submitted leaf to epoch 7 (closes_at=1778996850)
[step 7]  /v1/schedule confirms epoch 7 sealed
[step 8]  retrieved 2 witness revisions
[step 9]  L1 ok: revision rehash matches declared link
[step 9]  L2 ok: inclusion proof verifies (root=0xe563...4bbf, idx=0, size=1)
[step 9]  L3 ok: EIP-191 signature recovers to 0x55Fcf9F8C1287cB462aa3c1C97E2298d221c634f
[step 10] negative-1 ok: foreign DID gets 403 on by-leaf
[step 10] negative-2 ok: no-bearer POST /v1/leaves returns 401
STATUS = OK
```

Real Sepolia transaction submitted by the anchor:
- Hash: `0x0db2eb94217596ad39c59c27f54778cd53911186ceb759d8c13ba8cb3bf81f3c`
- From: `0x55fcf9f8c1287cb462aa3c1c97e2298d221c634f` (service wallet)
- To: `0x269ff9a5cb9bd5319bd95b248d2579aa1e9d78fe` (TIMESTAMP_ETH_SMART_CONTRACT_ADDRESS, hard-coded in `aqua-rs-sdk/src/blockchain/timestamp.rs`)
- Block: `0xa5d075` (10866805)
- Input: `0x114ee197` (witness selector) + the epoch 7 Merkle root
- Cost: ~tiny fraction of an ETH at testnet gas; balance still ~0.02 ETH

## Architecture (final)

```
~/projects/aqua-timestamp/
├── Cargo.toml                                 (workspace root)
├── crates/
│   ├── aqua-timestamp/                        (the server binary)
│   │   └── src/
│   │       ├── main.rs                        (thin wrapper around build_app)
│   │       ├── lib.rs                         (build_app, sealer wiring)
│   │       ├── config.rs                      ([server] [identity] [auth] [storage] [epoch] [anchors.evm])
│   │       ├── state.rs                       (AppState + bearer extractor plumbing)
│   │       ├── identity.rs                    (ServiceIdentity + service_claim_server tree)
│   │       ├── auth.rs                        (challenge / session / bearer middleware)
│   │       ├── routes.rs                      (/health, /, /.well-known/aqua-identity,
│   │       │                                   /auth/*, /v1/leaves, /v1/schedule,
│   │       │                                   /v1/epochs, /trees, /trees/{tip},
│   │       │                                   /trees/by-leaf, /trees?epoch=&method=)
│   │       └── landing.rs                     (single-file HTML landing)
│   ├── aqua-timestamp-core/                   (shared types and primitives)
│   │   └── src/
│   │       ├── accumulator.rs                 (Mutex-protected leaf buffer)
│   │       ├── epoch.rs                       (EpochRecord)
│   │       ├── merkle.rs                      (thin adapters over aqua-rs-sdk RFC 9162)
│   │       ├── sealer.rs                      (per-epoch seal + anchor orchestration)
│   │       ├── storage.rs                     (fjall with 5 partitions)
│   │       ├── time.rs                        (Clock trait + SystemClock)
│   │       ├── witness.rs                     (TimestampObject + Signature minter)
│   │       └── anchors.rs                     (AnchorProvider trait + blanket impl
│   │                                           over aqua-rs-sdk TimestampProvider)
│   └── aqua-timestamp-e2e/                    (live + selfcheck E2E test client)
│       └── src/
│           ├── main.rs                        (clap: live | selfcheck)
│           ├── flow.rs                        (the 10-step witness round-trip)
│           └── selfcheck.rs                   (in-process server + channel sealer)
├── deploy/
│   ├── Dockerfile                             (multi-stage; rust:1.95 -> debian-slim; non-root)
│   ├── docker-compose.yml                     (attaches to external portal-net)
│   ├── config.toml                            (server-side config)
│   └── caddyfile.snippet                      (site block appended to /home/portal/portal/Caddyfile)
├── tests/e2e/
│   └── live_roundtrip.sh                      (looks up test client mnemonic from keyring, runs `live`)
├── docs/
│   ├── design-spec.md                         (pre-existing; outdated in places, SDK is authoritative)
│   ├── success-criteria.md                    (the contract; M0-M3 + M-E2E + M4 ticked)
│   ├── handover-2026-05-17.md                 (pre-session handover doc)
│   └── runbooks/
│       ├── m0-deploy-transcript-2026-05-17.md
│       ├── e2e-live-transcript-2026-05-17.md
│       └── session-2026-05-17-overnight-build.md  (this file)
└── config.toml.example
```

## Storage layout (fjall)

The deployed keyspace at `/var/lib/aqua-timestamp/state` (mounted via the
`timestamp-data` named volume) contains five partitions:

- `epochs` — `u64 BE epoch_id` -> `EpochRecord` (postcard).
- `epoch_leaves` — `u64 BE epoch_id || leaf_bytes` -> submitter DID UTF-8.
- `witness_revisions` — `revision_hash` -> `serde_json::Value` of the `AnyRevision`.
- `tip_to_pair` — signature revision hash -> packed `TipPairIndex` (object hash, leaf, method byte, epoch id, submitter DID, file names).
- `leaf_to_tips` — `leaf || method_byte` -> signature revision hash.
- `leaf_owner` — `leaf` -> submitter DID UTF-8.

All seal-time writes happen under one fjall `Batch` followed by `PersistMode::SyncAll`. Restart durability is tested.

## Operational notes

- **Container restart resilience:** the named `timestamp-data` Docker volume survives `docker compose down` + `up -d`, so epoch numbering and prior witnesses persist. Verified across all redeploys this session.
- **Caddyfile state:** the original `/home/portal/portal/Caddyfile` was backed up before the first append (`Caddyfile.bak.20260517-031530`). The `timestamp.inblock.io` site block is the only addition.
- **Regression: `agentic.inblock.io`** still returns its prior 303 redirect (unchanged across all Caddy reloads).
- **EVM anchor failure handling:** if `CliEthTimestamper::create_timestamp` errors (insufficient balance, RPC down, etc.), the sealer emits a `tracing::warn`, falls back to stub data for that epoch's EVM witnesses, and continues. **Sealing never fails because the anchor failed**, and a future epoch retries.
- **Empty epochs do not anchor.** No leaves submitted == no gas burned. The epoch still seals with `leaf_count = 0` and an empty Merkle root, just without an on-chain tx.
- **Image size:** 139 MB at M4 (over the <100 MB success-criteria target). The bulk is `libssl3` + `ca-certificates` needed by the SDK's `web` feature for RFC 3161. Trimming is deferred.

## What's deferred (NOT shipped this session)

- **M5: real qTSA anchor.** The `qtsa_anchor` slot on `WitnessContext` and the `MethodAnchorOutcome` shape are in place; M5 only has to wire an RFC 3161 `AnchorProvider` impl and a `[anchors.qtsa]` config sub-table. M5 was out of scope for this session.
- **M6: production hardening.** Metrics, structured tracing tightening, rate limits per DID, fjall retention pruning, write-ahead log for the accumulator, chaos test for restart durability. Deferred.
- **GHCR push.** Image is built directly on the deploy server from rsynced source (no `gh auth`). Deferred until `gh auth login` happens.
- **Image size trim.** Listed above; cosmetic.
- **Em-dash sweep.** Pre-existing em-dashes from M0/M1 prose (`crates/aqua-timestamp/src/landing.rs`, several doc files) violate the global writing-style rule. Each implementation agent's *new* code is em-dash-free; the legacy ones are flagged in commit reports.

## How to operate

### Local

```sh
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo test --workspace                          # 54 tests, 1 ignored

# Live E2E (against deployed service)
chmod +x tests/e2e/live_roundtrip.sh
BASE_URL=https://timestamp.inblock.io tests/e2e/live_roundtrip.sh
```

### Live Sepolia anchor smoke test (burns Sepolia gas)

```sh
AQUA_TIMESTAMP_LIVE_SEPOLIA=1 \
  cargo test -p aqua-timestamp \
    --test live_sepolia_anchor \
    -- --ignored
```

### Redeploy

```sh
cd ~/projects
rsync -az --delete --exclude=target --exclude=.git --exclude=.claude \
  -e 'ssh -i ~/.ssh/timestamp_deploy_ed25519' \
  aqua-timestamp aqua-rs-sdk aqua-rs-auth \
  root@timestamp.inblock.io:/root/timestamp/build/
ssh -i ~/.ssh/timestamp_deploy_ed25519 root@timestamp.inblock.io '
  cd /root/timestamp/build &&
  cp aqua-timestamp/deploy/Dockerfile . &&
  cp aqua-timestamp/deploy/.dockerignore . &&
  docker buildx build -t aqua-timestamp:latest -f Dockerfile .
'
scp -i ~/.ssh/timestamp_deploy_ed25519 \
  deploy/{docker-compose.yml,config.toml} \
  root@timestamp.inblock.io:/root/timestamp/
ssh -i ~/.ssh/timestamp_deploy_ed25519 root@timestamp.inblock.io \
  'cd /root/timestamp && docker compose down && docker compose up -d'
```

The `.env` on the server already has `AQUA_TIMESTAMP_ANCHOR_MNEMONIC` set
from gnome-keyring (seeded once at the start of M1 deploy via
`secret-tool ... | ssh ... cat >> /root/timestamp/.env` with no
plain-text intermediary).

## Owner action items waiting

- None blocking. Sepolia funding is sufficient for many anchor txs at
  testnet gas, balance was confirmed at ~0.02 ETH after M4's first
  anchor. Verify on Etherscan: `https://sepolia.etherscan.io/address/0x55Fcf9F8C1287cB462aa3c1C97E2298d221c634f`.
- Optional: `gh auth login` to enable GHCR image push instead of
  rsync+build-on-server.
- Optional: review the em-dash sweep flagged in this doc and queue a
  cleanup PR.

## Sister-repo state (read-only path-deps)

All six inblockio sister repos are now cloned under `~/projects/`:
`aqua-spec`, `aqua-rs-sdk`, `aqua-rs-cli`, `aqua-state-viewer`,
`aqua-rs-auth`, `aqua-node` (the last one cloned at the start of this
session). Workspace `Cargo.toml` references `aqua-rs-sdk` and
`aqua-rs-auth` as `path = "../..."` deps.

## Closing notes

The crab scuttles to bed. The pipe runs end to end: clients sign in with
their own Ethereum DID, submit revision hashes, get back a tamper-evident
witness chain whose Merkle root is anchored on Sepolia. M5 (qTSA) is the
next milestone if the owner wants the dual-trust story live.
