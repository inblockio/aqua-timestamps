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

The session before this one made non-trivial decisions about the
overall architecture (single key, SDK-over-spec, Caddy not nginx-proxy).
Those are now codified in `docs/success-criteria.md` and recapped above.
If a future session disagrees with any of them, change them deliberately,
not by drift.
