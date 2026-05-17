# Aqua Aggregator

A high-throughput timestamping service that batches revision hashes from multiple Aqua-enabled services into Merkle trees and dual-anchors them to both an EVM blockchain and an eIDAS-qualified TSA (qTSA) in periodic epochs.

## Overview

The Aqua Aggregator solves the cost problem of per-hash on-chain timestamping. Services like [aquafier-rs](https://github.com/inblockio/aquafier-rs) and [agent-customer-portal](https://github.com/inblockio/agent-customer-portal) produce thousands of revision hashes that benefit from anchoring but cannot justify individual on-chain transactions. The aggregator amortizes a single EVM transaction and a single qTSA request across all hashes submitted within an epoch.

## How It Works

```
Clients submit hashes ──> Aggregator buffers (epoch) ──> Merkle tree built
                                                              |
                                              ┌─���──────��──────┴───────────────┐
                                              v                               v
                                     EVM contract submit             eIDAS qTSA submit
                                              |                               |
                                              v                               v
                              Witness revisions minted        Witness revisions minted
                              (TimestampObject + Sig)         (TimestampObject + Sig)
                                              |                               |
                                              v                               v
                                     Client pulls (EVM)              Client pulls (qTSA)
                                              |                               |
                                              v                               v
                                     Merges into own tree          Merges into own tree
```

### Epoch Model

The aggregator operates in fixed-duration epochs (default: 10 minutes):

1. **Accumulate** - clients submit leaf hashes via `POST /v1/leaves`
2. **Seal** - epoch closes, Merkle tree built from sorted leaves (RFC 9162)
3. **Dual-anchor** - root submitted to EVM contract AND eIDAS qTSA simultaneously
4. **Mint** - per-leaf witness revisions produced (TimestampObject + AggregatorSignature)
5. **Distribute** - clients pull their witness revisions and merge them into their trees

### Dual Trust

Every epoch root is anchored to **both** providers:

| Provider | Trust Basis | Legal Standing |
|----------|------------|----------------|
| EVM (Ethereum/L2) | Cryptographic consensus | Technical proof of existence |
| eIDAS-qualified TSA | EU-regulated (Art. 41) | Legal proof of existence |

Clients choose which witness revisions to retrieve based on their use case.

### Witness Revisions

The aggregator produces two revisions per leaf per anchor method:

```
Client's tree:   ... -> [tip: 0xABC...]
                              |
Aggregator adds:              +-> [TimestampObject]       previous_revision = 0xABC
                                       |
                                       +-> [Signature]    signer = aggregator DID (Ed25519)
```

These revisions chain directly off the client's submitted hash via `previous_revision` and get merged into the client's tree. No standalone tree, no genesis. Standard Aqua verification applies without modification.

## Authentication

CAIP-122 challenge-response via [aqua-rs-auth](https://github.com/inblockio/aqua-rs-auth). Clients authenticate with their existing service DID (EIP-191, Ed25519, or P-256). Access is DID-scoped: clients can only retrieve witness revisions for leaves they submitted.

## Aggregator Identity

The aggregator publishes a signed service_claim tree at `/.well-known/aqua-identity`, following the same pattern as [aqua-node](https://github.com/inblockio/aqua-node). Clients add the aggregator's DID to their trust store to verify witness signatures.

## API

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `POST /v1/leaves` | Bearer | Submit revision hashes for timestamping |
| `GET /v1/schedule` | Public | Query current epoch timing and anchor methods |
| `GET /trees/{tip}` | Bearer | Fetch witness revisions by tip hash |
| `GET /trees/by-leaf/{hash}?method=evm\|qtsa` | Bearer | Fetch witness revisions by submitted leaf |
| `GET /trees?epoch={id}&method=evm\|qtsa` | Bearer | List all witnesses for an epoch |
| `GET /v1/epochs?from={id}&limit=N` | Bearer | Epoch history |
| `GET /.well-known/aqua-identity` | Public | Aggregator service claim |
| `GET /health` | Public | Health check |
| `GET /auth/challenge?did=...` | Public | CAIP-122 challenge |
| `POST /auth/session` | Public | CAIP-122 session creation |

## Tech Stack

- **Language:** Rust (edition 2021, rustc 1.85+)
- **HTTP:** Axum
- **Storage:** fjall (LSM-tree)
- **Auth:** aqua-rs-auth (SIWE / CAIP-122)
- **Merkle:** aqua-rs-sdk (RFC 9162 primitives)
- **Signing:** secp256k1 + EIP-191 (aqua-rs-sdk `Secp256k1Signer`)
- **EVM:** aqua-rs-sdk `TimestampProvider`
- **qTSA:** RFC 3161 via aqua-rs-sdk `TsaTimestamper`

## Build, run, deploy

The repo expects its sister Rust SDKs to live alongside it under
`~/projects/` (path deps in `Cargo.toml`):

```text
~/projects/
├── aqua-timestamp/   (this repo)
├── aqua-rs-sdk/
└── aqua-rs-auth/
```

### Local build + tests

```sh
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo test --workspace
```

### Run locally

```sh
cp config.toml.example config.toml
# The mnemonic is required from M1 on; it never lives in config.toml.
# In production it comes from the gnome-keyring via the .env on the
# server; for local dev, a test mnemonic is fine.
export AQUA_TIMESTAMP_ANCHOR_MNEMONIC="test test test test test test test test test test test junk"
cargo run --bin aqua-timestamp -- --config config.toml
# http://127.0.0.1:8080/health
# http://127.0.0.1:8080/.well-known/aqua-identity
```

### Docker build

The Dockerfile (`deploy/Dockerfile`) expects a build context **one level
above** this repo so it can `COPY` the sister SDKs:

```sh
cd ~/projects
docker buildx build -t aqua-timestamp:latest \
    -f aqua-timestamp/deploy/Dockerfile .
```

### Deploy to `timestamp.inblock.io`

See [`docs/runbooks/m0-deploy-transcript-2026-05-17.md`](docs/runbooks/m0-deploy-transcript-2026-05-17.md)
for the full sequence. Pattern: rsync source to the server, build with
buildx there, `docker compose up -d` against
[`deploy/docker-compose.yml`](deploy/docker-compose.yml), append the
[Caddy snippet](deploy/caddyfile.snippet) to the existing
`/home/portal/portal/Caddyfile`, `caddy reload`.

## Documentation

- [Success Criteria](docs/success-criteria.md): per-milestone checklist (the contract).
- [Design Spec](docs/design-spec.md): early architecture sketch. **Read with skepticism**; the
  `aqua-rs-sdk` is authoritative where it disagrees, and several spec choices
  (Ed25519 service key, V4 framing, single anchor) were superseded by what
  shipped. The runbooks below describe what the deployed service actually does.
- [Overnight build session](docs/runbooks/session-2026-05-17-overnight-build.md):
  M0 -> M4 + M-E2E shipped in one session.
- [M0 deploy transcript](docs/runbooks/m0-deploy-transcript-2026-05-17.md)
- [Live e2e transcript](docs/runbooks/e2e-live-transcript-2026-05-17.md)
- [Multi-DID e2e + second Sepolia anchor](docs/runbooks/multi-method-e2e-and-anchor-2026-05-17.md)
- [M5 qTSA anchor live](docs/runbooks/m5-qtsa-anchor-2026-05-17.md)
- Project context for future Claude sessions: [`CLAUDE.md`](CLAUDE.md).

## Status

| Milestone | State |
|---|---|
| **M0** Skeleton on the wire | shipped 2026-05-17 (`https://timestamp.inblock.io/health` live, valid Let's Encrypt) |
| **M1** Identity + SIWE auth | shipped 2026-05-17 (signed `service_claim_server` at `/.well-known/aqua-identity`, secp256k1+EIP-191 plus Ed25519 + P-256 clients verified) |
| **M2** Accumulate + seal | shipped 2026-05-17 (600s epochs, deterministic RFC 9162 Merkle root, fjall LSM-tree storage) |
| **M3** Witness revisions | shipped 2026-05-17 (aqua-node compatible `/trees/{tip}` plus `by-leaf` / `?epoch=&method=` extensions, DID isolation, restart durability) |
| **M-E2E** Live roundtrip | shipped 2026-05-17 (`tests/e2e/live_roundtrip.sh` end-to-end, all three DID methods proven in-process) |
| **M4** Real EVM anchor (Sepolia) | shipped 2026-05-17 (`CliEthTimestamper` against Sepolia at chain id 11155111; service wallet `0x55Fcf9F8...634f`) |
| **M5** Real qTSA anchor | shipped 2026-05-17 (`TsaTimestamper` against `http://timestamp.sectigo.com/qualified`, eIDAS qualified chain) |
| M6 Production hardening | pending (metrics, rate-limits per DID, fjall pruning, WAL, chaos test) |

## License

AGPL-3.0
