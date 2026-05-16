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

- **Language:** Rust
- **HTTP:** Axum
- **Storage:** fjall (LSM-tree)
- **Auth:** aqua-rs-auth (CAIP-122)
- **Merkle:** aqua-rs-sdk (RFC 9162 primitives)
- **Signing:** Ed25519 (ed25519-dalek)
- **EVM:** aqua-rs-sdk TimestampProvider
- **qTSA:** RFC 3161 via aqua-rs-sdk TsaTimestamper

## Documentation

- [Design Specification](docs/design-spec.md) - Full architecture, data flows, and protocol details

## Status

**Pre-implementation.** Architecture spec under review.

## License

AGPL-3.0
