# Handover: Capacity Model + Wallet Pool Design (2026-05-20)

> **Confidence: LOW.** The numbers below are first-principles estimates, not
> benchmarked measurements. Per-leaf storage sizes are extrapolated from code
> structure, not measured on a running instance. EIP-191 and Ed25519 signing
> costs use published benchmarks, not local profiling. Wallet behavior
> archetypes are assumptions with no usage data behind them. Treat all
> figures as order-of-magnitude guidance, not engineering targets. Validate
> with real load testing before committing to capacity commitments.

## What happened this session

Capacity planning analysis for the aqua-timestamp service on the production
server (2-core, 4GB RAM, 50GB fjall DB). Three orthogonal layers modeled:
CPU seal throughput, storage retention, and session/memory overhead. Wallet
pool tiering and leaderboard structure designed. BTC authentication
feasibility investigated.

## Decisions made

1. **MAX_POOL = 500 wallets.** Template-defined, signed by authorized party.
   Scales with resources.

2. **Ed25519 for witness signing.** Not deferred. Root secp256k1 key
   (did:pkh:eip155:1:0x55Fc...) stays cold, signs identity tree and
   delegation claim only. Hot Ed25519 key signs all witness revisions.
   Delegation published via `/.well-known/aqua-identity`. Demand upstream
   SDK delegation claim template; hand-assemble until it lands (same
   pattern as `service_claim_server`).

3. **Storage is the sole binding constraint.** Ed25519 makes CPU irrelevant
   (~2% utilization at realistic loads). Per-leaf footprint: 4.7 KB (6.0 KB
   with LSM compaction). 50 GB holds ~8.8M leaves effective.

4. **Three-tier wallet eviction:**
   - Funded wallets: persist until outranked by fuel contribution (FILO)
   - Active unfunded: evict after 1 epoch (10 min) of inactivity
   - Idle auth-only: evict after 1 hour

5. **Two orthogonal leaderboards** (ETH | BTC), each showing: wallet DID,
   total fuel contributed, estimated tx funded, hashes submitted, last
   active timestamp.

6. **Free tier: 1 hash/s per wallet.**

## Key numbers

| Parameter | Value | Constraint |
|---|---|---|
| Per-leaf storage | 4.7 KB (6.0 KB effective) | Witness JSON is 84% |
| CPU seal cost (Ed25519) | 380 us/leaf | JSON serialization is new floor |
| Max sustained rate (25% CPU) | 658 leaves/s | Never binding |
| DB capacity | 8.8M leaves | 50 GB + LSM 1.3x |
| 500 wallets, 3-day retention | fits in 50 GB | OK for starter |
| 500 wallets, 7-day retention | needs ~86 GB | over budget w/o pruning |
| Witness pruning (hot/cold) | 15x storage efficiency | enables 30+ day retention |
| Max sessions (RAM) | ~2M | never binding |
| Absolute CPU ceiling | 14,620 wallets @ 25% | infinite disk scenario |

Wallet behavior model: weighted avg 0.045 hashes/s/wallet (27 hashes/epoch),
based on power/normal/light archetype mix (10%/30%/60%).

## Upstream gaps to file

1. **aqua-rs-sdk: DelegationClaim template.** Fields needed: `delegated_key_did`
   (the Ed25519 DID), `authority_scope` (e.g. "witness_signing"),
   `valid_from`, `valid_until`. Without this, hand-assemble the delegation
   revision like `service_claim_server`.

2. **aqua-auth: BitcoinSuite (BIP-322).** Bitcoin namespace not supported.
   Needs `CipherSuite` impl for `bip122`, BIP-322 message signing
   verification, `did:pkh:bip122:0:0x{address}` format. ~2-3 dev days.
   Client tooling exists (Sparrow, Bitcoin Core, BDK). Once registered,
   aqua-timestamp auth picks it up automatically.

## What to do next

### Priority 1: Ed25519 witness signing
1. Generate an Ed25519 keypair for the service (derive from same mnemonic
   or generate fresh; fresh is cleaner for key isolation).
2. Hand-assemble a delegation claim revision: root secp256k1 key signs a
   revision declaring the Ed25519 key is authorized for witness signing.
   Publish in the identity tree at `/.well-known/aqua-identity`.
3. Wire `Ed25519Signer` into the witness minter (`witness.rs`) instead of
   `Secp256k1Signer`.
4. File upstream issue on `aqua-rs-sdk` for `DelegationClaim` template.

### Priority 2: Wallet pool + eviction
1. Add wallet registry to `AppState` (in-memory `HashMap<DID, WalletEntry>`).
2. `WalletEntry`: tier (funded/active/idle), fuel_contributed_wei,
   fuel_contributed_sat, hashes_submitted, last_active, registered_at.
3. MAX_POOL check on SIWE session creation: reject if pool full and wallet
   has no fuel contribution that outranks the lowest funded wallet.
4. Eviction task (runs every epoch): sweep idle auth-only > 1h, sweep
   active unfunded > 1 epoch idle.
5. Funded wallets: update on-chain balance check (or event listener if
   the fuel split contract emits events).

### Priority 3: Leaderboard API
1. `GET /v1/leaderboard?chain=eth|btc` returning sorted wallet list.
2. `GET /v1/pool/status` returning current pool count, max pool,
   retention estimate.
3. No auth required for read (public scoreboard).

### Priority 4: Witness pruning (when storage pressure arrives)
1. Hot tier: full 4.7 KB/leaf for configurable window (e.g. 48h).
2. Cold tier: drop witness JSON, keep indexes only (306 B/leaf).
3. fjall compaction triggered by a background task on epoch boundaries.
4. This is the 15x storage lever; implements the "rolling period" the
   DB is designed for.

### Priority 5: BTC auth (when BTC leaderboard is needed)
1. Implement `BitcoinSuite` in aqua-auth.
2. Register in `all_cipher_suites()`.
3. BTC wallet holders can then authenticate and appear on BTC leaderboard.

## Files of interest

- This handover: `docs/handover/session-2026-05-20-capacity-wallet-pool.md`
- Bonding curve spec: `Spec_Aqua_L1_Timestamping_Bonding_Curve.md`
- Trust competition model: `Spec_Aqua_Trust_Competition_Model.md`
- Config example: `config.toml.example`
- Witness minter: `crates/aqua-timestamp-core/src/witness.rs`
- Sealer: `crates/aqua-timestamp-core/src/sealer.rs`
- Storage: `crates/aqua-timestamp-core/src/storage.rs`
- Auth: `crates/aqua-timestamp/src/auth.rs`
- Identity: `crates/aqua-timestamp/src/identity.rs`
