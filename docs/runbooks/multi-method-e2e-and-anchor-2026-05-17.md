# Multi-method e2e + second live Sepolia anchor, 2026-05-17

Follow-on to the overnight session. Captures answers to the operator's
post-handover questions and the verification work.

## 1. CLAUDE.md + skill files

`CLAUDE.md` now points at
[`docs/runbooks/session-2026-05-17-overnight-build.md`](session-2026-05-17-overnight-build.md)
and replaces the stale "Resume here" plan with a "Shipped" / "Deferred"
breakdown. The session log itself is the canonical "what happened"
artefact; there's no project-local `SKILL.md` to update (the only skill
files in `.claude/skills/` are auto-generated GitNexus index files,
managed by GitNexus, not the orchestrator).

## 2. E2E covers all three DID methods (secp256k1, ed25519, p256)

`aqua-rs-auth` accepts three CAIP-122 namespaces:

| DID format | Curve | Verifier |
|---|---|---|
| `did:pkh:eip155:1:0x{40 hex}` | secp256k1 | EIP-191 ecrecover, 65-byte `r||s||v` sig |
| `did:pkh:ed25519:0x{64 hex}` | Ed25519 | raw 64-byte Ed25519 sig over message bytes |
| `did:pkh:p256:0x{66 hex compressed}` | P-256 (NIST) | 64-byte ECDSA over message bytes (or DER) |

The challenge message format for all three is identical (CAIP-122 / SIWE
shape, with `Chain ID: 1` appended for `eip155` only). Verified by
inspecting `aqua-rs-auth/src/message.rs`.

The `aqua-timestamp-e2e` crate's `ClientKey` was generalised to dispatch
signing per method. Two new subcommands cover all three methods:

- **`live-all`** (against `https://timestamp.inblock.io`): runs the full
  flow three times, once per method. secp256k1 uses the keyring-stored
  test mnemonic; ed25519 and p256 generate fresh random keypairs
  in-process. Up to `3 * 600s` total on production epochs.
- **`selfcheck-all`** (against an in-process server with a channel
  sealer): same three runs, ~1s total.

A new integration test
`crates/aqua-timestamp-e2e/tests/multi_method.rs` invokes
`selfcheck-all` and asserts all three `STATUS=OK` plus
`OVERALL = OK (3 methods)`.

### Verified run (`cargo run --release -p aqua-timestamp-e2e -- selfcheck-all`)

```
[secp256k1+eip191] STATUS=OK  client_did=did:pkh:eip155:1:0x9858EfFD232B4033E47d90003D41EC34EcaEda94
[ed25519]          STATUS=OK  client_did=did:pkh:ed25519:0x09b084e995459b694add47eae8268b1f0e634db1bd0da8d6138563302e495423
[p256]             STATUS=OK  client_did=did:pkh:p256:0x0334757487d45c81d2c84139065c535fccdd130fdf39b24d86794ac64f3d6a4dc4
OVERALL = OK (3 methods)
```

Each pass exercises the same 10 steps (identity discovery, SIWE auth,
submit, wait for seal, witness retrieval, L1 + L2 + L3 verification,
isolation 403, no-bearer 401). The L3 verification always recovers the
same server address (`0x55Fcf9F8...634f` on prod, `0xf39Fd6e5...2266` in
selfcheck) because the witness is always signed by the server's
secp256k1 key regardless of which DID method the client used to log in.

## 3. Second live Sepolia anchor

Triggered fresh by running `tests/e2e/live_roundtrip.sh` against
production into epoch 30.

| Field | Epoch 7 (overnight) | Epoch 30 (this session) |
|---|---|---|
| Tx hash | `0x0db2eb94217596ad39c59c27f54778cd53911186ceb759d8c13ba8cb3bf81f3c` | `0x38fa0586aaa406eca34436ead05f8f35f76d605a18130ab9891cc215ad365354` |
| Block | `10866805` | `10867669` |
| Status | included | success (status=0x1) |
| Gas used | (~21k) | 22440 |
| Merkle root | `0xe5638244...4bbf` | `0x793327e8...9a45` |
| From | `0x55Fcf9F8...634f` | `0x55Fcf9F8...634f` |
| To (contract) | `0x269ff9a5cb9bd5319bd95b248d2579aa1e9d78fe` | (same) |

Etherscan links:

- <https://sepolia.etherscan.io/tx/0x0db2eb94217596ad39c59c27f54778cd53911186ceb759d8c13ba8cb3bf81f3c>
- <https://sepolia.etherscan.io/tx/0x38fa0586aaa406eca34436ead05f8f35f76d605a18130ab9891cc215ad365354>

Wallet balance after both anchors: still ~0.02 ETH (testnet gas is
essentially free; the burn-per-anchor is two orders of magnitude smaller
than the funded balance).

## 4. Current epoch configuration

From `deploy/config.toml` on the live server:

```toml
[epoch]
duration_secs           = 600
max_leaves_per_request  = 10000
```

- 10-minute epochs.
- Hard cap of 10,000 hashes per submit; 400 on over-cap.
- Empty epochs still seal but do **not** anchor (M4 guards against
  burning gas on degenerate roots; M3 still records the empty epoch
  with `leaf_count = 0`).

`anchors.evm` is on (the second anchor above demonstrates it), pointing
at `https://ethereum-sepolia-rpc.publicnode.com` on chain `sepolia`.
`anchors.qtsa` is not yet a config block (M5 work).

## 5. What's blocking real qTSA

Nothing inside the codebase. Concretely:

- `aqua_rs_sdk::web::tsa::TsaTimestamper` (at
  `aqua-rs-sdk/src/web/tsa.rs:528`) already implements
  `TimestampProvider::create_timestamp`. RFC 3161 request building,
  HTTP POST, and `genTime` extraction are all covered.
- M4 introduced an `AnchorProvider` trait with a blanket impl over the
  SDK's `TimestampProvider`. `TsaTimestamper` qualifies for free.
- The sealer already has a `qtsa_anchor` slot on `WitnessContext`; it
  currently stays empty so qTSA witnesses use stub data.

To turn on real qTSA, M5 needs:

1. A `[anchors.qtsa]` config sub-table mirroring `[anchors.evm]`:
   ```toml
   [anchors.qtsa]
   enabled              = true
   url                  = "http://timestamp.digicert.com"
   min_request_interval = 0     # 16 for Sectigo-qualified, etc.
   network_label        = "tsa"
   ```
2. About 30 lines in `crates/aqua-timestamp/src/lib.rs` to construct
   `TsaTimestamper` and attach it via `WitnessContext::with_qtsa_anchor`.
3. Tests mirroring M4's mock / failing / disabled paths.
4. (Optional) a `#[ignore]`-gated live test like
   `tests/live_sepolia_anchor.rs` that hits a public TSA.

Choosing a provider is the only real decision:

- Free standard TSA (e.g. `http://timestamp.digicert.com`,
  `http://timestamp.sectigo.com`): no auth, no rate limit beyond
  fairness; great for a smoke test, **not** eIDAS-qualified.
- eIDAS-qualified (e.g. D-Trust, Sectigo qualified, Buypass): requires
  an account and credentials; provides the legal trust the design spec
  asks for.

Recommendation: ship M5 first with a free standard TSA so the pipeline
is on the wire; cut over to an eIDAS-qualified provider once the
operator has chosen one.

## Tests after this work

```
auth_flow:        4 passed
identity:         3 passed
leaves_flow:      8 passed
smoke_health:     1 passed
witness_flow:     9 passed
(core unit):     27 passed
merkle_property:  1 passed
selfcheck:        1 passed
multi_method:     1 passed
TOTAL:           55 passed, 1 ignored (live Sepolia anchor)
```
