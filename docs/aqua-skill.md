---
name: aqua-timestamp-client
description: Use when an agent needs to obtain a tamper-evident timestamp witness for any 32-byte hash, dual-anchored to an EVM chain (Sepolia) AND an eIDAS-qualified RFC 3161 TSA, against the aqua-timestamp aggregator at {BASE_URL}. Covers SIWE / CAIP-122 authentication for `eip155` / `ed25519` / `p256` DIDs (deep-dive in `/.well-known/aqua-skill-auth.md`), leaf submission, polling for epoch seal, witness retrieval, signature + Merkle verification, and identity / server verification via `/.well-known/aqua-identity`.
version: 1.0.0
---

# aqua-timestamp-client

This service is a high-throughput timestamping aggregator. Submit a
32-byte hash, get back two signed witness revisions: one anchored to
Sepolia (cryptographic proof of existence), one anchored to a
Sectigo-qualified RFC 3161 timestamp authority (legal / eIDAS proof of
existence). Both chain off the hash you submitted via
`previous_revision`, so they merge directly into your Aqua tree with
no genesis rebase.

- Base URL: `{BASE_URL}`
- Server identity DID: `{SERVER_DID}` (verify against the live
  `/.well-known/aqua-identity` before trusting any witness).
- DNS / IP: `{DNS}` / `{IP}`.

## When to use this skill

Trigger phrases / situations:

- "anchor this hash", "timestamp this revision", "get a witness for X".
- The caller wants both EVM and eIDAS-qualified proof of existence for
  a piece of data and is willing to wait at most one epoch (10 min
  by default).
- The caller already has an Aqua tree and wants to append a witness
  chain rather than mint a new root.

Skip if:

- The caller wants to anchor a non-32-byte object (hash it first).
- The caller cannot wait for an epoch seal (use a per-hash anchor
  service instead).
- The caller is anchoring an empty / dummy hash (the service still
  accepts these but real evidence value is zero).

## Server identity and trust setup (do this once)

Before trusting any witness from `{BASE_URL}`, pin the server's
identity:

```sh
curl -sS {BASE_URL}/.well-known/aqua-identity > server-identity.json
```

The response carries the fields you need:

- `server_did` — the DID you'll see in every witness `signer` field.
- `ethereum_address` — the EIP-55 address ecrecover should return on
  every Signature revision the server mints.
- `identity_claim.revisions` — a valid Aqua tree:
  anchor -> `service_claim_server` object payload (with `signer_did`,
  `service_kind: "server"`, `valid_from`, `dns`, `ip`) -> EIP-191
  Signature. Verify it with `aqua-rs-sdk`'s
  `Aquafier::verify_tree_sync` (or equivalent). If verification fails,
  do not proceed.

The identity claim is self-signed by the server's secp256k1 key.
Add `server_did` to your trust store. From this point every witness
the server mints can be verified offline against this DID without
re-fetching the identity.

## Authenticate with the API (CAIP-122 / SIWE)

**Every protected endpoint requires a bearer token** in the
`Authorization: Bearer <token>` header. Obtain one by signing a
CAIP-122 challenge with the same private key your DID is derived
from. Three HTTP calls: challenge -> sign locally -> session ->
bearer. No shared secrets, no API keys.

Quickstart (eip155 example, using whichever local toolkit you've
already got for EIP-191 personal_sign):

```sh
# 1. Challenge
curl -sS '{BASE_URL}/auth/challenge?did=did:pkh:eip155:1:0xYOUR_ADDRESS'
#    -> { "nonce": "0x...", "message": "...", "expires_at": ... }

# 2. Sign the `message` bytes locally with your DID's key.
#    See the deep-dive for the exact prehash / encoding per curve.

# 3. Trade signature for bearer
curl -sS -X POST {BASE_URL}/auth/session \
  -H 'content-type: application/json' \
  -d '{"did":"did:pkh:...","nonce":"0x...","signature":"0x..."}'
#    -> { "token": "...", "did": "...", "valid_until": ... }

# 4. Carry the bearer on every protected call
curl -sS -H 'authorization: Bearer <token>' ...
```

**Deep-dive (read this before implementing):**
[`{BASE_URL}/.well-known/aqua-skill-auth.md`](/.well-known/aqua-skill-auth.md)
— accepted DID methods table (`eip155`, `ed25519`, `p256`), exact
prehash / signature encoding per curve, working Rust snippets,
failure-mode catalogue, lifetimes, reference implementation pointer.

A complete worked client lives at
[`crates/aqua-timestamp-e2e/src/flow.rs`](https://github.com/inblockio/aqua-timestamps/blob/main/crates/aqua-timestamp-e2e/src/flow.rs)
under `mint_bearer` + `ClientKey::sign_challenge`.

## Submitting a leaf

```sh
curl -sS -X POST {BASE_URL}/v1/leaves \
  -H 'authorization: Bearer <token>' \
  -H 'content-type: application/json' \
  -d '{"leaves":["0x<64 hex>"]}'
```

Request limits:

- 1..=10000 hashes per request (400 if outside).
- Each hash: optional `0x` prefix + exactly 64 hex chars (32 bytes).
- Duplicates within the same epoch are silently deduplicated; the
  response reports `accepted` vs `duplicates`.

Response (`202 Accepted`):

```json
{
  "accepted": 1,
  "duplicates": 0,
  "epoch_id": 42,
  "epoch_closes_at": 1779010650,
  "submitter_did": "did:pkh:eip155:1:0xYOUR_ADDRESS"
}
```

After this point the leaf is guaranteed to land in either `epoch_id`
or `epoch_id + 1` (never neither). The service records the submitter
DID so retrieval enforces ownership.

## Waiting for the epoch to seal

```sh
curl -sS {BASE_URL}/v1/schedule
```

Public, no auth required. Returns:

```json
{
  "current_epoch_id": 43,
  "current_epoch_opened_at": 1779010650,
  "current_epoch_closes_at": 1779011250,
  "epoch_duration_secs": 600,
  "last_sealed_epoch_id": 42,
  "last_sealed_at": 1779010650,
  "anchor_methods": ["evm", "qtsa"]
}
```

Poll until `last_sealed_epoch_id >= <your epoch_id>`. The safe ceiling
is `2 * (epoch_closes_at - now) + 30 s` from the submission response.

## Retrieving the witness

```sh
curl -sS -H 'authorization: Bearer <token>' \
  '{BASE_URL}/trees/by-leaf/0x<your-leaf-hex>?method=evm'
curl -sS -H 'authorization: Bearer <token>' \
  '{BASE_URL}/trees/by-leaf/0x<your-leaf-hex>?method=qtsa'
```

Each call returns a `Tree` object (the aqua-node wire format):

```json
{
  "revisions": {
    "0x<object_hash>":    { "revision_type": "...", "previous_revision": "0x<your-leaf>", "payloads": { ... }, ... },
    "0x<signature_hash>": { "revision_type": "...", "previous_revision": "0x<object_hash>", "signer": "<server_did>", "signature": { "signature_type": "ethereum:eip-191", "signature": "0x...65 bytes..." } }
  },
  "file_index": {
    "0x<object_hash>":    "witness_evm_0x<leaf-short>",
    "0x<signature_hash>": "witness_evm_0x<leaf-short>"
  }
}
```

The shape deserialises directly into `aqua_rs_sdk::schema::tree::Tree`.

Access control: a `404` means the leaf is unknown to the server. A
`403` means the leaf exists but a different DID submitted it. Callers
only see their own witnesses.

Other retrieval endpoints:

- `GET /trees` — list of all witness tips owned by the calling DID,
  descending by epoch.
- `GET /trees/{tip_hex}` — fetch a witness by signature-revision hash
  (the "tip"). aqua-node-compatible byte for byte.
- `GET /trees?epoch=<N>&method=evm|qtsa` — list every witness for the
  calling DID in epoch N (the union of revisions across all their
  leaves for that anchor method).
- `GET /v1/epochs?from=<id>&limit=<n>` — paginated epoch history.

## Verifying a witness offline (L1 / L2 / L3)

The minimum verification an agent should run after retrieval:

- **L1 — revision content integrity.** Hash each revision's JSON
  using `aqua_rs_sdk::verification::Linkable::calculate_link` and
  assert the result equals the map key it lives under. Either revision
  failing this check means the witness was tampered with in transit.

- **L2 — Merkle inclusion.** Read `payloads.merkle_root`,
  `payloads.merkle_proof`, `payloads.batch_tree_size`,
  `payloads.batch_leaf_index` from the TimestampObject revision. Run
  `aqua_rs_sdk::primitives::merkle::verify_inclusion(leaf_bytes,
  leaf_index, tree_size, &proof_bytes, &root_bytes,
  &HashType::Sha3_256)`. Must return true. The same check applies for
  both `evm` and `qtsa` witnesses because they share the same per-epoch
  root.

- **L3 — server signature.** Reconstruct the pre-signature canonical
  JSON of the Signature revision (the SDK exposes
  `signature.pre_signature_canonical_json()`), run
  `aqua_rs_sdk::core::signature::recover_wallet_address(canonical,
  &sig_bytes_65)`, and assert the recovered EIP-55 address equals the
  address in the pinned `server_did`. Anyone forging a witness needs
  the server's private key, so this check is the load-bearing one
  for trust.

For evm witnesses, you can additionally verify the on-chain
`transaction_hash` against the Sepolia RPC (selector `0x114ee197` is
`witness(bytes32)`; the call data after the selector is the Merkle
root). For qtsa witnesses, the `transaction_hash` is the base64-
encoded RFC 3161 TimeStampResp DER; verify the response under the
Sectigo Qualified Time Stamping Root R45 to confirm eIDAS-qualified
status (`certificatePolicies` OID `1.3.6.1.4.1.6449.1.2.1.9.1`).

## Failure modes the agent should handle

- `401` on any authenticated request: the bearer is missing, malformed,
  or expired. Re-run the challenge + session dance (see the
  [auth deep-dive](/.well-known/aqua-skill-auth.md)).
- `403` on a `/trees/...` call: the leaf exists but was submitted by a
  different DID. Don't retry blindly; the data isn't yours.
- `400` on `/v1/leaves`: malformed hash or over-cap batch. Inspect
  body for the field-level error message.
- `404` on `/trees/by-leaf/...` after the epoch is sealed: the leaf is
  truly unknown (very likely a typo in the hex). On the same call
  before the epoch is sealed, the leaf is still in the open
  accumulator and not yet retrievable.
- Mempool inclusion delay on the EVM tx: the witness lands as soon as
  the epoch is sealed even if the Sepolia tx is still pending. Poll
  the Sepolia RPC separately if a confirmed inclusion is required.

## Reference flow (Rust)

A complete reference client lives in
[aqua-timestamp-e2e](https://github.com/inblockio/aqua-timestamps/tree/main/crates/aqua-timestamp-e2e).
It runs the full flow + verification end-to-end against either the
deployed service or an in-process server, for all three DID methods.

To smoke-test against this deployment:

```sh
BASE_URL={BASE_URL} bash tests/e2e/live_roundtrip.sh
```

The wrapper looks up a test client mnemonic from the local
gnome-keyring, runs the SIWE -> submit -> wait-for-seal -> witness
-> verify cycle for both anchor methods, and exits `STATUS = OK`.

## Quick reference

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /.well-known/aqua-identity` | public | server identity claim (signed Aqua tree); pin once |
| `GET /.well-known/aqua-skill.md` | public | this skill (markdown, machine-readable) |
| `GET /.well-known/aqua-skill-auth.md` | public | SIWE / CAIP-122 auth deep-dive |
| `GET /docs` | public | the same content as a human-friendly HTML page |
| `GET /health` | public | liveness + uptime |
| `GET /v1/schedule` | public | current / last-sealed epoch state |
| `GET /auth/challenge?did=...` | public | CAIP-122 challenge |
| `POST /auth/session` | public | exchange signed challenge for bearer |
| `POST /v1/leaves` | bearer | submit hashes for the current epoch |
| `GET /v1/epochs` | bearer | paginated epoch history |
| `GET /trees` | bearer | tips owned by caller DID |
| `GET /trees/{tip}` | bearer | aqua-node compatible witness fetch by tip |
| `GET /trees/by-leaf/{leaf}?method=evm\|qtsa` | bearer | witness fetch by submitted leaf |
| `GET /trees?epoch=<N>&method=evm\|qtsa` | bearer | witnesses for caller's leaves in epoch N |

## License

Apache-2.0. Source at <https://github.com/inblockio/aqua-timestamps>.
