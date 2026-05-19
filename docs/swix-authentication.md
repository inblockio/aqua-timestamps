---
name: aqua-timestamp-auth
description: SIWE / CAIP-122 authentication for aqua-timestamp. Use when an agent or operator needs the full message-signing recipe (challenge -> sign -> session -> bearer) for one of the three accepted DID methods (eip155 + EIP-191, ed25519, p256). Linked from the main agent skill at `/.well-known/aqua-skill.md` as the auth deep-dive.
version: 1.0.0
---

# Authenticate with the aqua-timestamp API (SIWE / CAIP-122)

This is the sub-article linked from
[`/.well-known/aqua-skill.md`](aqua-skill.md). It's everything you
need to obtain a bearer for `{BASE_URL}`'s protected endpoints. The
main skill points here so the high-level overview stays slim.

**Every protected endpoint requires a bearer token in the
`Authorization: Bearer <token>` header.** Obtain one by signing a
CAIP-122 challenge with the same private key your DID is derived from.
Three HTTP calls: challenge -> sign locally -> session -> bearer. No
shared secrets, no API keys, no pre-registration.

The auth crate is [`aqua-rs-auth`](https://github.com/inblockio/aqua-rs-auth)
(crate name `aqua-auth`), the same one the entire Aqua ecosystem uses,
so an existing aqua-node / aquafire / agentic-portal client can
authenticate here without code changes.

## Supported DID methods

| DID format | Curve | What to sign | Signature shape |
|---|---|---|---|
| `did:pkh:eip155:1:0x{40 hex address}` | secp256k1 | `keccak256("\x19Ethereum Signed Message:\n" + len(msg) + msg)` (EIP-191 personal_sign prehash) | 65 bytes: `r \|\| s \|\| v`, with `v = recovery_id + 27` |
| `did:pkh:ed25519:0x{64 hex pubkey}` | Ed25519 | raw `msg` bytes | 64 bytes |
| `did:pkh:p256:0x{66 hex compressed pubkey}` | P-256 (NIST) | raw `msg` bytes | 64 bytes fixed-size (DER also accepted) |

The signature goes on the wire as a `0x`-prefixed hex string.

## Step 1: request a challenge

```sh
curl -sS '{BASE_URL}/auth/challenge?did=did:pkh:eip155:1:0xYOUR_ADDRESS'
```

Response (single-use, 5-minute TTL):

```json
{
  "nonce": "0x9a8b...e5ce4ea63c3708fe9d601fc399491bac22cd65d58c173791da97237c7d247fe9",
  "message": "{DNS} wants you to sign in with your Ethereum account:\n0xYOUR_ADDRESS\n\nSign in to Aqua Node\n\nURI: {BASE_URL}\nVersion: 1\nNonce: 0x9a8b...\nIssued At: 2026-05-17T03:55:30.049Z\nExpiration Time: 2026-05-17T04:00:30.049Z\nChain ID: 1",
  "expires_at": 1778990430
}
```

The `message` field is the canonical CAIP-122 / SIWE text. **You sign
the `message` bytes as-is, not the JSON envelope.** For `eip155` it
carries a `Chain ID: 1` trailer (MetaMask renders this natively); for
`ed25519` / `p256` the trailer is omitted and the `Ethereum account`
label is replaced by `Ed25519 account` / `P-256 account` so the same
template covers all three methods.

## Step 2: sign the message locally

### eip155 (secp256k1 + EIP-191)

```rust
use k256::ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, Signature, SigningKey};
use sha3::{Digest, Keccak256};

let signing_key = SigningKey::from_slice(&priv_32)?;
let mut h = Keccak256::new();
h.update(format!("\x19Ethereum Signed Message:\n{}", message.len()).as_bytes());
h.update(message.as_bytes());
let prehash: [u8; 32] = h.finalize().into();
let (sig, rec): (Signature, RecoveryId) = signing_key.sign_prehash(&prehash)?;
let mut bytes = [0u8; 65];
bytes[..64].copy_from_slice(&sig.to_bytes());
bytes[64] = u8::from(rec) + 27;
let signature_hex = format!("0x{}", hex::encode(bytes));
```

(`alloy::signers::local::PrivateKeySigner::sign_message(message)` does
the same thing in one line if you're already on alloy.)

### ed25519

```rust
use ed25519_dalek::{Signer, SigningKey};
let sk = SigningKey::from_bytes(&priv_32);
let sig = sk.sign(message.as_bytes()); // 64 bytes
let signature_hex = format!("0x{}", hex::encode(sig.to_bytes()));
```

### p256

```rust
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
let sk = SigningKey::from_slice(&priv_32)?;
let sig: Signature = sk.sign(message.as_bytes()); // 64-byte fixed-size
let signature_hex = format!("0x{}", hex::encode(sig.to_bytes()));
```

## Step 3: post the signed challenge for a bearer

```sh
curl -sS -X POST {BASE_URL}/auth/session \
  -H 'content-type: application/json' \
  -d '{
        "did":       "did:pkh:eip155:1:0xYOUR_ADDRESS",
        "nonce":     "0x9a8b...",
        "signature": "0x<the hex from step 2>"
      }'
```

Response (1-hour TTL by default):

```json
{
  "token":       "fb8ca2a2...64 hex...",
  "did":         "did:pkh:eip155:1:0xYOUR_ADDRESS",
  "valid_until": 1778999981,
  "created_at":  1778996381
}
```

The server (a) looks up the challenge by nonce, (b) confirms it hasn't
expired and hasn't been used, (c) calls
`aqua_auth::verify_caip122(did, message, signature_bytes)` which
dispatches on the DID namespace and verifies under the correct curve.

## Step 4: use the bearer on every authenticated call

```sh
TOKEN="fb8ca2a2..."
curl -sS -X POST {BASE_URL}/v1/leaves \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"leaves":["0x9615...5a97"]}'

curl -sS -H "authorization: Bearer $TOKEN" \
  '{BASE_URL}/trees/by-leaf/0x9615...5a97?method=evm'
```

The bearer authenticates the DID across **all** protected endpoints
(`POST /v1/leaves`, `GET /v1/epochs`, `GET /trees`,
`GET /trees/{tip}`, `GET /trees/by-leaf/{leaf}?method=...`,
`GET /trees?epoch=&method=...`). DID isolation is enforced on the
retrieval routes: a `404` on `/trees/by-leaf/...` means the leaf is
unknown; a `403` means the leaf exists but a **different** DID
submitted it.

## Failure modes

- `400 invalid signature hex`: your `signature` field wasn't valid
  hex, or the byte length didn't match the DID's curve (65 for
  eip155, 64 for the others).
- `401 challenge not found`: the nonce was already consumed (each
  challenge is single-use) or never issued; request a fresh challenge.
- `401 challenge expired`: more than 5 minutes elapsed between
  `/auth/challenge` and `/auth/session`; request a fresh challenge.
- `401 signature did not verify`: the signature didn't recover /
  validate against the DID's public key. Common causes: signed the
  JSON envelope instead of the `message` field; forgot the EIP-191
  prefix for eip155; signed with a different key than the one your
  DID was derived from.
- `401 missing Authorization: Bearer ...` (on protected endpoints):
  no bearer at all; re-run the dance.
- `401 invalid or expired session token`: bearer too old (>1 h by
  default), or never issued; re-run the dance.

## Lifetimes

- **Challenge:** single-use, 5-minute TTL.
- **Bearer / session:** 1-hour TTL by default
  ([`auth.session_ttl_secs`](https://github.com/inblockio/aqua-timestamps/blob/main/deploy/config.toml)
  on the server); refresh by repeating the three-step dance when it
  expires. Sessions are revoked on a normal server restart (the
  store is in-memory).

## Reference implementation

A complete worked example in Rust (all three DID methods) lives at
[`crates/aqua-timestamp-e2e/src/flow.rs`](https://github.com/inblockio/aqua-timestamps/blob/main/crates/aqua-timestamp-e2e/src/flow.rs)
under `mint_bearer` + `ClientKey::sign_challenge`.
