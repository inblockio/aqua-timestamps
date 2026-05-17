//! Self-served documentation for human and agent integrators.
//!
//! The deployment publishes two artefacts so any other agent can
//! self-bootstrap against this service without an out-of-band manual:
//!
//! * `GET /docs/skill.md` returns [`SKILL_MD`] verbatim. The format is the
//!   same shape Claude (and any other agent honoring the convention)
//!   already consumes for `~/.claude/skills/<name>/SKILL.md`: YAML
//!   front-matter with `name` / `description` / `version` followed by
//!   markdown body. An agent can drop the response into its own skill
//!   library and learn how to call this service unattended.
//!
//! * `GET /docs` returns [`HTML`] — a browser-friendly rendering of the
//!   same content for humans. Single-file HTML, no JS, no external
//!   assets.
//!
//! The HTML and the markdown are intentionally hand-kept in parallel
//! rather than rendered at build time. The substantive content lives
//! in [`SKILL_MD`]; the [`HTML`] page is a styled mirror so casual
//! browsers don't need a markdown renderer.
//!
//! Both endpoints are public (no auth). The DNS / IP / server DID
//! values are stamped into the live response by [`render_html`] /
//! [`render_skill_md`] at request time from the loaded identity, so a
//! reverse-proxy / private deploy reads correctly without an edit.

use crate::identity::ServiceIdentity;

/// Server-side skill markdown template. The `{...}` placeholders are
/// substituted at request time so an operator who deploys at a
/// different DNS name picks up the right URLs and DID values without a
/// recompile.
const SKILL_TEMPLATE: &str = r##"---
name: aqua-timestamp-client
description: Use when an agent needs to obtain a tamper-evident timestamp witness for any 32-byte hash, dual-anchored to an EVM chain (Sepolia) AND an eIDAS-qualified RFC 3161 TSA, against the aqua-timestamp aggregator at {BASE_URL}. Covers SIWE / CAIP-122 authentication for `eip155` / `ed25519` / `p256` DIDs, leaf submission, polling for epoch seal, witness retrieval, signature + Merkle verification, and identity / server verification via `/.well-known/aqua-identity`.
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

## Authentication (CAIP-122 / SIWE)

Three DID methods are accepted:

- `did:pkh:eip155:1:0x{EIP-55 address}` — secp256k1 + EIP-191
  personal_sign over Keccak-256 prehash, 65-byte `r||s||v` signature
  (`v = recovery_id + 27`).
- `did:pkh:ed25519:0x{32-byte pubkey hex}` — raw Ed25519 sign over the
  challenge bytes, 64-byte signature.
- `did:pkh:p256:0x{33-byte compressed pubkey hex}` — P-256 ECDSA over
  the challenge bytes, 64-byte fixed-size encoding (DER also accepted).

### Step 1: request a challenge

```sh
curl -sS '{BASE_URL}/auth/challenge?did=did:pkh:eip155:1:0xYOUR_ADDRESS'
```

Response:

```json
{
  "nonce": "0x<32-byte hex>",
  "message": "<CAIP-122 message text to sign>",
  "expires_at": <unix seconds>
}
```

The challenge has a five-minute TTL and is single-use. The message
follows the SIWE shape; for `eip155` it has a `Chain ID: 1` trailer,
for `ed25519` / `p256` it does not.

### Step 2: sign the message and post a session

```sh
curl -sS -X POST {BASE_URL}/auth/session \
  -H 'content-type: application/json' \
  -d '{"did":"did:pkh:eip155:1:0xYOUR_ADDRESS","nonce":"0x...","signature":"0x..."}'
```

Response:

```json
{
  "token": "<opaque 64-char hex>",
  "did":   "did:pkh:eip155:1:0xYOUR_ADDRESS",
  "valid_until": <unix>,
  "created_at": <unix>
}
```

The bearer is opaque hex, valid one hour by default. Carry it in
`Authorization: Bearer {token}` for every authenticated request.

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
  or expired. Re-run the challenge + session dance.
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
[aqua-timestamp-e2e](https://github.com/inblockio/aqua-timestamp/tree/main/crates/aqua-timestamp-e2e).
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
| `GET /docs` | public | this guide (HTML) |
| `GET /docs/skill.md` | public | this guide (raw markdown for agent consumption) |
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

AGPL-3.0. Source at <https://github.com/inblockio/aqua-timestamp>.
"##;

/// HTML rendering of the same content. Browser-friendly, single-file,
/// no JS, no external assets. The `{...}` placeholders mirror the
/// markdown template so both stay in sync at render time.
const HTML_TEMPLATE: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Agent integration · aqua-timestamp · {DNS}</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
         Helvetica, Arial, sans-serif; max-width: 50rem; margin: 3rem auto;
         padding: 0 1.25rem; line-height: 1.55; }
  h1 { margin-bottom: 0.25rem; }
  h2 { margin-top: 2rem; border-top: 1px solid rgba(127,127,127,0.2);
       padding-top: 1.5rem; }
  h3 { margin-top: 1.5rem; }
  .sub { color: #777; margin-top: 0; }
  code { background: rgba(127,127,127,0.15); padding: 0.1rem 0.35rem;
         border-radius: 3px; font-size: 0.95em; }
  pre { background: rgba(127,127,127,0.1); padding: 0.75rem 1rem;
        border-radius: 4px; overflow-x: auto; font-size: 0.9em; }
  pre code { background: none; padding: 0; }
  table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
  th, td { text-align: left; padding: 0.35rem 0.6rem;
           border-bottom: 1px solid rgba(127,127,127,0.2); font-size: 0.95em; }
  th { background: rgba(127,127,127,0.07); }
  ul { padding-left: 1.25rem; }
  footer { margin-top: 3rem; color: #888; font-size: 0.9rem;
           border-top: 1px solid rgba(127,127,127,0.2); padding-top: 1rem; }
  a { color: #1a73e8; }
  .pill { display: inline-block; padding: 0.1rem 0.45rem;
          background: rgba(26,115,232,0.12); color: #1a73e8;
          border-radius: 999px; font-size: 0.8em; margin-left: 0.4rem;
          vertical-align: middle; }
</style>
</head>
<body>
  <h1>Agent integration <span class="pill">aqua-timestamp</span></h1>
  <p class="sub">How to obtain dual-anchored (EVM + eIDAS-qualified qTSA)
  timestamp witnesses from <a href="{BASE_URL}">{DNS}</a> as an automated
  client.</p>

  <p>This page mirrors the machine-readable skill at
  <a href="/docs/skill.md"><code>GET /docs/skill.md</code></a> in the
  same format Claude (and any other agent honoring the convention)
  consumes for <code>~/.claude/skills/&lt;name&gt;/SKILL.md</code>.
  A client can fetch that URL and drop it into its own skill library
  to learn how to call this service unattended.</p>

  <h2>What this service does</h2>
  <p>Submit a 32-byte hash. Get back two signed witness revisions: one
  anchored to Sepolia (cryptographic proof of existence) and one
  anchored to a Sectigo-qualified RFC 3161 TSA (legal / eIDAS proof of
  existence). Both chain off the hash you submitted via
  <code>previous_revision</code>, so they merge directly into your
  existing Aqua tree without rebasing the genesis.</p>

  <ul>
    <li>Base URL: <code>{BASE_URL}</code></li>
    <li>Server identity DID: <code>{SERVER_DID}</code></li>
    <li>DNS / IP: <code>{DNS}</code> / <code>{IP}</code></li>
  </ul>

  <h2>1. Pin the server identity (do this once)</h2>
  <p>Before trusting any witness, verify the server's published identity
  claim and add its DID to your trust store:</p>
<pre><code>curl -sS {BASE_URL}/.well-known/aqua-identity &gt; server-identity.json</code></pre>
  <p>The response carries a valid Aqua tree:
  <code>anchor -&gt; service_claim_server object -&gt; EIP-191 Signature</code>,
  signed by the server's secp256k1 key. Verify it with
  <code>aqua-rs-sdk</code>'s tree verifier; on success, pin
  <code>server_did</code> and never trust an unsigned witness again.</p>

  <h2>2. Authenticate (CAIP-122 / SIWE)</h2>
  <p>Three DID methods are accepted:</p>
  <table>
    <tr><th>DID format</th><th>Curve</th><th>Signature shape</th></tr>
    <tr><td><code>did:pkh:eip155:1:0x{40 hex}</code></td><td>secp256k1</td><td>65-byte EIP-191 (r||s||v)</td></tr>
    <tr><td><code>did:pkh:ed25519:0x{64 hex}</code></td><td>Ed25519</td><td>64-byte raw</td></tr>
    <tr><td><code>did:pkh:p256:0x{66 hex}</code></td><td>P-256 (NIST)</td><td>64-byte fixed (DER also OK)</td></tr>
  </table>
  <p>Request a challenge, sign the <code>message</code> field, post the
  signature back, get a bearer:</p>
<pre><code>curl -sS '{BASE_URL}/auth/challenge?did=did:pkh:eip155:1:0xYOUR_ADDRESS'

curl -sS -X POST {BASE_URL}/auth/session \
  -H 'content-type: application/json' \
  -d '{"did":"did:pkh:...","nonce":"0x...","signature":"0x..."}'</code></pre>
  <p>The bearer is opaque hex, 1 hour TTL. Carry it in
  <code>Authorization: Bearer &lt;token&gt;</code>.</p>

  <h2>3. Submit a leaf</h2>
<pre><code>curl -sS -X POST {BASE_URL}/v1/leaves \
  -H 'authorization: Bearer &lt;token&gt;' \
  -H 'content-type: application/json' \
  -d '{"leaves":["0x&lt;64 hex&gt;"]}'</code></pre>
  <p>Up to 10000 hashes per request. Each leaf is 32 bytes (64 hex,
  optional <code>0x</code>). The response carries
  <code>epoch_id</code> and <code>epoch_closes_at</code>; your leaf is
  guaranteed to land in either that epoch or the next one.</p>

  <h2>4. Wait for the seal</h2>
<pre><code>curl -sS {BASE_URL}/v1/schedule</code></pre>
  <p>Poll until <code>last_sealed_epoch_id &gt;= your_epoch_id</code>.
  The default epoch is 10 minutes. A safe poll ceiling is
  <code>2 &times; (epoch_closes_at - now) + 30 s</code>.</p>

  <h2>5. Fetch the witnesses</h2>
<pre><code>curl -sS -H 'authorization: Bearer &lt;token&gt;' \
  '{BASE_URL}/trees/by-leaf/0x&lt;leaf&gt;?method=evm'
curl -sS -H 'authorization: Bearer &lt;token&gt;' \
  '{BASE_URL}/trees/by-leaf/0x&lt;leaf&gt;?method=qtsa'</code></pre>
  <p>Each response is an aqua-node-compatible <code>Tree</code>:
  <code>{ revisions: BTreeMap, file_index: BTreeMap }</code>.
  Deserialise directly into
  <code>aqua_rs_sdk::schema::tree::Tree</code>. <code>404</code> means
  the leaf is unknown; <code>403</code> means the leaf exists but
  another DID submitted it.</p>

  <h2>6. Verify offline</h2>
  <p>Run three checks against every witness before trusting it:</p>
  <ul>
    <li><strong>L1 (revision integrity):</strong> hash each revision's
    JSON with the SDK's <code>Linkable::calculate_link</code>; assert
    the result equals the map key.</li>
    <li><strong>L2 (Merkle inclusion):</strong> call
    <code>verify_inclusion(leaf, idx, size, &amp;proof, &amp;root,
    HashType::Sha3_256)</code> from
    <code>aqua_rs_sdk::primitives::merkle</code>. The
    <code>payloads.merkle_root</code> / <code>merkle_proof</code> /
    <code>batch_tree_size</code> / <code>batch_leaf_index</code> fields
    of the TimestampObject revision feed in directly.</li>
    <li><strong>L3 (server signature):</strong> ecrecover the Signature
    revision's <code>signature</code> blob against
    <code>signature.pre_signature_canonical_json()</code>; assert the
    recovered EIP-55 address equals the address baked into the pinned
    <code>server_did</code>. This is the trust-load-bearing check.</li>
  </ul>
  <p>EVM extras: the on-chain <code>transaction_hash</code> can be
  cross-checked against the Sepolia RPC; the call data is
  <code>0x114ee197</code> (function selector
  <code>witness(bytes32)</code>) followed by the Merkle root.</p>
  <p>qTSA extras: the <code>transaction_hash</code> field is the
  base64-encoded RFC 3161 TimeStampResp DER. Verify it under the
  Sectigo Qualified Time Stamping Root R45; the certificatePolicies OID
  <code>1.3.6.1.4.1.6449.1.2.1.9.1</code> confirms eIDAS-qualified
  status.</p>

  <h2>Endpoint catalogue</h2>
  <table>
    <tr><th>Endpoint</th><th>Auth</th><th>Purpose</th></tr>
    <tr><td><a href="/.well-known/aqua-identity"><code>GET /.well-known/aqua-identity</code></a></td><td>public</td><td>server identity claim (signed Aqua tree); pin once</td></tr>
    <tr><td><a href="/docs"><code>GET /docs</code></a></td><td>public</td><td>this guide (HTML)</td></tr>
    <tr><td><a href="/docs/skill.md"><code>GET /docs/skill.md</code></a></td><td>public</td><td>this guide (raw markdown for agent consumption)</td></tr>
    <tr><td><a href="/health"><code>GET /health</code></a></td><td>public</td><td>liveness + uptime</td></tr>
    <tr><td><a href="/v1/schedule"><code>GET /v1/schedule</code></a></td><td>public</td><td>current / last-sealed epoch state</td></tr>
    <tr><td><code>GET /auth/challenge?did=...</code></td><td>public</td><td>CAIP-122 challenge</td></tr>
    <tr><td><code>POST /auth/session</code></td><td>public</td><td>exchange signed challenge for bearer</td></tr>
    <tr><td><code>POST /v1/leaves</code></td><td>bearer</td><td>submit hashes for the current epoch</td></tr>
    <tr><td><code>GET /v1/epochs</code></td><td>bearer</td><td>paginated epoch history</td></tr>
    <tr><td><code>GET /trees</code></td><td>bearer</td><td>tips owned by caller DID</td></tr>
    <tr><td><code>GET /trees/{tip}</code></td><td>bearer</td><td>aqua-node compatible witness fetch by tip</td></tr>
    <tr><td><code>GET /trees/by-leaf/{leaf}?method=evm|qtsa</code></td><td>bearer</td><td>witness fetch by submitted leaf</td></tr>
    <tr><td><code>GET /trees?epoch=N&amp;method=evm|qtsa</code></td><td>bearer</td><td>witnesses for caller's leaves in epoch N</td></tr>
  </table>

  <h2>Reference client</h2>
  <p>A complete reference client (Rust) lives at
  <a href="https://github.com/inblockio/aqua-timestamp/tree/main/crates/aqua-timestamp-e2e">crates/aqua-timestamp-e2e</a>
  in the project repo. It runs the full flow + verification against
  this deployment for all three DID methods.</p>

  <footer>
    aqua-timestamp · <a href="https://github.com/inblockio/aqua-timestamp">github.com/inblockio/aqua-timestamp</a> · AGPL-3.0 · operated by <a href="https://inblock.io">inblock.io</a>
  </footer>
</body>
</html>
"##;

/// Build the rendered skill markdown for the live deployment.
pub fn render_skill_md(identity: &ServiceIdentity) -> String {
    let base_url = format!("https://{}", identity.dns);
    SKILL_TEMPLATE
        .replace("{BASE_URL}", &base_url)
        .replace("{SERVER_DID}", &identity.server_did)
        .replace("{DNS}", &identity.dns)
        .replace("{IP}", &identity.ip)
}

/// Build the rendered HTML guide for the live deployment.
pub fn render_html(identity: &ServiceIdentity) -> String {
    let base_url = format!("https://{}", identity.dns);
    HTML_TEMPLATE
        .replace("{BASE_URL}", &base_url)
        .replace("{SERVER_DID}", &identity.server_did)
        .replace("{DNS}", &identity.dns)
        .replace("{IP}", &identity.ip)
}
