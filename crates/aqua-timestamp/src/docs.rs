//! Self-served documentation for human and agent integrators.
//!
//! The deployment publishes three artefacts so any other agent can
//! self-bootstrap against this service without an out-of-band manual:
//!
//! * `GET /.well-known/aqua-skill.md` returns the main agent skill,
//!   slim. YAML front-matter with `name` / `description` / `version`
//!   followed by markdown body, the same shape Claude (and any other
//!   agent honoring the convention) consumes for
//!   `~/.claude/skills/<name>/SKILL.md`. An agent can drop the
//!   response into its own skill library and learn how to call this
//!   service unattended.
//!
//! * `GET /.well-known/aqua-skill-auth.md` returns the SIWE / CAIP-122
//!   authentication deep-dive (sub-article). Linked from the main
//!   skill so the high-level overview stays compact while the full
//!   per-curve signing recipe stays one fetch away.
//!
//! * `GET /docs` returns a browser-friendly HTML rendering of the
//!   same content for humans. Single-file HTML, no JS, no external
//!   assets.
//!
//! Both markdown surfaces are `include_str!`-imported from the repo
//! sources under `docs/`, so the canonical content is browseable on
//! GitHub and the binary stays in lock-step with it. The HTML is
//! hand-kept in parallel; a future markdown-rendering dep could
//! replace it.
//!
//! All three endpoints are public (no auth). The DNS / IP / server DID
//! values are stamped into the live response at boot from the loaded
//! identity, so a reverse-proxy / private deploy reads correctly
//! without an edit.

use crate::identity::ServiceIdentity;

/// Main agent skill. Source of truth: `docs/aqua-skill.md` in the repo.
const SKILL_TEMPLATE: &str = include_str!("../../../docs/aqua-skill.md");

/// SIWE / CAIP-122 authentication deep-dive. Source of truth:
/// `docs/swix-authentication.md` in the repo. Linked from the main
/// skill.
const SKILL_AUTH_TEMPLATE: &str = include_str!("../../../docs/swix-authentication.md");

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
  <a href="/.well-known/aqua-skill.md"><code>GET /.well-known/aqua-skill.md</code></a>
  (with the SIWE auth deep-dive at
  <a href="/.well-known/aqua-skill-auth.md"><code>/.well-known/aqua-skill-auth.md</code></a>),
  in the same format Claude (and any other agent honoring the
  convention) consumes for <code>~/.claude/skills/&lt;name&gt;/SKILL.md</code>.
  A client can fetch those URLs and drop them into its own skill
  library to learn how to call this service unattended.</p>

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

  <h2>2. Authenticate with the API (CAIP-122 / SIWE)</h2>
  <p><strong>Every protected endpoint requires a bearer token in the
  <code>Authorization: Bearer &lt;token&gt;</code> header.</strong>
  Obtain one by signing a CAIP-122 challenge with the same private key
  your DID is derived from. Three HTTP calls: challenge -&gt; sign
  locally -&gt; session -&gt; bearer. No shared secrets, no API keys.</p>

  <p>Quickstart (eip155 example):</p>
<pre><code>curl -sS '{BASE_URL}/auth/challenge?did=did:pkh:eip155:1:0xYOUR_ADDRESS'
#   -&gt; { "nonce": "0x...", "message": "...", "expires_at": ... }

# Sign the `message` bytes locally with your DID's key.
# (See the deep-dive for the exact prehash / encoding per curve.)

curl -sS -X POST {BASE_URL}/auth/session \
  -H 'content-type: application/json' \
  -d '{"did":"did:pkh:...","nonce":"0x...","signature":"0x..."}'
#   -&gt; { "token": "...", "did": "...", "valid_until": ... }

curl -sS -H 'authorization: Bearer &lt;token&gt;' ...
</code></pre>

  <p><strong>Deep-dive (read this before implementing):</strong>
  <a href="/.well-known/aqua-skill-auth.md"><code>/.well-known/aqua-skill-auth.md</code></a>
  &mdash; accepted DID methods (<code>eip155</code>, <code>ed25519</code>,
  <code>p256</code>), per-curve signing recipe with working Rust
  snippets, failure-mode catalogue, lifetimes, reference implementation
  pointer.</p>

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
    <tr><td><a href="/.well-known/aqua-skill.md"><code>GET /.well-known/aqua-skill.md</code></a></td><td>public</td><td>main agent skill (markdown, machine-readable)</td></tr>
    <tr><td><a href="/.well-known/aqua-skill-auth.md"><code>GET /.well-known/aqua-skill-auth.md</code></a></td><td>public</td><td>SIWE / CAIP-122 authentication deep-dive</td></tr>
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
  <a href="https://github.com/inblockio/aqua-timestamps/tree/main/crates/aqua-timestamp-e2e">crates/aqua-timestamp-e2e</a>
  in the project repo. It runs the full flow + verification against
  this deployment for all three DID methods.</p>

  <footer>
    aqua-timestamp · <a href="https://github.com/inblockio/aqua-timestamps">github.com/inblockio/aqua-timestamps</a> · Apache-2.0 · operated by <a href="https://inblock.io">inblock.io</a>
  </footer>
</body>
</html>
"##;

/// Build the rendered skill markdown for the live deployment.
pub fn render_skill_md(identity: &ServiceIdentity) -> String {
    substitute(SKILL_TEMPLATE, identity)
}

/// Build the rendered SIWE / CAIP-122 authentication deep-dive for the
/// live deployment. Served at `/.well-known/aqua-skill-auth.md`.
pub fn render_skill_auth_md(identity: &ServiceIdentity) -> String {
    substitute(SKILL_AUTH_TEMPLATE, identity)
}

/// Build the rendered HTML guide for the live deployment.
pub fn render_html(identity: &ServiceIdentity) -> String {
    substitute(HTML_TEMPLATE, identity)
}

/// Substitute `{BASE_URL}` / `{SERVER_DID}` / `{DNS}` / `{IP}` in any
/// template against the loaded identity.
fn substitute(template: &str, identity: &ServiceIdentity) -> String {
    let base_url = format!("https://{}", identity.dns);
    template
        .replace("{BASE_URL}", &base_url)
        .replace("{SERVER_DID}", &identity.server_did)
        .replace("{DNS}", &identity.dns)
        .replace("{IP}", &identity.ip)
}
