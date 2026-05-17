pub const HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Aqua Aggregator · timestamp.inblock.io</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
         Helvetica, Arial, sans-serif; max-width: 44rem; margin: 3rem auto;
         padding: 0 1.25rem; line-height: 1.55; }
  h1 { margin-bottom: 0.25rem; }
  .sub { color: #666; margin-top: 0; }
  code { background: rgba(127,127,127,0.15); padding: 0.1rem 0.35rem;
         border-radius: 3px; font-size: 0.95em; }
  ul { padding-left: 1.25rem; }
  .cta { background: rgba(26,115,232,0.07); border-left: 3px solid #1a73e8;
         padding: 0.75rem 1rem; margin: 1.25rem 0; border-radius: 3px; }
  footer { margin-top: 3rem; color: #888; font-size: 0.9rem; }
  a { color: #1a73e8; }
</style>
</head>
<body>
  <h1>Aqua Aggregator</h1>
  <p class="sub">A high-throughput timestamping service for the Aqua Protocol.</p>

  <p>This service batches revision hashes from Aqua-enabled clients into
  Merkle trees and dual-anchors them per epoch to both an EVM blockchain
  (Sepolia) and an eIDAS-qualified RFC 3161 TSA. Each submitted leaf is
  returned a witness revision pair (<code>TimestampObject</code> +
  <code>Signature</code>) that chains directly off the client's tip.</p>

  <p>Operated by <a href="https://inblock.io">inblock.io</a>.</p>

  <div class="cta">
    <strong>Integrating an agent or client?</strong> Read
    <a href="/docs"><code>/docs</code></a> (or fetch the same content as a
    machine-readable skill at
    <a href="/.well-known/aqua-skill.md"><code>/.well-known/aqua-skill.md</code></a>,
    with the SIWE auth deep-dive at
    <a href="/.well-known/aqua-skill-auth.md"><code>/.well-known/aqua-skill-auth.md</code></a>).
    Covers SIWE authentication for <code>eip155</code> / <code>ed25519</code> /
    <code>p256</code> DIDs, leaf submission, witness retrieval, and
    offline verification.
  </div>

  <h2>Server identity</h2>
  <p>Before trusting any witness from this service, verify the published
  identity claim and pin the resulting DID:</p>
  <ul>
    <li><a href="/.well-known/aqua-identity"><code>GET /.well-known/aqua-identity</code></a>
    — service identity claim, a self-signed Aqua tree
    (<code>anchor → service_claim_server → EIP-191 signature</code>).
    Verify with <code>aqua-rs-sdk</code> before adding
    <code>server_did</code> to your trust store.</li>
  </ul>

  <h2>Endpoints</h2>
  <ul>
    <li><a href="/docs"><code>GET /docs</code></a> — agent integration guide (HTML)</li>
    <li><a href="/.well-known/aqua-skill.md"><code>GET /.well-known/aqua-skill.md</code></a> — main agent skill (raw markdown)</li>
    <li><a href="/.well-known/aqua-skill-auth.md"><code>GET /.well-known/aqua-skill-auth.md</code></a> — SIWE auth deep-dive (raw markdown)</li>
    <li><a href="/.well-known/aqua-identity"><code>GET /.well-known/aqua-identity</code></a> — service identity claim</li>
    <li><a href="/health"><code>GET /health</code></a> — health and uptime</li>
    <li><a href="/v1/schedule"><code>GET /v1/schedule</code></a> — current / last-sealed epoch</li>
    <li><code>POST /v1/leaves</code> — submit hashes (bearer-gated)</li>
    <li><code>GET /trees/by-leaf/{leaf}?method=evm|qtsa</code> — fetch witness (bearer-gated)</li>
  </ul>

  <h2>Source</h2>
  <p><a href="https://github.com/inblockio/aqua-timestamp">github.com/inblockio/aqua-timestamp</a></p>

  <footer>aqua-timestamp · dual-anchor: Sepolia + Sectigo qualified TSA · AGPL-3.0</footer>
</body>
</html>
"##;
