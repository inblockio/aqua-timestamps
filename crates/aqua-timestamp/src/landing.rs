pub const HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Aqua Aggregator — timestamp.inblock.io</title>
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
  footer { margin-top: 3rem; color: #888; font-size: 0.9rem; }
  a { color: #1a73e8; }
</style>
</head>
<body>
  <h1>Aqua Aggregator</h1>
  <p class="sub">A high-throughput timestamping service for the Aqua Protocol.</p>

  <p>This service batches revision hashes from Aqua-enabled clients into
  Merkle trees and dual-anchors them per epoch to both an EVM blockchain
  (Sepolia at present) and an eIDAS-qualified TSA. Each submitted leaf is
  returned a witness revision pair (<code>TimestampObject</code> +
  <code>Signature</code>) that chains directly off the client's tip.</p>

  <p>Operated by <a href="https://inblock.io">inblock.io</a>.</p>

  <h2>Endpoints</h2>
  <ul>
    <li><a href="/health"><code>GET /health</code></a> — health and uptime</li>
    <li><a href="/.well-known/aqua-identity"><code>GET /.well-known/aqua-identity</code></a> — service identity claim (signed Aqua tree)</li>
  </ul>

  <h2>Source</h2>
  <p><a href="https://github.com/inblockio/aqua-timestamp">github.com/inblockio/aqua-timestamp</a></p>

  <footer>aqua-timestamp · M0 skeleton · AGPL-3.0</footer>
</body>
</html>
"##;
