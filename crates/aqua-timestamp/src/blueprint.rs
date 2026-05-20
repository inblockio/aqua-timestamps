pub const HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Blueprint for Trusted Institutions &middot; OpenWitness.org</title>
<link rel="icon" href="/favicon.ico" type="image/x-icon" />
<link rel="apple-touch-icon" href="/apple-touch-icon.png" />
<style>
@import url('https://fonts.googleapis.com/css2?family=Sora:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --accent: #5B9BD5;
  --accent-hover: #4889BF;
  --proof-green: #2a8a5a;
  --enforce-amber: #d97706;
  --sans: 'Sora', sans-serif;
  --mono: 'JetBrains Mono', monospace;

  --bg: #0f0f13;
  --surface: #1a1a20;
  --text: #e4e4e7;
  --border: #2a2a32;
  --dim: #71717a;
}

@media (prefers-color-scheme: light) {
  :root {
    --bg: #fafaf9;
    --surface: #ffffff;
    --text: #1c1917;
    --border: #e7e5e4;
    --dim: #78716c;
  }
}

html { scroll-behavior: smooth; }

body {
  font-family: var(--sans);
  background: var(--bg);
  color: var(--text);
  line-height: 1.7;
  -webkit-font-smoothing: antialiased;
}

a { color: var(--accent); text-decoration: none; }
a:hover { color: var(--accent-hover); text-decoration: underline; }

code, .mono {
  font-family: var(--mono);
  font-size: 0.875em;
}

.container {
  max-width: 900px;
  margin: 0 auto;
  padding: 0 1.5rem;
}

/* ── Header bar ─────────────────────────────────────────────────── */

.top-bar {
  padding: 1rem 0;
  border-bottom: 1px solid var(--border);
}

.top-bar .container {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.top-bar-brand {
  font-family: var(--mono);
  font-size: 0.8rem;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  color: var(--accent);
}

.top-bar-nav {
  margin-left: auto;
  display: flex;
  gap: 1.25rem;
  font-size: 0.85rem;
}

/* ── Hero ────────────────────────────────────────────────────────── */

.bp-hero {
  padding: 4.5rem 0 3.5rem;
  text-align: center;
  position: relative;
  overflow: hidden;
}

.bp-hero::before {
  content: '';
  position: absolute;
  inset: 0;
  background-image: radial-gradient(circle at 1px 1px, var(--border) 1px, transparent 0);
  background-size: 40px 40px;
  mask-image: radial-gradient(ellipse 60% 50% at 50% 30%, black 0%, transparent 70%);
  -webkit-mask-image: radial-gradient(ellipse 60% 50% at 50% 30%, black 0%, transparent 70%);
  opacity: 0.35;
  pointer-events: none;
}

.bp-hero h1 {
  font-size: clamp(1.8rem, 4vw, 2.8rem);
  font-weight: 700;
  letter-spacing: -0.02em;
  line-height: 1.15;
  position: relative;
}

.bp-hero .subtitle {
  font-size: 1.05rem;
  color: var(--dim);
  margin-top: 1rem;
  max-width: 640px;
  margin-left: auto;
  margin-right: auto;
  position: relative;
}

/* ── Sections ────────────────────────────────────────────────────── */

section {
  padding: 3.5rem 0;
}

section + section {
  border-top: 1px solid var(--border);
}

.section-eyebrow {
  font-family: var(--mono);
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.14em;
  color: var(--accent);
  margin-bottom: 0.5rem;
}

section h2 {
  font-size: 1.5rem;
  font-weight: 700;
  margin-bottom: 0.75rem;
  letter-spacing: -0.01em;
}

section h3 {
  font-size: 1.15rem;
  font-weight: 600;
  margin-top: 2rem;
  margin-bottom: 0.5rem;
}

section p {
  margin-bottom: 1rem;
  color: var(--text);
}

section p.dim {
  color: var(--dim);
}

/* ── Stack diagram ───────────────────────────────────────────────── */

.stack-diagram {
  display: flex;
  flex-direction: column;
  gap: 0;
  margin: 2.5rem 0;
  position: relative;
}

.stack-layer {
  display: grid;
  grid-template-columns: 140px 1fr;
  align-items: stretch;
  min-height: 72px;
}

.stack-label {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  padding-right: 1.25rem;
  font-family: var(--mono);
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--dim);
}

.stack-content {
  background: var(--surface);
  border: 1px solid var(--border);
  padding: 1rem 1.25rem;
  display: flex;
  align-items: center;
  gap: 1.5rem;
  flex-wrap: wrap;
}

.stack-layer:first-child .stack-content {
  border-radius: 10px 10px 0 0;
}

.stack-layer:last-child .stack-content {
  border-radius: 0 0 10px 10px;
}

.stack-layer:not(:first-child) .stack-content {
  border-top: none;
}

.stack-tag {
  font-size: 0.82rem;
  font-weight: 500;
  padding: 0.2rem 0.6rem;
  border-radius: 6px;
  white-space: nowrap;
}

.stack-tag.blue {
  background: rgba(91, 155, 213, 0.12);
  color: var(--accent);
  border: 1px solid rgba(91, 155, 213, 0.25);
}

.stack-tag.green {
  background: rgba(42, 138, 90, 0.08);
  color: var(--proof-green);
  border: 1px solid rgba(42, 138, 90, 0.2);
}

.stack-tag.amber {
  background: rgba(217, 119, 6, 0.08);
  color: var(--enforce-amber);
  border: 1px solid rgba(217, 119, 6, 0.2);
}

.stack-tag.dim {
  background: rgba(113, 113, 122, 0.08);
  color: var(--dim);
  border: 1px solid rgba(113, 113, 122, 0.2);
}

.stack-desc {
  font-size: 0.82rem;
  color: var(--dim);
}

/* ── Flow diagrams ───────────────────────────────────────────────── */

.flow {
  display: flex;
  align-items: stretch;
  gap: 0;
  margin: 2rem 0;
  overflow-x: auto;
  padding-bottom: 0.5rem;
}

.flow-step {
  flex: 1;
  min-width: 140px;
  background: var(--surface);
  border: 1px solid var(--border);
  padding: 1rem;
  text-align: center;
  position: relative;
}

.flow-step:first-child {
  border-radius: 10px 0 0 10px;
}

.flow-step:last-child {
  border-radius: 0 10px 10px 0;
}

.flow-step:not(:first-child) {
  border-left: none;
}

.flow-step::after {
  content: '\2192';
  position: absolute;
  right: -0.55rem;
  top: 50%;
  transform: translateY(-50%);
  font-size: 1rem;
  color: var(--accent);
  z-index: 1;
  background: var(--bg);
  width: 1.1rem;
  text-align: center;
  line-height: 1;
}

.flow-step:last-child::after {
  display: none;
}

.flow-step .step-num {
  font-family: var(--mono);
  font-size: 0.65rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--accent);
  display: block;
  margin-bottom: 0.3rem;
}

.flow-step .step-title {
  font-weight: 600;
  font-size: 0.85rem;
  margin-bottom: 0.25rem;
}

.flow-step .step-detail {
  font-size: 0.75rem;
  color: var(--dim);
  line-height: 1.4;
}

/* ── Key hierarchy ───────────────────────────────────────────────── */

.key-tree {
  margin: 2rem 0;
  padding: 1.5rem;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  font-family: var(--mono);
  font-size: 0.8rem;
  line-height: 2;
  overflow-x: auto;
}

.key-tree .root { color: var(--accent); font-weight: 600; }
.key-tree .branch { color: var(--proof-green); }
.key-tree .leaf { color: var(--dim); }
.key-tree .note { color: var(--dim); font-size: 0.72rem; }

/* ── Causal chain ────────────────────────────────────────────────── */

.causal-chain {
  margin: 2rem 0;
  padding: 0 0 0 1.5rem;
  border-left: 3px solid var(--accent);
}

.causal-link {
  padding: 0.6rem 0;
  position: relative;
}

.causal-link::before {
  content: '';
  position: absolute;
  left: -1.75rem;
  top: 1rem;
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: var(--accent);
}

.causal-if {
  font-family: var(--mono);
  font-size: 0.78rem;
  color: var(--accent);
}

.causal-then {
  font-size: 0.88rem;
  margin-left: 0.5rem;
}

/* ── Comparison table ────────────────────────────────────────────── */

.bp-table {
  width: 100%;
  border-collapse: collapse;
  margin: 1.5rem 0;
  font-size: 0.88rem;
}

.bp-table th {
  text-align: left;
  font-weight: 600;
  padding: 0.6rem 0.75rem;
  border-bottom: 2px solid var(--border);
  font-size: 0.82rem;
}

.bp-table td {
  padding: 0.6rem 0.75rem;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}

.bp-table tr:last-child td {
  border-bottom: none;
}

/* ── Gap cards ───────────────────────────────────────────────────── */

.gap-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 1rem;
  margin: 1.5rem 0;
}

.gap-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 1.25rem;
}

.gap-card .gap-title {
  font-weight: 600;
  font-size: 0.92rem;
  margin-bottom: 0.4rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.gap-card .gap-status {
  font-family: var(--mono);
  font-size: 0.65rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  padding: 0.15rem 0.45rem;
  border-radius: 4px;
}

.gap-status.open {
  background: rgba(217, 119, 6, 0.1);
  color: var(--enforce-amber);
  border: 1px solid rgba(217, 119, 6, 0.2);
}

.gap-status.deferred {
  background: rgba(113, 113, 122, 0.1);
  color: var(--dim);
  border: 1px solid rgba(113, 113, 122, 0.2);
}

.gap-card .gap-body {
  font-size: 0.82rem;
  color: var(--dim);
  line-height: 1.5;
}

/* ── Principle pills ─────────────────────────────────────────────── */

.principle-row {
  display: flex;
  gap: 0.75rem;
  flex-wrap: wrap;
  margin: 1.5rem 0;
}

.principle-pill {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  font-size: 0.82rem;
  font-weight: 500;
  padding: 0.4rem 0.85rem;
  border-radius: 8px;
  background: var(--surface);
  border: 1px solid var(--border);
}

.principle-pill .dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--accent);
  flex-shrink: 0;
}

/* ── Blockquote ──────────────────────────────────────────────────── */

blockquote {
  border-left: 3px solid var(--accent);
  padding: 1rem 1.25rem;
  margin: 1.5rem 0;
  background: var(--surface);
  border-radius: 0 8px 8px 0;
  font-size: 0.92rem;
}

blockquote p {
  margin-bottom: 0.5rem;
}

blockquote p:last-child {
  margin-bottom: 0;
}

/* ── Two-domain diagram ──────────────────────────────────────────── */

.two-domains {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
  margin: 2rem 0;
}

.domain-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 1.25rem;
}

.domain-card h4 {
  font-size: 0.92rem;
  font-weight: 600;
  margin-bottom: 0.5rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.domain-card h4 .tag {
  font-family: var(--mono);
  font-size: 0.62rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  padding: 0.12rem 0.4rem;
  border-radius: 4px;
}

.domain-card ul {
  list-style: none;
  padding: 0;
}

.domain-card li {
  font-size: 0.82rem;
  color: var(--dim);
  padding: 0.25rem 0;
  padding-left: 1rem;
  position: relative;
}

.domain-card li::before {
  content: '\2022';
  position: absolute;
  left: 0;
  color: var(--accent);
}

/* ── Footer ──────────────────────────────────────────────────────── */

.bp-footer {
  padding: 2rem 0;
  border-top: 1px solid var(--border);
  text-align: center;
  font-size: 0.82rem;
  color: var(--dim);
}

.bp-footer a {
  color: var(--accent);
}

/* ── Responsive ──────────────────────────────────────────────────── */

@media (max-width: 700px) {
  .stack-layer {
    grid-template-columns: 1fr;
  }
  .stack-label {
    justify-content: flex-start;
    padding: 0.5rem 1rem 0;
  }
  .stack-layer:first-child .stack-content {
    border-radius: 0;
  }
  .stack-layer:last-child .stack-content {
    border-radius: 0 0 10px 10px;
  }
  .stack-layer:first-child .stack-label + .stack-content {
    border-top: 1px solid var(--border);
  }
  .flow {
    flex-direction: column;
  }
  .flow-step {
    border-radius: 0 !important;
    border-left: 1px solid var(--border) !important;
  }
  .flow-step:first-child {
    border-radius: 10px 10px 0 0 !important;
  }
  .flow-step:last-child {
    border-radius: 0 0 10px 10px !important;
  }
  .flow-step::after {
    content: '\2193';
    right: 50%;
    transform: translateX(50%);
    top: auto;
    bottom: -0.55rem;
  }
  .two-domains {
    grid-template-columns: 1fr;
  }
}
</style>
</head>
<body>

<!-- Top bar -->
<div class="top-bar">
  <div class="container">
    <a href="/" class="top-bar-brand">OpenWitness.org</a>
    <nav class="top-bar-nav">
      <a href="/">Home</a>
      <a href="/docs">Docs</a>
      <a href="/blueprint">Blueprint</a>
    </nav>
  </div>
</div>

<!-- Hero -->
<div class="bp-hero">
  <div class="container">
    <h1>Blueprint for<br>Trusted Institutions</h1>
    <p class="subtitle">
      How to build a public service that is accountable without authority,
      funded without fees, and governed without governors.
    </p>
  </div>
</div>

<!-- Section 1: The Promise -->
<section>
  <div class="container">
    <div class="section-eyebrow">The Promise</div>
    <h2>Why a blueprint?</h2>
    <p>
      Traditional institutions earn trust through reputation, regulation, and legal
      enforcement. These mechanisms work, but they concentrate authority in gatekeepers.
      When gatekeepers fail, so does the trust.
    </p>
    <p>
      OpenWitness takes a different approach: structural accountability. Every design
      decision is made so that trust is a measurable outcome of the system's architecture,
      not a promise from its operators. The entire service is designed to be copied,
      forked, and replaced by anyone who can run it better.
    </p>
    <p>
      This page documents the institutional architecture behind OpenWitness. It is
      both an explanation and an invitation: if this design works, use it.
      If it has flaws, fork it and fix them.
    </p>

    <div class="principle-row">
      <span class="principle-pill"><span class="dot"></span>Free by design</span>
      <span class="principle-pill"><span class="dot"></span>Accountable by protocol</span>
      <span class="principle-pill"><span class="dot"></span>Open to competition</span>
      <span class="principle-pill"><span class="dot"></span>Forkable as governance</span>
    </div>
  </div>
</section>

<!-- Section 2: Architecture overview -->
<section>
  <div class="container">
    <div class="section-eyebrow">Architecture</div>
    <h2>Five layers of institutional trust</h2>
    <p>
      The architecture is organized as a stack. Each layer builds on the one below it.
      The cryptographic foundation carries everything; the trust competition layer
      governs everything.
    </p>

    <div class="stack-diagram">
      <div class="stack-layer">
        <div class="stack-label">Layer 5</div>
        <div class="stack-content">
          <span class="stack-tag amber">Trust Competition</span>
          <span class="stack-desc">Forkability as governance. Race-to-bottom trust economics. No lock-in.</span>
        </div>
      </div>
      <div class="stack-layer">
        <div class="stack-label">Layer 4</div>
        <div class="stack-content">
          <span class="stack-tag blue">Capacity &amp; Access</span>
          <span class="stack-desc">Subscription tiers. Per-wallet rate allocation. Anti-sybil via contribution tracking.</span>
        </div>
      </div>
      <div class="stack-layer">
        <div class="stack-label">Layer 3</div>
        <div class="stack-content">
          <span class="stack-tag blue">Economic Model</span>
          <span class="stack-desc">Fuel bonding curves. Smart-contract-governed A/B split. Founder reward.</span>
        </div>
      </div>
      <div class="stack-layer">
        <div class="stack-label">Layer 2</div>
        <div class="stack-content">
          <span class="stack-tag green">Identity &amp; Governance</span>
          <span class="stack-desc">Founder key hierarchy. Signed governance tree. Bootstrap protocol.</span>
        </div>
      </div>
      <div class="stack-layer">
        <div class="stack-label">Layer 1</div>
        <div class="stack-content">
          <span class="stack-tag blue">Cryptographic Foundation</span>
          <span class="stack-desc">Merkle trees. Dual anchoring (EVM + eIDAS qTSA). Membership shielding.</span>
        </div>
      </div>
    </div>
  </div>
</section>

<!-- Section 3: Layer 1 - Cryptographic Foundation -->
<section>
  <div class="container">
    <div class="section-eyebrow">Layer 1</div>
    <h2>Cryptographic Foundation</h2>
    <p>
      Every claim the service makes is anchored to independently verifiable roots of trust.
      No claim depends on the operator's word alone.
    </p>

    <h3>Dual anchoring</h3>
    <p>
      Each batch of submitted hashes is anchored to two independent trust roots simultaneously:
      an EVM blockchain (Ethereum) and an eIDAS-qualified Timestamping Authority. One root is
      governed by cryptographic consensus, the other by EU regulatory oversight. A verifier who
      trusts either system can validate the timestamp.
    </p>

    <div class="flow">
      <div class="flow-step">
        <span class="step-num">Step 1</span>
        <span class="step-title">Collect</span>
        <span class="step-detail">Hashes accumulate during the epoch window</span>
      </div>
      <div class="flow-step">
        <span class="step-num">Step 2</span>
        <span class="step-title">Seal</span>
        <span class="step-detail">Merkle tree built, root computed</span>
      </div>
      <div class="flow-step">
        <span class="step-num">Step 3</span>
        <span class="step-title">Anchor</span>
        <span class="step-detail">Root published to EVM + qTSA in parallel</span>
      </div>
      <div class="flow-step">
        <span class="step-num">Step 4</span>
        <span class="step-title">Witness</span>
        <span class="step-detail">Per-hash inclusion proofs minted and stored</span>
      </div>
    </div>

    <h3>Membership shielding</h3>
    <p>
      Standard Merkle proofs leak sibling hashes, enabling membership inference attacks. OpenWitness
      shields each leaf with a per-leaf random nonce before building the tree. Proof siblings are
      shielded values that cannot be reversed without the submitter's nonce. Verification
      stays self-contained: the witness carries the nonce and the verifier recomputes locally.
    </p>

    <h3>Witness shape</h3>
    <p>
      For each submitted hash, the service produces a witness: a chain of Aqua Protocol revisions
      linking the client's original hash to the anchored root. The witness is a standalone
      proof artifact; it carries everything a verifier needs. No callback to the service is required.
    </p>
  </div>
</section>

<!-- Section 4: Layer 2 - Identity & Governance -->
<section>
  <div class="container">
    <div class="section-eyebrow">Layer 2</div>
    <h2>Identity &amp; Governance</h2>
    <p>
      The service has a cryptographic identity rooted in a founder key. Every governance
      action is a signed message. Unsigned instructions carry no identity, no accountability,
      and no basis for verification.
    </p>

    <h3>Key hierarchy</h3>
    <div class="key-tree">
<span class="root">Founder Key</span> <span class="note">(cold, external, root trust)</span>
  <span class="leaf">Three responsibilities only:</span>
    <span class="leaf">a) Declare and authorize operational keys</span>
    <span class="leaf">b) Receive founder reward (1% success incentive)</span>
    <span class="leaf">c) Authoritative smart contract interactions</span>

  <span class="branch">Delegates to:</span>
    <span class="branch">Authorization Key</span> <span class="note">(hot, operational)</span>
      <span class="leaf">Authenticates CLI sessions for governance uploads</span>

    <span class="branch">Service Identity Key</span> <span class="note">(hot, operational)</span>
      <span class="leaf">Signs witnesses, identity tree, SIWE challenges</span>
      <span class="leaf">Anchors Merkle roots to EVM</span>

    <span class="branch">Publishing Wallet</span> <span class="note">(hot, operational, deferred)</span>
      <span class="leaf">Reviews and operates governance proposals</span>
    </div>

    <h3>Bootstrap protocol</h3>
    <p>
      The governance tree is built and signed externally by the founder, uploaded via
      an authenticated CLI session, and persisted permanently. Two separate verifications
      must pass: the CLI session must be authenticated by the authorization key, and the
      governance tree must be signed by the founder key. Both are required.
    </p>

    <div class="flow">
      <div class="flow-step">
        <span class="step-num">Founder</span>
        <span class="step-title">Build &amp; Sign</span>
        <span class="step-detail">Governance tree built via CLI, signed with founder key</span>
      </div>
      <div class="flow-step">
        <span class="step-num">Operator</span>
        <span class="step-title">Authenticate</span>
        <span class="step-detail">CLI session authenticated with authorization key</span>
      </div>
      <div class="flow-step">
        <span class="step-num">Service</span>
        <span class="step-title">Verify &amp; Ingest</span>
        <span class="step-detail">Both signatures checked; tree persisted; state transitions</span>
      </div>
    </div>

    <h3>Governance tree</h3>
    <p>
      The governance tree is a standard Aqua tree served publicly at
      <code class="mono">/.well-known/aqua-governance</code>. It contains signed declarations
      for the founder's identity, contract addresses, beneficiary address, and trust
      delegations. All governance content is verifiable by anyone using the same tools
      the service uses for its own timestamps.
    </p>
  </div>
</section>

<!-- Section 5: Layer 3 - Economic Model -->
<section>
  <div class="container">
    <div class="section-eyebrow">Layer 3</div>
    <h2>Economic Model</h2>
    <p>
      The service is free. Contributions are "fuel" that powers the machine, not fees
      charged for access. The economic model is designed so that funding scales the
      service without creating a paywall.
    </p>

    <h3>Fuel, not fee</h3>
    <blockquote>
      <p>
        The service provides timestamping at no charge. Contributors send fuel to
        increase the service's anchoring capacity and publication speed. More fuel
        means faster epochs, not gated access.
      </p>
    </blockquote>

    <h3>The A/B split</h3>
    <p>
      All incoming fuel is split between two purposes by a deterministic smart contract:
    </p>

    <div class="two-domains">
      <div class="domain-card">
        <h4>
          (A) Anchoring
          <span class="tag" style="background: rgba(91, 155, 213, 0.12); color: var(--accent); border: 1px solid rgba(91, 155, 213, 0.25);">On-chain</span>
        </h4>
        <ul>
          <li>Gas for EVM anchor transactions</li>
          <li>Costs for qTSA requests</li>
          <li>BTC anchoring (planned)</li>
          <li>Verifiable by anyone on-chain</li>
        </ul>
      </div>
      <div class="domain-card">
        <h4>
          (B) Operations
          <span class="tag" style="background: rgba(42, 138, 90, 0.08); color: var(--proof-green); border: 1px solid rgba(42, 138, 90, 0.2);">Aqua-tracked</span>
        </h4>
        <ul>
          <li>Infrastructure and compute</li>
          <li>Development and maintenance</li>
          <li>Coordination and outreach</li>
          <li>Accountable via Aqua-on-Aqua</li>
        </ul>
      </div>
    </div>

    <h3>Bonding curve</h3>
    <p>
      The operational share follows a logarithmic decay from 50% (bootstrap phase, low income)
      to 2% (mature phase, high income). A single tuning parameter shapes the curve.
      As the service matures and income grows, a larger share goes directly to anchoring
      and a smaller share to operations, ensuring efficiency pressure scales with success.
    </p>

    <table class="bp-table">
      <thead>
        <tr>
          <th>Phase</th>
          <th>Operational share</th>
          <th>Anchoring share</th>
          <th>Condition</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>Bootstrap</td>
          <td>50%</td>
          <td>50%</td>
          <td>Below income threshold</td>
        </tr>
        <tr>
          <td>Growth</td>
          <td>50% to 2%</td>
          <td>50% to 98%</td>
          <td>Logarithmic decay as income rises</td>
        </tr>
        <tr>
          <td>Mature</td>
          <td>2%</td>
          <td>98%</td>
          <td>Above half-life income</td>
        </tr>
        <tr>
          <td>Terminal</td>
          <td>1%</td>
          <td>99%</td>
          <td>After both founder reward caps are hit</td>
        </tr>
      </tbody>
    </table>

    <h3>Two chains, one model</h3>
    <p>
      ETH and BTC are the same economic model running independently in two separate worlds.
      They share only the BTC difficulty epoch (~2 weeks) as an evaluation clock. No exchange
      rates, no cross-chain binding, no shared balances. A single Ethereum smart contract
      governs the fuel split for both chains, with BTC bridged in via wrapped BTC.
    </p>

    <h3>Founder reward</h3>
    <p>
      The founding team receives 0.5% per chain (1% total), capped at 10 BTC + 500 ETH.
      The reward activates only when both chains reach maximum publication rate,
      ensuring the founders earn only when the service is operating at peak capacity.
      A competitor who skips the founder reward starts with a 1 percentage point
      structural advantage on fuel efficiency.
    </p>
  </div>
</section>

<!-- Section 6: Layer 4 - Capacity & Access -->
<section>
  <div class="container">
    <div class="section-eyebrow">Layer 4</div>
    <h2>Capacity &amp; Access</h2>
    <p>
      The service has finite anchoring capacity determined by its fuel balance and
      publication rate. The capacity layer allocates this budget across contributors.
    </p>

    <h3>Free tier</h3>
    <p>
      Every wallet gets a baseline allocation at no cost. The free tier is a structural
      commitment: the service is free by design, not free as a trial. Rate limits
      prevent abuse without creating a paywall.
    </p>

    <h3>Contribution scaling</h3>
    <p>
      Wallets that contribute fuel receive higher hash rate allocations. The mapping
      from contribution to allocation follows a logarithmic curve matching the fuel
      model's character. This is "fuel, not fee": contributors increase the whole
      service's capacity while earning priority for their own usage.
    </p>

    <h3>Wallet pool</h3>
    <p>
      The service maintains a pool of up to 500 active wallets. A three-tier
      eviction strategy (funded, active, idle) ensures capacity goes to wallets
      that are actively using and supporting the service. Two orthogonal
      leaderboards (ETH and BTC) provide transparent, real-time visibility into
      who is fueling the machine.
    </p>
  </div>
</section>

<!-- Section 7: Layer 5 - Trust Competition -->
<section>
  <div class="container">
    <div class="section-eyebrow">Layer 5</div>
    <h2>Trust Competition</h2>
    <p>
      This is the governance layer. It has no voting, no council, and no on-chain
      enforcement of off-chain spending. Instead, it relies on competitive pressure
      from an open market of potential operators.
    </p>

    <h3>The core thesis</h3>
    <blockquote>
      <p>
        The spec and service are open and meant to be copied. This is not a
        side effect of open source. It is the governance model.
      </p>
    </blockquote>

    <h3>Two accountability domains</h3>

    <div class="two-domains">
      <div class="domain-card">
        <h4>
          Hash World (A)
          <span class="tag" style="background: rgba(91, 155, 213, 0.12); color: var(--accent); border: 1px solid rgba(91, 155, 213, 0.25);">Self-accountable</span>
        </h4>
        <ul>
          <li>Anchoring transactions on-chain</li>
          <li>Verifiable by default</li>
          <li>No trust required</li>
          <li>Governed by deterministic math</li>
        </ul>
      </div>
      <div class="domain-card">
        <h4>
          Operational World (B)
          <span class="tag" style="background: rgba(217, 119, 6, 0.08); color: var(--enforce-amber); border: 1px solid rgba(217, 119, 6, 0.2);">Competition-governed</span>
        </h4>
        <ul>
          <li>Infrastructure, development, coordination</li>
          <li>Cannot be verified purely on-chain</li>
          <li>Governed by two mechanisms below</li>
          <li>Backstop: forkability</li>
        </ul>
      </div>
    </div>

    <h3>Mechanism 1: Aqua-on-Aqua accounting</h3>
    <p>
      The operational budget is tracked using the Aqua Protocol itself. The service
      that provides data integrity uses its own product to account for its own operations.
      Operational decisions, expenditures, and resource allocation are captured as
      timestamped, immutable hash chains. Anyone can audit the operational record
      using the same tools they use to verify their own timestamps.
    </p>

    <h3>Mechanism 2: Competitive accountability</h3>
    <p>
      Because the spec is complete and the code is open, any team can fork the service.
      Operators compete on trust, efficiency, and reliability. The most trusted operator
      attracts the most fuel. This creates a virtuous cycle where trust directly translates
      to service quality.
    </p>

    <div class="causal-chain">
      <div class="causal-link">
        <span class="causal-if">IF</span>
        <span class="causal-then">the spec is open and complete</span>
      </div>
      <div class="causal-link">
        <span class="causal-if">THEN</span>
        <span class="causal-then">any team can understand and replicate the service</span>
      </div>
      <div class="causal-link">
        <span class="causal-if">IF</span>
        <span class="causal-then">a competitor runs the service leaner</span>
      </div>
      <div class="causal-link">
        <span class="causal-if">THEN</span>
        <span class="causal-then">they offer lower fuel ratios or faster publishing</span>
      </div>
      <div class="causal-link">
        <span class="causal-if">IF</span>
        <span class="causal-then">the more trusted operator attracts more fuel</span>
      </div>
      <div class="causal-link">
        <span class="causal-if">THEN</span>
        <span class="causal-then">they publish the fastest (bonding curve rewards scale)</span>
      </div>
      <div class="causal-link">
        <span class="causal-if">THEREFORE</span>
        <span class="causal-then">openness creates self-reinforcing trust competition that governs accountability without authority</span>
      </div>
    </div>

    <h3>No structural advantage for the founders</h3>

    <table class="bp-table">
      <thead>
        <tr>
          <th>Potential advantage</th>
          <th>Why it does not hold</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>First mover</td>
          <td>Open spec means latecomers start fully informed</td>
        </tr>
        <tr>
          <td>Code ownership</td>
          <td>Open source; forks inherit all engineering</td>
        </tr>
        <tr>
          <td>Brand recognition</td>
          <td>Trust is re-earned continuously; brand is a lagging indicator</td>
        </tr>
        <tr>
          <td>User lock-in</td>
          <td>Service is stateless for users; switching cost is near zero</td>
        </tr>
        <tr>
          <td>Founder reward</td>
          <td>1% total, capped, conditional on peak operation</td>
        </tr>
      </tbody>
    </table>
  </div>
</section>

<!-- Section 8: Open Questions -->
<section>
  <div class="container">
    <div class="section-eyebrow">Honesty</div>
    <h2>Open Questions &amp; Gaps</h2>
    <p>
      A blueprint that hides its gaps is not a blueprint; it is marketing. These are
      the areas where the institutional design is incomplete, unresolved, or deferred.
      Each gap is a research question, not a failure.
    </p>

    <div class="gap-grid">
      <div class="gap-card">
        <div class="gap-title">
          Dispute Resolution
          <span class="gap-status open">Open</span>
        </div>
        <div class="gap-body">
          No mechanism for resolving conflicts between operators,
          or between operators and contributors. The trust competition model
          assumes exit (fork and leave) as the sole recourse.
        </div>
      </div>

      <div class="gap-card">
        <div class="gap-title">
          BTC Bridge Mechanism
          <span class="gap-status open">Open</span>
        </div>
        <div class="gap-body">
          How to pipe Bitcoin fuel into the Ethereum smart contract
          trustlessly. Options range from custodial (wBTC) to threshold
          (tBTC v2) to experimental (BitVM bridges). Unresolved.
        </div>
      </div>

      <div class="gap-card">
        <div class="gap-title">
          Governance Decision Rounds
          <span class="gap-status deferred">Deferred</span>
        </div>
        <div class="gap-body">
          The proposal, review, and approval flow for operational
          decisions is designed but not implemented. Depends on the publishing
          wallet delegation and the org smart contract.
        </div>
      </div>

      <div class="gap-card">
        <div class="gap-title">
          Key Rotation
          <span class="gap-status deferred">Deferred</span>
        </div>
        <div class="gap-body">
          The founder key can be rotated once, anchored to the org smart
          contract. The contract does not exist yet. Without rotation, founder
          key compromise is catastrophic.
        </div>
      </div>

      <div class="gap-card">
        <div class="gap-title">
          Contribution Tracking
          <span class="gap-status open">Open</span>
        </div>
        <div class="gap-body">
          Should per-wallet contribution tracking live on-chain
          (transparent but expensive) or off-chain via Aqua-on-Aqua
          (cheaper but requires the trust competition model for
          accountability)? The biggest architectural decision remaining.
        </div>
      </div>

      <div class="gap-card">
        <div class="gap-title">
          External Audit Framework
          <span class="gap-status open">Open</span>
        </div>
        <div class="gap-body">
          Aqua-on-Aqua accounting for the operational budget is
          self-referential. External audits and cross-operator verification
          break the circularity, but no protocol for how these audits
          happen is defined.
        </div>
      </div>

      <div class="gap-card">
        <div class="gap-title">
          Migration Protocol
          <span class="gap-status open">Open</span>
        </div>
        <div class="gap-body">
          Forkability assumes near-zero switching cost. There is no
          defined protocol for a contributor to port their proof history
          or contribution record to a competing operator.
        </div>
      </div>

      <div class="gap-card">
        <div class="gap-title">
          Natural Monopoly Risk
          <span class="gap-status open">Open</span>
        </div>
        <div class="gap-body">
          Whether the service has natural monopoly dynamics at small
          scale is an empirical question. If only one operator is economically
          viable, the trust competition model becomes theoretical.
        </div>
      </div>
    </div>
  </div>
</section>

<!-- Section 9: How to Fork -->
<section>
  <div class="container">
    <div class="section-eyebrow">Fork It</div>
    <h2>How to run your own instance</h2>
    <p>
      The blueprint is only credible if you can act on it. Everything needed to
      run a competing instance is public.
    </p>

    <table class="bp-table">
      <thead>
        <tr>
          <th>Component</th>
          <th>Where</th>
          <th>License</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>Protocol specification</td>
          <td><a href="https://github.com/inblockio/aqua-spec">aqua-spec</a></td>
          <td>Open</td>
        </tr>
        <tr>
          <td>Reference SDK (Rust)</td>
          <td><a href="https://github.com/inblockio/aqua-rs-sdk">aqua-rs-sdk</a></td>
          <td>Apache-2.0</td>
        </tr>
        <tr>
          <td>This service</td>
          <td><a href="https://github.com/inblockio/aqua-timestamps">aqua-timestamps</a></td>
          <td>Apache-2.0</td>
        </tr>
        <tr>
          <td>Auth library</td>
          <td><a href="https://github.com/inblockio/aqua-rs-auth">aqua-rs-auth</a></td>
          <td>Apache-2.0</td>
        </tr>
        <tr>
          <td>Operational design</td>
          <td>This page</td>
          <td>Public domain</td>
        </tr>
      </tbody>
    </table>

    <p class="dim" style="margin-top: 1rem;">
      Generate a secp256k1 key, configure the dual anchors, deploy the Docker image,
      and point contributors to your instance. The bonding curve, governance bootstrap,
      and trust competition model apply identically to any operator.
    </p>
  </div>
</section>

<!-- Footer -->
<footer class="bp-footer">
  <div class="container">
    <p>
      Apache-2.0 &middot; Operated by <a href="https://inblock.io">inblock.io</a>
      &middot; <a href="/">Back to OpenWitness.org</a>
    </p>
  </div>
</footer>

</body>
</html>
"##;
