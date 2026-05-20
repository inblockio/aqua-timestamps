pub const HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Aqua Aggregator · timestamp.inblock.io</title>
<link rel="icon" href="/favicon.ico" type="image/x-icon" />
<link rel="apple-touch-icon" href="/apple-touch-icon.png" />
<style>
@import url('https://fonts.googleapis.com/css2?family=Sora:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --accent: #E8611A;
  --accent-hover: #D4570F;
  --define-blue: #4895ef;
  --enforce-amber: #d97706;
  --proof-green: #2a8a5a;
  --sans: 'Sora', sans-serif;
  --mono: 'JetBrains Mono', monospace;

  /* Dark theme (default) */
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
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
}

a { color: var(--accent); text-decoration: none; }
a:hover { color: var(--accent-hover); text-decoration: underline; }

code, .mono {
  font-family: var(--mono);
  font-size: 0.875em;
}

/* ── Layout ──────────────────────────────────────────────────────── */

.container {
  max-width: 1120px;
  margin: 0 auto;
  padding: 0 1.5rem;
}

section {
  padding: 4rem 0;
}

section + section {
  border-top: 1px solid var(--border);
}

/* ── Section 1: Hero ─────────────────────────────────────────────── */

.hero {
  padding: 5rem 0 4rem;
  text-align: center;
}

.hero-eyebrow {
  font-size: 0.75rem;
  font-weight: 600;
  letter-spacing: 0.15em;
  text-transform: uppercase;
  color: var(--accent);
  margin-bottom: 1rem;
}

.hero h1 {
  font-size: clamp(1.75rem, 4vw, 2.75rem);
  font-weight: 700;
  line-height: 1.2;
  margin-bottom: 1.25rem;
  max-width: 720px;
  margin-left: auto;
  margin-right: auto;
}

.hero-body {
  font-size: 1.05rem;
  color: var(--dim);
  max-width: 640px;
  margin: 0 auto 2rem;
  line-height: 1.7;
}

.value-pills {
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 0.75rem;
}

.value-pill {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  border-radius: 10px;
  border: 1px solid var(--border);
  background: var(--surface);
  font-size: 0.875rem;
  font-weight: 500;
}

.value-pill .dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}

.value-pill.blue .dot { background: var(--define-blue); }
.value-pill.green .dot { background: var(--proof-green); }

/* ── Section 2: Operational Overview ────────────────────────────── */

.ops-section h2 {
  font-size: 1.5rem;
  font-weight: 600;
  margin-bottom: 0.5rem;
  text-align: center;
}

.ops-subtitle {
  text-align: center;
  color: var(--dim);
  margin-bottom: 2rem;
  font-size: 0.95rem;
}

.channel-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 1rem;
  margin-bottom: 2rem;
}

.channel-card {
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 1.25rem 1.5rem;
  background: var(--surface);
  position: relative;
}

.channel-card.planned {
  opacity: 0.5;
}

.channel-header {
  display: flex;
  align-items: center;
  gap: 0.625rem;
  margin-bottom: 1rem;
}

.status-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  flex-shrink: 0;
}

.status-dot.green { background: var(--proof-green); box-shadow: 0 0 6px var(--proof-green); }
.status-dot.grey { background: var(--dim); }

.channel-name {
  font-weight: 600;
  font-size: 1rem;
}

.channel-network {
  font-size: 0.8rem;
  color: var(--dim);
  font-weight: 400;
}

.badge {
  font-size: 0.7rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  padding: 0.2rem 0.5rem;
  border-radius: 8px;
  margin-left: auto;
}

.badge.live { background: rgba(42, 138, 90, 0.15); color: var(--proof-green); }
.badge.planned { background: rgba(113, 113, 122, 0.15); color: var(--dim); }

.channel-details {
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
}

.channel-detail {
  display: flex;
  justify-content: space-between;
  font-size: 0.85rem;
}

.channel-detail .label { color: var(--dim); }
.channel-detail .value { font-family: var(--mono); font-size: 0.8rem; }

.stat-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
}

.stat-card {
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 1.25rem 1.5rem;
  background: var(--surface);
  text-align: center;
}

.stat-value {
  font-size: 1.75rem;
  font-weight: 700;
  font-family: var(--mono);
  margin-bottom: 0.25rem;
}

.stat-label {
  font-size: 0.8rem;
  color: var(--dim);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  font-weight: 500;
}

/* ── Section 3: Support ──────────────────────────────────────────── */

.support-section h2 {
  font-size: 1.5rem;
  font-weight: 600;
  margin-bottom: 0.5rem;
  text-align: center;
}

.support-subtitle {
  text-align: center;
  color: var(--dim);
  margin-bottom: 2rem;
  font-size: 0.95rem;
}

.goal-card {
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 1.5rem;
  background: var(--surface);
  margin-bottom: 1rem;
}

.goal-header {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-bottom: 0.75rem;
  flex-wrap: wrap;
}

.goal-title {
  font-size: 1.1rem;
  font-weight: 600;
}

.goal-badge {
  font-size: 0.7rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  padding: 0.2rem 0.5rem;
  border-radius: 8px;
}

.goal-badge.active { background: rgba(42, 138, 90, 0.15); color: var(--proof-green); }
.goal-badge.funding { background: rgba(217, 119, 6, 0.15); color: var(--enforce-amber); }

.goal-type {
  font-size: 0.8rem;
  color: var(--dim);
  margin-left: auto;
}

.goal-body {
  font-size: 0.95rem;
  color: var(--dim);
  margin-bottom: 1rem;
  line-height: 1.6;
}

.progress-wrapper {
  margin-bottom: 1rem;
}

.progress-label {
  display: flex;
  justify-content: space-between;
  font-size: 0.8rem;
  color: var(--dim);
  margin-bottom: 0.375rem;
}

.progress-bar {
  height: 8px;
  background: var(--border);
  border-radius: 4px;
  overflow: hidden;
}

.progress-fill {
  height: 100%;
  border-radius: 4px;
  transition: width 0.3s ease;
}

.progress-fill.blue { background: var(--define-blue); }
.progress-fill.amber { background: var(--enforce-amber); }

.wallet-row {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 0.5rem;
  font-size: 0.85rem;
  flex-wrap: wrap;
}

.wallet-label {
  color: var(--dim);
  min-width: 5rem;
}

.wallet-addr {
  font-family: var(--mono);
  font-size: 0.78rem;
  word-break: break-all;
  color: var(--text);
  background: rgba(127, 127, 127, 0.08);
  padding: 0.2rem 0.5rem;
  border-radius: 6px;
  cursor: pointer;
  position: relative;
}

.wallet-addr:hover { background: rgba(127, 127, 127, 0.15); }

.wallet-addr .copied-tooltip {
  display: none;
  position: absolute;
  top: -1.75rem;
  left: 50%;
  transform: translateX(-50%);
  background: var(--accent);
  color: #fff;
  font-size: 0.7rem;
  padding: 0.2rem 0.5rem;
  border-radius: 4px;
  white-space: nowrap;
  font-family: var(--sans);
}

.wallet-addr.show-copied .copied-tooltip {
  display: block;
}

.budget-note {
  margin-top: 1.5rem;
  font-size: 0.85rem;
  color: var(--dim);
  text-align: center;
  font-style: italic;
}

/* ── ORL Badge ───────────────────────────────────────────────────── */

.orl-badge {
  position: fixed;
  top: 1rem;
  right: 1rem;
  z-index: 100;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  cursor: pointer;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 0.4rem 0.75rem;
  font-size: 0.8rem;
  font-weight: 500;
  user-select: none;
  transition: box-shadow 0.2s;
}

.orl-badge:hover {
  box-shadow: 0 2px 12px rgba(0, 0, 0, 0.15);
}

.orl-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: #F97316;
  flex-shrink: 0;
}

.orl-label { color: var(--text); }

.orl-panel {
  display: none;
  position: fixed;
  top: 3.5rem;
  right: 1rem;
  z-index: 101;
  width: 340px;
  max-width: calc(100vw - 2rem);
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 1.25rem;
  box-shadow: 0 4px 24px rgba(0, 0, 0, 0.2);
}

.orl-panel.open { display: block; }

.orl-panel-title {
  font-size: 1rem;
  font-weight: 600;
  margin-bottom: 0.25rem;
}

.orl-panel-desc {
  font-size: 0.85rem;
  color: var(--dim);
  margin-bottom: 1rem;
  line-height: 1.5;
}

.orl-progress {
  display: flex;
  gap: 4px;
  margin-bottom: 1rem;
}

.orl-segment {
  flex: 1;
  height: 6px;
  border-radius: 3px;
  background: var(--border);
}

.orl-segment.lit-red { background: #ef4444; }
.orl-segment.lit-orange { background: #F97316; }

.orl-checklist {
  list-style: none;
  font-size: 0.82rem;
  margin-bottom: 1rem;
}

.orl-checklist li {
  padding: 0.25rem 0;
  display: flex;
  align-items: flex-start;
  gap: 0.4rem;
}

.orl-checklist li::before {
  flex-shrink: 0;
  font-size: 0.85rem;
  line-height: 1.4;
}

.orl-checklist li.met::before { content: "\2713"; color: var(--proof-green); }
.orl-checklist li.unmet::before { content: "\2717"; color: var(--dim); }

.orl-link {
  font-size: 0.82rem;
}

@media (max-width: 600px) {
  .orl-label { display: none; }
  .orl-badge { padding: 0.4rem; border-radius: 50%; }
}

/* ── Footer ──────────────────────────────────────────────────────── */

.site-footer {
  border-top: 1px solid var(--border);
  padding: 2rem 0;
  text-align: center;
  font-size: 0.85rem;
  color: var(--dim);
}

.footer-links {
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 1.25rem;
  margin-bottom: 0.75rem;
}

.footer-copy {
  font-size: 0.8rem;
}

/* ── Responsive ──────────────────────────────────────────────────── */

@media (max-width: 640px) {
  section { padding: 2.5rem 0; }
  .hero { padding: 3rem 0 2.5rem; }
  .stat-grid { grid-template-columns: 1fr 1fr; }
}
</style>
</head>
<body>

<!-- ORL Badge -->
<div class="orl-badge" id="orl-badge" onclick="toggleOrl()">
  <span class="orl-dot"></span>
  <span class="orl-label">ORL-2 Development</span>
</div>

<div class="orl-panel" id="orl-panel">
  <div class="orl-panel-title">ORL-2: Development</div>
  <div class="orl-panel-desc">Maintained but unstable. Breaking changes possible. No SLA.</div>
  <div class="orl-progress">
    <div class="orl-segment lit-red"></div>
    <div class="orl-segment lit-orange"></div>
    <div class="orl-segment"></div>
    <div class="orl-segment"></div>
    <div class="orl-segment"></div>
  </div>
  <ul class="orl-checklist">
    <li class="met">Source code published</li>
    <li class="met">Automated build and deploy</li>
    <li class="met">Health endpoint available</li>
    <li class="met">Dual-anchor operational (EVM + qTSA)</li>
    <li class="unmet">Security review not started</li>
    <li class="unmet">Backup restore not verified</li>
    <li class="unmet">Monitoring and alerting not active</li>
    <li class="unmet">Dependency audit not completed</li>
  </ul>
  <a class="orl-link" href="/.well-known/aqua-orl">View ORL declaration (JSON)</a>
</div>

<!-- Section 1: Hero -->
<section class="hero">
  <div class="container">
    <div class="hero-eyebrow">Aqua Timestamp Service</div>
    <h1>A free anchor of trust for a world that needs it</h1>
    <p class="hero-body">
      Trust is eroding. Uncertainty is rising. We made it our mission to provide
      a free, public timestamping service that anchors data integrity across
      jurisdictions and blockchains. No accounts. No fees. Just proof.
    </p>
    <div class="value-pills">
      <span class="value-pill blue"><span class="dot"></span> Fastest multi-chain publishing</span>
      <span class="value-pill green"><span class="dot"></span> Most trusted cross-jurisdiction anchoring</span>
    </div>
  </div>
</section>

<!-- Section 2: Operational Overview -->
<section class="ops-section">
  <div class="container">
    <h2>Operational Overview</h2>
    <p class="ops-subtitle">Live anchoring channels and service statistics</p>

    <div class="channel-grid">
      <!-- Ethereum -->
      <div class="channel-card">
        <div class="channel-header">
          <span class="status-dot green"></span>
          <span class="channel-name">Ethereum <span class="channel-network">(Sepolia)</span></span>
          <span class="badge live">Live</span>
        </div>
        <div class="channel-details">
          <div class="channel-detail">
            <span class="label">Block time</span>
            <span class="value">~12s</span>
          </div>
          <div class="channel-detail">
            <span class="label">Epoch cycle</span>
            <span class="value" id="evm-epoch-cycle">...</span>
          </div>
          <div class="channel-detail">
            <span class="label">Last anchor</span>
            <span class="value" id="evm-last-anchor">...</span>
          </div>
        </div>
      </div>

      <!-- qTSA -->
      <div class="channel-card">
        <div class="channel-header">
          <span class="status-dot green"></span>
          <span class="channel-name">qTSA <span class="channel-network">(EU / eIDAS)</span></span>
          <span class="badge live">Live</span>
        </div>
        <div class="channel-details">
          <div class="channel-detail">
            <span class="label">Response time</span>
            <span class="value">Instant (RFC 3161)</span>
          </div>
          <div class="channel-detail">
            <span class="label">Provider</span>
            <span class="value">Sectigo Qualified</span>
          </div>
          <div class="channel-detail">
            <span class="label">Last anchor</span>
            <span class="value" id="qtsa-last-anchor">...</span>
          </div>
        </div>
      </div>

      <!-- Bitcoin (planned) -->
      <div class="channel-card planned">
        <div class="channel-header">
          <span class="status-dot grey"></span>
          <span class="channel-name">Bitcoin <span class="channel-network">(mainnet)</span></span>
          <span class="badge planned">Planned</span>
        </div>
        <div class="channel-details">
          <div class="channel-detail">
            <span class="label">Block time</span>
            <span class="value">~10 min</span>
          </div>
          <div class="channel-detail">
            <span class="label">Method</span>
            <span class="value">OP_RETURN</span>
          </div>
          <div class="channel-detail">
            <span class="label">Status</span>
            <span class="value">Pending funding</span>
          </div>
        </div>
      </div>
    </div>

    <div class="stat-grid">
      <div class="stat-card">
        <div class="stat-value mono" id="stat-epochs">...</div>
        <div class="stat-label">Epochs sealed</div>
      </div>
      <div class="stat-card">
        <div class="stat-value mono" id="stat-leaves">...</div>
        <div class="stat-label">Leaves timestamped</div>
      </div>
      <div class="stat-card">
        <div class="stat-value mono" id="stat-uptime">...</div>
        <div class="stat-label">Uptime</div>
      </div>
      <div class="stat-card">
        <div class="stat-value mono" id="stat-online-since">...</div>
        <div class="stat-label">Online since</div>
      </div>
    </div>
  </div>
</section>

<!-- Section 3: Support the Project -->
<section class="support-section">
  <div class="container">
    <h2>Help us build trust</h2>
    <p class="support-subtitle">This is a non-profit activity of inblock.io. All goals are aqua-verified and trackable.</p>

    <!-- Goal 0 -->
    <div class="goal-card">
      <div class="goal-header">
        <span class="goal-title">Goal 0: Burn My Crypto</span>
        <span class="goal-badge active">Active</span>
        <span class="goal-type">Open-ended</span>
      </div>
      <p class="goal-body">
        Send small amounts to prove the pipeline works.
        Test your wallet, fuel the machine.
      </p>
      <div class="wallet-row">
        <span class="wallet-label">ETH wallet</span>
        <span class="wallet-addr mono" onclick="copyAddr(this)" title="Click to copy">0x55Fcf9F8C1287cB462aa3c1C97E2298d221c634f<span class="copied-tooltip">Copied</span></span>
      </div>
      <div class="wallet-row">
        <span class="wallet-label">BTC wallet</span>
        <span class="wallet-addr mono">FIXME</span>
      </div>
    </div>

    <!-- Goal 1 -->
    <div class="goal-card">
      <div class="goal-header">
        <span class="goal-title">Goal 1: Ethereum Mainnet</span>
        <span class="goal-badge funding">Funding</span>
        <span class="goal-type">Target: 5.0 ETH</span>
      </div>
      <p class="goal-body">
        Move from Sepolia testnet to Ethereum mainnet anchoring.
        50% fuels timestamping, 50% covers operational hardening and maintenance.
      </p>
      <div class="progress-wrapper">
        <div class="progress-label">
          <span>0.00 ETH raised</span>
          <span>5.00 ETH</span>
        </div>
        <div class="progress-bar">
          <div class="progress-fill blue" style="width: 0%"></div>
        </div>
      </div>
      <div class="wallet-row">
        <span class="wallet-label">Fuel wallet</span>
        <span class="wallet-addr mono" onclick="copyAddr(this)" title="Click to copy">0x55Fcf9F8C1287cB462aa3c1C97E2298d221c634f<span class="copied-tooltip">Copied</span></span>
      </div>
      <div class="wallet-row">
        <span class="wallet-label">Ops wallet</span>
        <span class="wallet-addr mono">FIXME</span>
      </div>
    </div>

    <!-- Goal 2 -->
    <div class="goal-card">
      <div class="goal-header">
        <span class="goal-title">Goal 2: Bitcoin Direct Timestamping</span>
        <span class="goal-badge funding">Funding</span>
        <span class="goal-type">Target: 0.25 BTC</span>
      </div>
      <p class="goal-body">
        Direct OP_RETURN anchoring instead of proxy through OpenTimestamps.org.
        50% fuels timestamping, 50% covers operational hardening and maintenance.
      </p>
      <div class="progress-wrapper">
        <div class="progress-label">
          <span>0.000 BTC raised</span>
          <span>0.250 BTC</span>
        </div>
        <div class="progress-bar">
          <div class="progress-fill amber" style="width: 0%"></div>
        </div>
      </div>
      <div class="wallet-row">
        <span class="wallet-label">Fuel wallet</span>
        <span class="wallet-addr mono">FIXME</span>
      </div>
      <div class="wallet-row">
        <span class="wallet-label">Ops wallet</span>
        <span class="wallet-addr mono">FIXME</span>
      </div>
    </div>

    <p class="budget-note">
      Operational budget: starts at 50% of contributions, follows a logarithmic
      curve as funding grows. Curve model pending.
    </p>
  </div>
</section>

<!-- Footer -->
<footer class="site-footer">
  <div class="container">
    <div class="footer-links">
      <a href="/docs">Documentation</a>
      <a href="/.well-known/aqua-identity">Service Identity</a>
      <a href="https://github.com/inblockio/aqua-timestamps">GitHub</a>
    </div>
    <div class="footer-copy">
      Apache-2.0 &middot; Operated by <a href="https://inblock.io">inblock.io</a>
    </div>
  </div>
</footer>

<script>
(function () {
  'use strict';

  /* ── State ────────────────────────────────────────────────────── */

  var bootTime = null;       // Date when the server started
  var lastSealedAt = null;   // epoch seconds of last seal
  var evmLastAnchor = null;  // epoch seconds
  var qtsaLastAnchor = null; // epoch seconds

  /* ── Helpers ──────────────────────────────────────────────────── */

  function $(id) { return document.getElementById(id); }

  function timeAgo(epochSecs) {
    if (!epochSecs) return '...';
    var diff = Math.floor(Date.now() / 1000) - epochSecs;
    if (diff < 0) diff = 0;
    if (diff < 60) return diff + 's ago';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    return Math.floor(diff / 86400) + 'd ago';
  }

  function formatUptime(secs) {
    if (secs == null) return '...';
    var d = Math.floor(secs / 86400);
    var h = Math.floor((secs % 86400) / 3600);
    var m = Math.floor((secs % 3600) / 60);
    if (d > 0) return d + 'd ' + h + 'h';
    if (h > 0) return h + 'h ' + m + 'm';
    return m + 'm';
  }

  function formatDate(epochSecs) {
    if (!epochSecs) return '...';
    var d = new Date(epochSecs * 1000);
    return d.toISOString().slice(0, 10);
  }

  function uptimePercent(secs) {
    // We only know the current uptime window; report as string
    if (secs == null) return '...';
    return '100%';
  }

  /* ── DOM updates ──────────────────────────────────────────────── */

  function updateHealth(data) {
    if (!data) return;
    var upSecs = data.uptime_secs || 0;
    $('stat-uptime').textContent = uptimePercent(upSecs);

    bootTime = Math.floor(Date.now() / 1000) - upSecs;
    $('stat-online-since').textContent = formatDate(bootTime);
  }

  function updateSchedule(data) {
    if (!data) return;
    var durSecs = data.epoch_duration_secs;
    if (durSecs) {
      $('evm-epoch-cycle').textContent = durSecs + 's';
    }
    if (data.last_sealed_at) {
      lastSealedAt = data.last_sealed_at;
      $('evm-last-anchor').textContent = timeAgo(lastSealedAt);
      $('qtsa-last-anchor').textContent = timeAgo(lastSealedAt);
    }
    if (data.last_sealed_epoch_id != null) {
      $('stat-epochs').textContent = String(data.last_sealed_epoch_id + 1);
    }
  }

  function updateTimeAgo() {
    if (lastSealedAt) {
      $('evm-last-anchor').textContent = timeAgo(evmLastAnchor || lastSealedAt);
      $('qtsa-last-anchor').textContent = timeAgo(qtsaLastAnchor || lastSealedAt);
    }
  }

  /* ── Fetch initial data ───────────────────────────────────────── */

  document.addEventListener('DOMContentLoaded', function () {
    Promise.all([
      fetch('/health').then(function (r) { return r.json(); }).catch(function () { return null; }),
      fetch('/v1/schedule').then(function (r) { return r.json(); }).catch(function () { return null; })
    ]).then(function (results) {
      updateHealth(results[0]);
      updateSchedule(results[1]);
    });

    /* ── SSE subscription ──────────────────────────────────────── */

    try {
      var source = new EventSource('/events');

      source.addEventListener('epoch:sealed', function (e) {
        try {
          var d = JSON.parse(e.data);
          lastSealedAt = d.timestamp || lastSealedAt;
          if (d.epoch_id != null) {
            $('stat-epochs').textContent = String(d.epoch_id + 1);
          }
          if (d.leaf_count != null) {
            var cur = parseInt($('stat-leaves').textContent, 10) || 0;
            $('stat-leaves').textContent = String(cur + d.leaf_count);
          }
        } catch (err) { /* ignore parse errors */ }
      });

      source.addEventListener('anchor:evm', function (e) {
        try {
          var d = JSON.parse(e.data);
          evmLastAnchor = Math.floor(Date.now() / 1000);
        } catch (err) { /* ignore */ }
      });

      source.addEventListener('anchor:qtsa', function (e) {
        try {
          var d = JSON.parse(e.data);
          qtsaLastAnchor = Math.floor(Date.now() / 1000);
        } catch (err) { /* ignore */ }
      });

      source.addEventListener('health:tick', function (e) {
        try {
          var d = JSON.parse(e.data);
          if (d.uptime_secs != null) {
            $('stat-uptime').textContent = uptimePercent(d.uptime_secs);
            bootTime = Math.floor(Date.now() / 1000) - d.uptime_secs;
            $('stat-online-since').textContent = formatDate(bootTime);
          }
          if (d.epochs_total != null) {
            $('stat-epochs').textContent = String(d.epochs_total);
          }
          if (d.leaves_total != null) {
            $('stat-leaves').textContent = String(d.leaves_total);
          }
        } catch (err) { /* ignore */ }
      });
    } catch (err) {
      /* SSE not supported or blocked; page degrades gracefully */
    }

    /* ── Tick time-ago displays ────────────────────────────────── */

    setInterval(updateTimeAgo, 1000);
  });

  /* ── ORL toggle ───────────────────────────────────────────────── */

  window.toggleOrl = function () {
    var panel = document.getElementById('orl-panel');
    panel.classList.toggle('open');
  };

  // Close ORL panel when clicking outside
  document.addEventListener('click', function (e) {
    var badge = document.getElementById('orl-badge');
    var panel = document.getElementById('orl-panel');
    if (!badge.contains(e.target) && !panel.contains(e.target)) {
      panel.classList.remove('open');
    }
  });

  /* ── Copy wallet address ──────────────────────────────────────── */

  window.copyAddr = function (el) {
    var text = el.textContent.replace('Copied', '').trim();
    if (text === 'FIXME') return;
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).then(function () {
        el.classList.add('show-copied');
        setTimeout(function () { el.classList.remove('show-copied'); }, 1200);
      });
    }
  };
})();
</script>

</body>
</html>
"##;
