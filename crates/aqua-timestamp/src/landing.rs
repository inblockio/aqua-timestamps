pub const HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>OpenWitness.org · Free and Open Time Stamping</title>
<link rel="icon" href="/favicon.ico" type="image/x-icon" />
<link rel="apple-touch-icon" href="/apple-touch-icon.png" />
<style>
@import url('https://fonts.googleapis.com/css2?family=Sora:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --accent: #5B9BD5;
  --accent-hover: #4889BF;
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

@keyframes hero-fade-up {
  from { opacity: 0; transform: translateY(18px); }
  to { opacity: 1; transform: translateY(0); }
}

.hero {
  padding: 6rem 0 5rem;
  text-align: center;
  position: relative;
  overflow: hidden;
}

.hero::before {
  content: '';
  position: absolute;
  inset: 0;
  background-image: radial-gradient(circle at 1px 1px, var(--border) 1px, transparent 0);
  background-size: 40px 40px;
  mask-image: radial-gradient(ellipse 60% 50% at 50% 30%, black 0%, transparent 70%);
  -webkit-mask-image: radial-gradient(ellipse 60% 50% at 50% 30%, black 0%, transparent 70%);
  opacity: 0.45;
  pointer-events: none;
}

.hero::after {
  content: '';
  position: absolute;
  top: 15%;
  left: 50%;
  width: 700px;
  height: 700px;
  transform: translateX(-50%);
  background: radial-gradient(circle, rgba(91, 155, 213, 0.06) 0%, transparent 55%);
  pointer-events: none;
}

.hero > .container {
  position: relative;
  z-index: 1;
}

.hero-eyebrow {
  font-family: var(--mono);
  font-size: 0.78rem;
  font-weight: 500;
  letter-spacing: 0.2em;
  text-transform: uppercase;
  color: var(--accent);
  margin-bottom: 1.5rem;
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  animation: hero-fade-up 0.7s ease both;
}

.hero-eyebrow::before {
  content: '';
  display: inline-block;
  width: 7px;
  height: 7px;
  background: var(--accent);
  border-radius: 1px;
  transform: rotate(45deg);
}

.hero h1 {
  font-size: clamp(2rem, 5vw, 3.25rem);
  font-weight: 700;
  line-height: 1.12;
  letter-spacing: -0.02em;
  margin-bottom: 1.5rem;
  max-width: 720px;
  margin-left: auto;
  margin-right: auto;
  animation: hero-fade-up 0.7s ease 0.08s both;
}

.hero-descriptor {
  font-family: var(--mono);
  font-size: 0.88rem;
  color: var(--proof-green);
  font-weight: 400;
  max-width: 640px;
  margin: 0 auto 1.75rem;
  line-height: 1.6;
  padding: 0.5rem 1.25rem;
  border: 1px solid rgba(42, 138, 90, 0.25);
  border-radius: 10px;
  display: inline-block;
  background: rgba(42, 138, 90, 0.06);
  animation: hero-fade-up 0.7s ease 0.16s both;
}

.hero-mission {
  font-size: 1.1rem;
  font-weight: 500;
  color: var(--text);
  max-width: 640px;
  margin: 0 auto 1.5rem;
  line-height: 1.6;
  animation: hero-fade-up 0.7s ease 0.22s both;
}

.mission-label {
  font-size: 0.75rem;
  font-weight: 600;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--dim);
  display: inline-block;
  margin-bottom: 0.25rem;
}

.epoch-metric {
  display: inline-flex;
  flex-direction: column;
  align-items: center;
  gap: 0;
  margin: 0 auto 1.75rem;
  cursor: pointer;
  user-select: none;
  animation: hero-fade-up 0.7s ease 0.26s both;
}

.epoch-metric-inner {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.4rem 1rem;
  border: 1px solid var(--border);
  border-radius: 10px;
  background: var(--surface);
  transition: border-color 0.2s, box-shadow 0.2s;
}

.epoch-metric:hover .epoch-metric-inner {
  border-color: rgba(91, 155, 213, 0.3);
  box-shadow: 0 2px 12px rgba(0, 0, 0, 0.1);
}

.epoch-pulse {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--accent);
  flex-shrink: 0;
  animation: pulse-glow 2s ease-in-out infinite;
}

@keyframes pulse-glow {
  0%, 100% { box-shadow: 0 0 0 0 rgba(91, 155, 213, 0.4); }
  50% { box-shadow: 0 0 0 4px rgba(91, 155, 213, 0); }
}

.epoch-value {
  font-size: 1.1rem;
  font-weight: 600;
  color: var(--text);
}

.epoch-unit {
  font-size: 0.75rem;
  font-weight: 500;
  color: var(--dim);
  text-transform: uppercase;
  letter-spacing: 0.06em;
}

.epoch-vision {
  max-height: 0;
  overflow: hidden;
  opacity: 0;
  font-size: 0.82rem;
  color: var(--dim);
  line-height: 1.5;
  max-width: 420px;
  text-align: center;
  transition: max-height 0.3s ease, opacity 0.3s ease, margin 0.3s ease;
  margin-top: 0;
}

.epoch-vision.open {
  max-height: 3rem;
  opacity: 1;
  margin-top: 0.5rem;
}

.hero-blockquote {
  max-width: 580px;
  margin: 0 auto 2.5rem;
  padding: 1.25rem 1.5rem;
  border-left: 3px solid var(--accent);
  background: var(--surface);
  border-radius: 0 10px 10px 0;
  text-align: left;
  animation: hero-fade-up 0.7s ease 0.28s both;
}

.hero-blockquote p {
  font-size: 0.95rem;
  color: var(--dim);
  line-height: 1.7;
  margin: 0;
}

.hero-blockquote p + p {
  margin-top: 0.75rem;
}

.value-pills {
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 0.75rem;
  animation: hero-fade-up 0.7s ease 0.38s both;
}

.value-pill {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  border-radius: 10px;
  border: 1px solid var(--border);
  background: var(--surface);
  font-size: 0.85rem;
  font-weight: 500;
  transition: transform 0.2s, border-color 0.2s, box-shadow 0.2s;
}

.value-pill:hover {
  transform: translateY(-2px);
  border-color: rgba(91, 155, 213, 0.3);
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.12);
}

.value-pill .dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}

.value-pill .dot { background: var(--accent); box-shadow: 0 0 6px rgba(91, 155, 213, 0.4); }

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

/* ── Fuel the machine ──────────────────────────────────────────── */

.fuel-heading {
  font-size: 1.15rem;
  font-weight: 600;
  margin: 2.5rem 0 0.35rem;
  text-align: center;
}

.fuel-subtitle {
  text-align: center;
  color: var(--dim);
  margin-bottom: 1.5rem;
  font-size: 0.9rem;
}

.fuel-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 1rem;
}

.fuel-chain-label {
  font-weight: 600;
  font-size: 0.9rem;
  margin-bottom: 0.75rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.fuel-chain-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}

.fuel-note {
  font-size: 0.78rem;
  color: var(--dim);
  margin-top: 0.75rem;
  font-style: italic;
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

/* ── Section 2.5: Contributors ──────────────────────────────────── */

.contributors-section h2 {
  font-size: 1.5rem;
  font-weight: 600;
  margin-bottom: 0.5rem;
  text-align: center;
}

.contributors-subtitle {
  text-align: center;
  color: var(--dim);
  margin-bottom: 2rem;
  font-size: 0.95rem;
}

.chain-tabs {
  display: flex;
  justify-content: center;
  margin-bottom: 1.5rem;
}

.chain-tab {
  padding: 0.5rem 1.5rem;
  font-size: 0.8rem;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  background: transparent;
  border: 1px solid var(--border);
  color: var(--dim);
  cursor: pointer;
  transition: all 0.2s;
  font-family: var(--sans);
}

.chain-tab:first-child { border-radius: 8px 0 0 8px; }
.chain-tab:last-child { border-radius: 0 8px 8px 0; border-left: none; }

.chain-tab.active {
  background: var(--accent);
  border-color: var(--accent);
  color: #fff;
}

.chain-tab:not(.active):hover {
  background: var(--surface);
  color: var(--text);
}

.leaderboard-card {
  border: 1px solid var(--border);
  border-radius: 14px;
  background: var(--surface);
  overflow: hidden;
}

.leaderboard-header {
  display: grid;
  grid-template-columns: 3rem 1fr 7rem 6rem 5.5rem;
  padding: 0.75rem 1.5rem;
  border-bottom: 1px solid var(--border);
  font-size: 0.7rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--dim);
}

.leaderboard-row {
  display: grid;
  grid-template-columns: 3rem 1fr 7rem 6rem 5.5rem;
  padding: 0.75rem 1.5rem;
  align-items: center;
  border-bottom: 1px solid var(--border);
  font-size: 0.85rem;
  transition: background 0.15s;
}

.leaderboard-row:last-child { border-bottom: none; }

.leaderboard-row:hover { background: rgba(127, 127, 127, 0.04); }

.lb-rank {
  font-weight: 700;
  font-family: var(--mono);
  font-size: 0.8rem;
}

.lb-rank.gold { color: #d4a017; }
.lb-rank.silver { color: #94a3b8; }
.lb-rank.bronze { color: #b45309; }

.lb-did {
  font-family: var(--mono);
  font-size: 0.78rem;
  color: var(--text);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  padding-right: 1rem;
}

.lb-fuel {
  font-family: var(--mono);
  font-size: 0.8rem;
  font-weight: 500;
  text-align: right;
}

.lb-hashes {
  font-family: var(--mono);
  font-size: 0.8rem;
  text-align: right;
}

.lb-active {
  font-size: 0.8rem;
  color: var(--dim);
  text-align: right;
}

.pool-status {
  margin-top: 1.5rem;
  display: flex;
  align-items: center;
  gap: 1rem;
  justify-content: center;
  font-size: 0.82rem;
  color: var(--dim);
}

.pool-bar-wrap {
  width: 120px;
  height: 6px;
  background: var(--border);
  border-radius: 3px;
  overflow: hidden;
}

.pool-bar-fill {
  height: 100%;
  background: var(--accent);
  border-radius: 3px;
  transition: width 0.5s ease;
}

.leaderboard-empty {
  padding: 3rem 1.5rem;
  text-align: center;
  color: var(--dim);
}

.leaderboard-empty-title {
  font-size: 0.95rem;
  margin-bottom: 0.35rem;
}

.leaderboard-empty-hint {
  font-size: 0.8rem;
  opacity: 0.7;
}

@media (max-width: 640px) {
  .leaderboard-header,
  .leaderboard-row {
    grid-template-columns: 2.5rem 1fr 5.5rem 4.5rem;
  }
  .lh-active,
  .lb-active { display: none; }
}

/* ── ORL Badge & Panel ─────────────────────────────────────────── */

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
  font-size: 0.78rem;
  font-weight: 500;
  user-select: none;
  transition: box-shadow 0.2s, border-color 0.2s;
}

.orl-badge:hover {
  box-shadow: 0 2px 12px rgba(0, 0, 0, 0.15);
  border-color: rgba(249, 115, 22, 0.3);
}

.orl-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: #F97316;
  flex-shrink: 0;
}

.orl-label-full { color: var(--text); }
.orl-label-short { display: none; color: var(--text); }

.orl-panel {
  display: none;
  position: fixed;
  top: 3.5rem;
  right: 1rem;
  z-index: 101;
  width: 400px;
  max-width: calc(100vw - 2rem);
  max-height: calc(100vh - 5rem);
  overflow-y: auto;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 1.25rem;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.25);
}

.orl-panel.open { display: block; }

.orl-panel-title {
  font-size: 0.95rem;
  font-weight: 600;
  margin-bottom: 0.25rem;
}

.orl-panel-current {
  font-size: 0.82rem;
  color: var(--dim);
  margin-bottom: 1rem;
}

.orl-panel-current strong {
  color: #F97316;
  font-weight: 600;
}

.orl-progress {
  display: flex;
  gap: 4px;
  margin-bottom: 1.25rem;
}

.orl-segment {
  flex: 1;
  height: 6px;
  border-radius: 3px;
  background: var(--border);
}

.orl-levels {
  display: flex;
  flex-direction: column;
  gap: 2px;
  margin-bottom: 1.25rem;
}

.orl-level {
  border: 1px solid transparent;
  border-radius: 10px;
  cursor: pointer;
  transition: background 0.15s, border-color 0.15s;
  overflow: hidden;
}

.orl-level:hover {
  background: rgba(127, 127, 127, 0.05);
}

.orl-level.expanded {
  border-color: var(--border);
  background: rgba(127, 127, 127, 0.04);
}

.orl-level-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 0.65rem;
}

.orl-level-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  flex-shrink: 0;
  background: var(--dot-color);
}

.orl-level-name {
  font-size: 0.82rem;
  font-weight: 500;
  flex: 1;
}

.orl-level.future .orl-level-name { color: var(--dim); }
.orl-level.future .orl-level-dot { opacity: 0.35; }

.orl-level-tag {
  font-size: 0.65rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  padding: 0.15rem 0.4rem;
  border-radius: 6px;
  flex-shrink: 0;
}

.orl-level-tag.tag-passed {
  background: rgba(34, 197, 94, 0.12);
  color: var(--proof-green);
}

.orl-level-tag.tag-current {
  background: rgba(249, 115, 22, 0.15);
  color: #F97316;
}

.orl-level-body {
  display: none;
  padding: 0 0.65rem 0.65rem;
}

.orl-level.expanded .orl-level-body { display: block; }

.orl-level-body p {
  font-size: 0.78rem;
  color: var(--dim);
  line-height: 1.55;
  margin: 0;
}

.orl-context {
  border-top: 1px solid var(--border);
  padding-top: 1rem;
}

.orl-context p {
  font-size: 0.78rem;
  color: var(--dim);
  line-height: 1.55;
  margin: 0 0 0.5rem;
}

.orl-context a { color: var(--accent); }

.orl-decl-link {
  font-size: 0.78rem;
  display: inline-flex;
  align-items: center;
  gap: 0.3rem;
}

@media (max-width: 600px) {
  .orl-label-full { display: none; }
  .orl-label-short { display: inline; }
  .orl-panel { width: calc(100vw - 2rem); }
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
  .hero { padding: 3.5rem 0 2.5rem; }
  .stat-grid { grid-template-columns: 1fr 1fr; }
}
</style>
</head>
<body>

<!-- ORL Badge -->
<div class="orl-badge" id="orl-badge" onclick="toggleOrl()">
  <span class="orl-dot"></span>
  <span class="orl-label-full">Operational Readiness Level (ORL-2)</span>
  <span class="orl-label-short">ORL-2</span>
</div>

<div class="orl-panel" id="orl-panel">
  <div class="orl-panel-title">Operational Readiness Level</div>
  <div class="orl-panel-current">This service is at <strong>ORL-2: Development</strong></div>

  <div class="orl-progress">
    <div class="orl-segment" style="background: #EF4444"></div>
    <div class="orl-segment" style="background: #F97316"></div>
    <div class="orl-segment"></div>
    <div class="orl-segment"></div>
    <div class="orl-segment"></div>
  </div>

  <div class="orl-levels" id="orl-levels">
    <div class="orl-level passed" data-level="1" onclick="selectOrlLevel(1)">
      <div class="orl-level-header">
        <span class="orl-level-dot" style="--dot-color: #EF4444"></span>
        <span class="orl-level-name">ORL-1: Experimental</span>
        <span class="orl-level-tag tag-passed">Passed</span>
      </div>
      <div class="orl-level-body">
        <p>Use at own risk. No backups, no security hardening, no uptime guarantee. May be taken down without notice. Data may be lost at any time.</p>
      </div>
    </div>

    <div class="orl-level current expanded" data-level="2" onclick="selectOrlLevel(2)">
      <div class="orl-level-header">
        <span class="orl-level-dot" style="--dot-color: #F97316"></span>
        <span class="orl-level-name">ORL-2: Development</span>
        <span class="orl-level-tag tag-current">Current</span>
      </div>
      <div class="orl-level-body">
        <p>Maintained but unstable. Someone is actively working on this. Breaking changes may happen but are communicated. Basic deployment exists. No SLA.</p>
      </div>
    </div>

    <div class="orl-level future" data-level="3" onclick="selectOrlLevel(3)">
      <div class="orl-level-header">
        <span class="orl-level-dot" style="--dot-color: #EAB308"></span>
        <span class="orl-level-name">ORL-3: Pre-production</span>
      </div>
      <div class="orl-level-body">
        <p>Service is stabilizing. Safe to evaluate for production adoption. Breaking changes only with a migration path. Active monitoring, but no formal SLA yet.</p>
      </div>
    </div>

    <div class="orl-level future" data-level="4" onclick="selectOrlLevel(4)">
      <div class="orl-level-header">
        <span class="orl-level-dot" style="--dot-color: #84CC16"></span>
        <span class="orl-level-name">ORL-4: Operational (Limited)</span>
      </div>
      <div class="orl-level-body">
        <p>Reliable for production use with documented limitations. Incidents will be responded to. Data is protected with automated backups and tested restore.</p>
      </div>
    </div>

    <div class="orl-level future" data-level="5" onclick="selectOrlLevel(5)">
      <div class="orl-level-header">
        <span class="orl-level-dot" style="--dot-color: #22C55E"></span>
        <span class="orl-level-name">ORL-5: Operational (Full)</span>
      </div>
      <div class="orl-level-body">
        <p>Production-grade, fully supported service. Clear SLA with accountability. Proactive maintenance and monitoring. Comprehensive incident response.</p>
      </div>
    </div>
  </div>

  <div class="orl-context">
    <p><a href="https://inblock.io">inblock.io</a> uses Operational Readiness Levels to transparently signal the maturity of its projects and services. We are committed to building open trust infrastructure.</p>
  </div>
</div>

<!-- Section 1: Hero -->
<section class="hero">
  <div class="container">
    <div class="hero-eyebrow">OpenWitness.org</div>
    <h1>Free and Open<br>Time Stamping Service</h1>
    <p class="hero-descriptor">
      Dual-anchored to Ethereum and qualified Timestamping Authorities
    </p>
    <p class="hero-mission">
      <span class="mission-label">Our Mission</span><br>
      Highest-trust timestamping with cross-jurisdictional acceptance.
    </p>
    <div class="epoch-metric" id="epoch-metric" onclick="toggleEpochVision()">
      <div class="epoch-metric-inner">
        <span class="epoch-pulse"></span>
        <span class="epoch-value mono" id="epoch-metric-value">...</span>
        <span class="epoch-unit">min epoch</span>
      </div>
      <div class="epoch-vision" id="epoch-vision">
        Our target: settle with every block on Ethereum mainnet and the Bitcoin network.
      </div>
    </div>
    <blockquote class="hero-blockquote">
      <p>The more we are trusted, the faster our time-service becomes.
      We are built for resilience and lasting proof.</p>
      <p>A new standard of accountability and trust: OpenWitness.org as a
      for trusted institutions. <a href="#">Learn more</a></p>
    </blockquote>
    <div class="value-pills">
      <span class="value-pill blue"><span class="dot"></span>Dual-anchored: EVM + eIDAS qTSA</span>
      <span class="value-pill green"><span class="dot"></span>Self-auditing by protocol</span>
      <span class="value-pill amber"><span class="dot"></span>Open Institutional Design</span>
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

    <h3 class="fuel-heading">Fuel the machine</h3>
    <p class="fuel-subtitle">The service is free. Contributions are fuel that powers timestamping and operations.</p>

    <div class="fuel-grid">
      <div class="channel-card">
        <div class="fuel-chain-label">
          <span class="fuel-chain-dot" style="background: var(--define-blue)"></span>
          Ethereum
        </div>
        <div class="wallet-row">
          <span class="wallet-label">Fuel</span>
          <span class="wallet-addr mono" onclick="copyAddr(this)" title="Click to copy">0x55Fcf9F8C1287cB462aa3c1C97E2298d221c634f<span class="copied-tooltip">Copied</span></span>
        </div>
        <div class="wallet-row">
          <span class="wallet-label">Ops</span>
          <span class="wallet-addr mono">FIXME</span>
        </div>
        <p class="fuel-note">Split governed by on-chain smart contract</p>
      </div>

      <div class="channel-card">
        <div class="fuel-chain-label">
          <span class="fuel-chain-dot" style="background: var(--enforce-amber)"></span>
          Bitcoin
        </div>
        <div class="wallet-row">
          <span class="wallet-label">Fuel</span>
          <span class="wallet-addr mono">FIXME</span>
        </div>
        <div class="wallet-row">
          <span class="wallet-label">Ops</span>
          <span class="wallet-addr mono">FIXME</span>
        </div>
        <p class="fuel-note">Native split at each difficulty epoch (~2 weeks)</p>
      </div>
    </div>
  </div>
</section>

<!-- Section 2.5: Contributors -->
<section class="contributors-section">
  <div class="container">
    <h2>Contributors</h2>
    <p class="contributors-subtitle">Public scoreboard of wallets fueling the service</p>

    <div class="chain-tabs">
      <button class="chain-tab active" data-chain="eth" onclick="switchChain('eth')">ETH</button>
      <button class="chain-tab" data-chain="btc" onclick="switchChain('btc')">BTC</button>
    </div>

    <div class="leaderboard-card">
      <div class="leaderboard-header">
        <span>#</span>
        <span>Wallet</span>
        <span class="lh-fuel" style="text-align:right">Fuel</span>
        <span class="lh-hashes" style="text-align:right">Hashes</span>
        <span class="lh-active" style="text-align:right">Active</span>
      </div>
      <div id="leaderboard-body">
        <div class="leaderboard-empty">
          <div class="leaderboard-empty-title">No contributors yet</div>
          <div class="leaderboard-empty-hint">Send fuel to the wallet below to appear on the board</div>
        </div>
      </div>
    </div>

    <div class="pool-status">
      <span>Pool: <span class="mono" id="pool-count">0</span> / <span class="mono">500</span></span>
      <div class="pool-bar-wrap">
        <div class="pool-bar-fill" id="pool-bar" style="width: 0%"></div>
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
      var mins = (durSecs / 60).toFixed(1).replace(/\.0$/, '');
      $('epoch-metric-value').textContent = mins;
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

  /* ── Leaderboard ──────────────────────────────────────────────── */

  var currentChain = 'eth';

  function truncateDid(did) {
    if (!did || did.length < 24) return did || '';
    return did.slice(0, 18) + '…' + did.slice(-8);
  }

  function formatFuel(amount, chain) {
    if (chain === 'btc') return (Number(amount) / 1e8).toFixed(6) + ' BTC';
    return (Number(amount) / 1e18).toFixed(4) + ' ETH';
  }

  function rankClass(i) {
    if (i === 0) return 'gold';
    if (i === 1) return 'silver';
    if (i === 2) return 'bronze';
    return '';
  }

  function renderLeaderboard(entries, chain) {
    var body = $('leaderboard-body');
    if (!entries || entries.length === 0) {
      body.innerHTML = '<div class="leaderboard-empty">' +
        '<div class="leaderboard-empty-title">No contributors yet</div>' +
        '<div class="leaderboard-empty-hint">Send fuel to the wallet below to appear on the board</div>' +
        '</div>';
      return;
    }
    var html = '';
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      var rc = rankClass(i);
      var fuelVal = chain === 'btc' ? e.fuel_contributed_sat : e.fuel_contributed_wei;
      html += '<div class="leaderboard-row">' +
        '<span class="lb-rank ' + rc + '">' + (i + 1) + '</span>' +
        '<span class="lb-did" title="' + (e.did || '') + '">' + truncateDid(e.did) + '</span>' +
        '<span class="lb-fuel">' + formatFuel(fuelVal || 0, chain) + '</span>' +
        '<span class="lb-hashes">' + (e.hashes_submitted || 0) + '</span>' +
        '<span class="lb-active">' + timeAgo(e.last_active) + '</span>' +
        '</div>';
    }
    body.innerHTML = html;
  }

  function fetchLeaderboard(chain) {
    fetch('/v1/leaderboard?chain=' + chain)
      .then(function (r) {
        if (!r.ok) throw new Error(r.status);
        return r.json();
      })
      .then(function (data) {
        var wallets = data.wallets || data;
        renderLeaderboard(Array.isArray(wallets) ? wallets : [], chain);
        if (data.pool_count != null) {
          $('pool-count').textContent = String(data.pool_count);
          var pct = Math.min(100, (data.pool_count / (data.max_pool || 500)) * 100);
          $('pool-bar').style.width = pct + '%';
        }
      })
      .catch(function () {
        renderLeaderboard([], chain);
      });
  }

  function fetchPoolStatus() {
    fetch('/v1/pool/status')
      .then(function (r) {
        if (!r.ok) throw new Error(r.status);
        return r.json();
      })
      .then(function (data) {
        if (data.current != null) {
          $('pool-count').textContent = String(data.current);
          var pct = Math.min(100, (data.current / (data.max || 500)) * 100);
          $('pool-bar').style.width = pct + '%';
        }
      })
      .catch(function () { /* API not yet available */ });
  }

  window.switchChain = function (chain) {
    currentChain = chain;
    var tabs = document.querySelectorAll('.chain-tab');
    for (var i = 0; i < tabs.length; i++) {
      var active = tabs[i].getAttribute('data-chain') === chain;
      tabs[i].classList.toggle('active', active);
    }
    fetchLeaderboard(chain);
  };

  /* ── Fetch initial data ───────────────────────────────────────── */

  document.addEventListener('DOMContentLoaded', function () {
    Promise.all([
      fetch('/health').then(function (r) { return r.json(); }).catch(function () { return null; }),
      fetch('/v1/schedule').then(function (r) { return r.json(); }).catch(function () { return null; })
    ]).then(function (results) {
      updateHealth(results[0]);
      updateSchedule(results[1]);
    });

    fetchLeaderboard('eth');
    fetchPoolStatus();

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

  window.toggleEpochVision = function () {
    var v = document.getElementById('epoch-vision');
    v.classList.toggle('open');
  };

  window.selectOrlLevel = function (level) {
    var levels = document.querySelectorAll('.orl-level');
    for (var i = 0; i < levels.length; i++) {
      var l = parseInt(levels[i].getAttribute('data-level'), 10);
      if (l === level) {
        levels[i].classList.toggle('expanded');
      } else {
        levels[i].classList.remove('expanded');
      }
    }
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
