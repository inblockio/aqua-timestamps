# Status Page Design Spec

**Date:** 2026-05-20
**Author:** Tim Bansemer / Claude
**Status:** Draft

## Overview

Replace the current minimal landing page at `GET /` with a mission-driven,
read-only status page that streams live operational data from the server.
The page has three sections: (1) mission and vision, (2) live operational
overview of publishing pipelines, (3) fundable project goals. All mutable
state (goals, ORL level, server commands) enters the system as signed
aqua-data through the existing `POST /v1/leaves` endpoint, differentiated
by template type and DID permissions. The page is a pure viewer.

## Design Principles

These are inherited from the project `CLAUDE.md` and are non-negotiable:

- **Fuel, not fee.** The service is free. Contributions are "fuel" that
  powers the machine. Never use "fee" in specs, code, or docs.
- **Complete orthogonality.** BTC and ETH are independent models. No
  cross-chain binding, no exchange rates, no shared balances. They share
  only the BTC difficulty epoch as a clock.
- **Forkability is governance.** The spec and service are open and meant
  to be copied. Never design for lock-in.
- **Aqua-on-Aqua accountability.** The operational budget must be tracked
  using the Aqua Protocol itself. This is structural, not optional.

## Brand Identity

Per the inblock.io brand guide:

| Token | Value | Role |
|---|---|---|
| `--accent` | `#E8611A` | Brand orange, sole chromatic accent |
| `--define-blue` | `#4895ef` | Semantic: define pillar |
| `--enforce-amber` | `#d97706` | Semantic: enforce pillar |
| `--proof-green` | `#2a8a5a` | Semantic: prove pillar |
| `--sans` | Sora | Primary typeface (Google Fonts) |
| `--mono` | JetBrains Mono | Protocol data: DIDs, hashes, timestamps |

Both light and dark themes are first-class. Use CSS custom properties,
never hardcoded hex. Dark theme: cool zinc greys (`--bg: #0f0f13`,
`--surface: #1a1a20`). Light theme: warm stone greys (`--bg: #fafaf9`,
`--surface: #ffffff`).

Tone: mission-driven, approachable, purpose-led. Think Mozilla or Let's
Encrypt. Clear call to action, accessible language, supportive tone.

## Architecture

### Data Flow

```
CLI Operator (aqua-rs-cli)
  |
  | Signs aqua-templates (bounty.create, bounty.edit, bounty.close,
  | orl.promote, server.command)
  |
  v
POST /v1/leaves (SIWE auth, DID + template permissions)
  |
  | Template router:
  |   operator DID + recognized template -> process command
  |   any DID -> timestamp only (existing behavior)
  |
  v
fjall storage (operational record)
  |
  | SSE broadcast on state change
  |
  v
GET / (status page HTML)
GET /events (SSE stream)
```

### Key Decisions

1. **Single ingestion path.** All data enters via `POST /v1/leaves`.
   Template type + DID permissions determine processing. No separate
   admin API.

2. **SSE for real-time.** `GET /events` streams epoch seals, anchor
   confirmations, goal updates, ORL changes. The page is read-only;
   WebSocket is unnecessary.

3. **Goals as aqua-trees.** Each funding goal is a revision chain.
   Create, edit, close are revisions submitted as signed aqua-templates.
   Donors can verify that a goal description has not been tampered with.

4. **Embedded HTML + vanilla JS.** The page is an embedded HTML string
   in the Rust binary (consistent with the existing `landing.rs`
   pattern). It fetches live data from existing API endpoints
   (`/health`, `/v1/schedule`, `/v1/epochs`) on load, then subscribes
   to `/events` for real-time updates. No frontend build toolchain,
   no static file serving. The CSS and JS are inlined.

5. **ORL badge.** The Operational Readiness Level badge is displayed in
   the upper-right corner per the ORL skill spec. Clickable to expand
   the full checklist panel. Machine-readable at
   `/.well-known/aqua-orl`.

## Section 1: Mission / Vision / WHY

A centered hero block. No stock photography, no decorative images.

**Content:**

- Eyebrow: "Aqua Timestamp Service" (orange, uppercase, letterspaced)
- Headline: "A free anchor of trust for a world that needs it"
- Body: "Trust is eroding. Uncertainty is rising. We made it our mission
  to provide a free, public timestamping service that anchors data
  integrity across jurisdictions and blockchains. No accounts. No fees.
  Just proof."
- Two value pills:
  - "Fastest multi-chain publishing" (blue accent)
  - "Most trusted cross-jurisdiction anchoring" (green accent)

This section is static content, not data-driven.

## Section 2: Operational Overview

All data in this section is live, fetched from the API on page load and
updated via SSE.

### Publishing Channels

Three cards in a row, one per anchor method:

| Channel | Network | Status | Settlement | Data Source |
|---|---|---|---|---|
| Ethereum | Sepolia (testnet) | active (green dot) | ~12s block time | `/v1/schedule`, `/v1/epochs` |
| qTSA | EU / eIDAS | active (green dot) | instant (RFC 3161) | `/v1/schedule`, `/v1/epochs` |
| Bitcoin | mainnet | planned (grey dot, dimmed) | ~10min block time | static until funded |

Each active channel card shows:
- Status dot (green = online, red = degraded, grey = planned)
- Channel name and network/jurisdiction
- Settlement speed (maximum theoretical)
- Current epoch cycle duration
- Time since last anchor (relative, live-updating)

The Bitcoin card is dimmed at 50% opacity with a "planned" badge and a
link to its funding goal in Section 3.

### Service Statistics

Four stat cards in a row, live-updated:

| Stat | Data Source |
|---|---|
| Epochs sealed | `/v1/epochs` (count) |
| Leaves timestamped | `/v1/epochs` (sum of leaf counts) |
| Uptime percentage | `/health` (calculated from `started_at`) |
| Online since | `/health` (`started_at`, relative) |

All numbers displayed in JetBrains Mono.

## Section 3: Support the Project

Header: "Help us build trust"
Subheader: "This is a non-profit activity of inblock.io. All goals are
aqua-verified and trackable."

### Funding Goals

An extensible list of goal cards. Each goal is an aqua-tree, managed
via signed aqua-templates through the CLI. For Phase 1, the initial
goals are hardcoded; Phase 2 makes them dynamic via the `/v1/goals`
endpoint.

**Goal 0: Burn My Crypto**
- Status: active (green badge)
- Description: "Send small amounts to prove the pipeline works. Test your
  wallet, fuel the machine."
- Wallets: 1 ETH (service address `0x55Fc...634f`), 1 BTC (FIXME)
- No funding target (open-ended)

**Goal 1: Ethereum Mainnet**
- Status: funding (amber badge)
- Target: 5.0 ETH
- Description: "Move from Sepolia testnet to Ethereum mainnet anchoring.
  50% fuels timestamping, 50% covers operational hardening and
  maintenance."
- Wallets: ETH fuel (`0x55Fc...634f`), ETH ops (FIXME)
- Progress bar (blue fill)

**Goal 2: Bitcoin Direct Timestamping**
- Status: funding (amber badge)
- Target: 0.25 BTC
- Description: "Direct OP_RETURN anchoring instead of proxy through
  OpenTimestamps.org. 50% fuels timestamping, 50% covers operational
  hardening and maintenance."
- Wallets: BTC fuel (FIXME), BTC ops (FIXME)
- Progress bar (amber fill)
- Execution trigger: activates when target is reached

### Budget Model

Each goal with a funding target splits contributions:

- **Fuel wallet:** powers the timestamping machine directly (gas, tx fees)
- **Ops wallet:** operational expenses (architecture hardening,
  maintenance, diligence)

The split starts at 50/50. As funding grows, the operational percentage
follows a logarithmic curve. FIXME: the curve model is assigned to
another agent and will be integrated when available.

### Wallet Summary

| # | Chain | Purpose | Address | Notes |
|---|---|---|---|---|
| 1 | ETH | Fuel (timestamping) | `0x55Fcf9F8C1287cB462aa3c1C97E2298d221c634f` | Service key, already on server |
| 2 | ETH | Operations | FIXME | Key management by another agent |
| 3 | BTC | Fuel (timestamping) | FIXME | Key management by another agent |
| 4 | BTC | Operations | FIXME | Key management by another agent |

## ORL Integration

### Badge

- Position: fixed, upper-right corner of the page
- Content: colored dot + "ORL-N LevelName"
- Click: expands a panel overlay
- Mobile: collapses to just the colored dot; tap to expand

### Expanded Panel

Shows on click/tap:

1. Current level with colored dot and name
2. User expectation summary (one line from the ORL spec)
3. Five-segment progress bar (colored segments for achieved levels,
   grey for unachieved)
4. Checklist: met criteria (green check) and unmet criteria for the
   next level (red X)
5. Links to `/.well-known/aqua-orl` and `ORL.md` on GitHub

### /.well-known/aqua-orl Endpoint

New endpoint returning machine-readable JSON:

```json
{
  "orl": 2,
  "label": "Development",
  "color": "#F97316",
  "since": "2026-05-17",
  "assessed_by": "tim.bansemer@inblock.io",
  "next_level_blockers": [
    "Security review not started",
    "Backup restore not verified",
    "Monitoring and alerting not active",
    "Dependency audit not completed"
  ],
  "checklist_url": "https://github.com/inblockio/aqua-timestamps/blob/main/ORL.md"
}
```

### ORL Promotion

ORL level changes are submitted as signed aqua-templates via
`POST /v1/leaves` by an operator DID. The server validates the
template, updates the stored ORL state, and broadcasts the change
via SSE. The badge updates live.

## SSE Event Stream

New endpoint: `GET /events`

Returns `text/event-stream` with the following event types:

| Event Type | Payload | Trigger |
|---|---|---|
| `epoch:sealed` | `{epoch_id, leaf_count, merkle_root, timestamp}` | Epoch sealer completes |
| `anchor:evm` | `{epoch_id, tx_hash, block, network}` | EVM anchor confirmed |
| `anchor:qtsa` | `{epoch_id, tsa_provider, gen_time}` | qTSA anchor confirmed |
| `goal:updated` | `{goal_id, status, progress}` | Goal state changes |
| `orl:changed` | `{level, label, color}` | ORL promotion |
| `health:tick` | `{uptime_secs, epochs_total, leaves_total}` | Periodic (every 60s) |

The page subscribes on load and updates the DOM incrementally.
Reconnection is handled by the browser's native `EventSource` with
`Last-Event-ID` support.

## Template-Based Mutations (Phase 2)

Phase 2 introduces aqua-template recognition in the leaf processing
pipeline. The following templates are recognized when submitted by an
operator DID:

| Template | Action | Fields |
|---|---|---|
| `bounty.create` | Creates a new funding goal | title, description, target_amount, chain, fuel_address, ops_address |
| `bounty.edit` | Creates a new revision of an existing goal | goal_id (previous_revision), updated fields |
| `bounty.close` | Closes a goal (funded or cancelled) | goal_id, reason |
| `orl.promote` | Updates the ORL level | new_level, assessment_notes |
| `server.command` | Operator commands | command_type, parameters |

All mutations are revisions in an aqua-tree. The full history is
the operational record. Edits to a goal create a new revision linked
to the previous one, not an overwrite.

### Permission Model

The existing `[auth].allowlist` in config gains a role dimension:

- **operator DIDs:** can submit all template types including bounty
  management, ORL promotion, and server commands
- **public DIDs:** can submit leaves for timestamping only (existing
  behavior, unchanged)

The server checks: (1) is the DID authenticated via SIWE? (2) does the
leaf contain a recognized template? (3) does the DID have the required
role for that template type? If (2) is false, the leaf is timestamped
normally. If (2) is true but (3) is false, the request is rejected
with 403.

## New Endpoints Summary

| Method | Path | Purpose | Auth |
|---|---|---|---|
| GET | `/` | Status page HTML (replaces current landing) | None |
| GET | `/events` | SSE event stream | None |
| GET | `/.well-known/aqua-orl` | Machine-readable ORL JSON | None |
| GET | `/v1/goals` | List active funding goals (Phase 2) | None |
| GET | `/v1/goals/{id}` | Goal detail with revision history (Phase 2) | None |

## Build Phases

### Phase 1: Static Status Page + SSE

- Replace `/` landing page with the three-section status page
- Embedded HTML in `landing.rs` (existing pattern), vanilla JS, inblock.io brand
- Fetch live data from existing endpoints on page load
- Implement `GET /events` SSE endpoint broadcasting epoch/anchor events
- Implement `GET /.well-known/aqua-orl` with hardcoded initial assessment
- Create `ORL.md` in project root
- Hardcode initial three funding goals in the HTML
- ORL badge with expand/collapse interaction

### Phase 2: Goal Management via Aqua-Templates

- Define aqua-template schemas for `bounty.create`, `bounty.edit`,
  `bounty.close`
- Add template recognition to the leaf processing pipeline
- Add role-based permission checking (operator vs public DID)
- New fjall storage partition for goals
- Implement `GET /v1/goals` and `GET /v1/goals/{id}` endpoints
- SSE `goal:updated` events
- Page dynamically renders goals from the API instead of hardcoded HTML

### Phase 3: ORL + Server Commands via Aqua-Templates

- Define `orl.promote` and `server.command` template schemas
- Wire ORL changes through the template pipeline
- SSE `orl:changed` events update the badge live
- Server command framework (scope TBD based on operational needs)

### Phase 4: Real-Time Visualization

- FIXME: model and implementation assigned to another agent
- Placeholder in the page layout for where the visualization will live
- Goal: real-time visual representation of the anchoring pipeline

## Out of Scope

- Wallet key generation and secure key management (another agent)
- Logarithmic budget curve formula (another agent)
- Real-time visualization implementation (another agent)
- Bitcoin anchor implementation (separate milestone)
- Ethereum mainnet migration (gated on Goal 1 funding)
- User accounts or authentication on the status page (it is read-only)
