# Aqua Trust Competition Model

## Version History

| Version | Date | Changes |
|---|---|---|
| 0.1.0-draft | 2026-05-20 | Initial capture from fuel bonding curve design session. |

## Logic Model: Forkability as Governance

---

## Phase 1: CONTEXT

### What exists

The Aqua Timestamping Service anchors root hashes to Ethereum L1 and
(planned) Bitcoin. It is funded by "fuel" (contributions that power the
machine). The fuel bonding curve (`Spec_Aqua_L1_Operational_Fuel_Bonding_Curve.md`)
governs how incoming fuel is split between anchoring (A) and operational
budget (B).

### The accountability problem

The hash world (A) is self-accountable: on-chain transactions are
transparent and verifiable by default. No trust required.

The operational world (B) is the human world: infrastructure, development,
coordination. It cannot be verified purely on-chain. How do you ensure the
operational budget is spent responsibly without introducing a governing
authority?

### Prior art

Bitcoin solved miner accountability through open competition: anyone can
mine, the most efficient wins, inefficient miners are abandoned. The protocol
does not govern how miners spend their revenue; the market does.

---

## Phase 2: GOAL

**Establish a governance model for the operational budget that requires no
central authority, no voting mechanism, and no on-chain enforcement of
off-chain spending, while ensuring long-term accountability and efficiency.**

Acceptance criterion: a causal chain from openness to accountability that
does not depend on the goodwill of the original team.

---

## Phase 3: INPUTS

### Two accountability domains

| Domain | What | Accountable how |
|---|---|---|
| **(A) Hash world** | Anchoring transactions (gas, fees) | On-chain by default. Every transaction is verifiable. |
| **(B) Operational world** | Infrastructure, compute, development, coordination | Two mechanisms (see Phase 4) |

### Design assets

| Asset | Role |
|---|---|
| Open spec (this repo) | Enables any team to understand and replicate the service |
| Open code (this repo) | Enables any team to fork and deploy |
| Aqua Protocol | Provides data accounting for operational decisions |
| Fuel bonding curve | Transparent, deterministic fuel allocation; no discretionary spending |

---

## Phase 4: ACTIVITIES + OUTPUTS

### 4.1 Mechanism 1: Aqua-on-Aqua Operational Accounting

The operational budget is tracked using the Aqua Protocol itself. The
service that provides data integrity uses its own product to account for
its own operations.

This means:

- Operational decisions, expenditures, and resource allocation are captured
  as Aqua hash chains
- The data is timestamped, immutable, and verifiable using the same
  infrastructure the service provides to its users
- Anyone can audit the operational record using the same tools they use
  to verify their own timestamps

The service eats its own dogfood. If the Aqua Protocol is good enough to
trust for timestamping, it is good enough to trust for operational
transparency.

### 4.2 Mechanism 2: Competitive Accountability (Race to the Bottom)

The spec and service are open and **meant to be copied**.

This is not a side effect of open source. It is the governance model.

#### The causal chain

```
IF   the spec is open and complete
THEN any team can understand the service fully

IF   the code is open and deployable
THEN any team can fork and run the service

IF   a competitor runs the service leaner
THEN they can offer lower fuel percentages or faster publishing

IF   a competitor builds more trust (better uptime, transparency, audits)
THEN users migrate to the more trusted operator

IF   users migrate
THEN the original team's income drops

IF   the original team's income drops below threshold
THEN they fall back to bootstrap phase (50% fuel) or cease operations

IF   the original team ceases
THEN the service continues under the more trusted operator
```

#### The race to the bottom

"Race to the bottom" here is positive: operators compete on trust, not
on margin. The dynamics:

| Factor | Effect |
|---|---|
| Lower operational overhead | Lower fuel %, more goes to anchoring, faster publishing |
| Better transparency | More users trust the operator, fuel contributions increase |
| Better uptime | Users depend on the operator, stickiness increases |
| Better audits | Third-party verification builds institutional trust |
| More forks | More competition, more pressure to improve |

The winning operator is the one users trust most. Trust is earned through:
transparency (Aqua-on-Aqua accounting), reliability (uptime and correctness),
and efficiency (low operational overhead).

#### Why this works

The fuel bonding curve is deterministic and transparent. Given the same
income, every operator produces the same fuel split. There is no
discretionary spending within the curve itself. The only discretionary
element is how (B) is spent, and that is governed by competition.

No formula can govern human spending. But if the alternative to
responsible spending is being outcompeted and abandoned, the incentive
structure is sufficient.

### 4.3 Why the Original Team Has No Structural Advantage

| Potential advantage | Why it doesn't hold |
|---|---|
| First mover | Open spec means latecomers start fully informed |
| Code ownership | Open source; forks inherit all engineering |
| Brand recognition | Trust is re-earned continuously; brand is a lagging indicator |
| Founder reward | Activates only at max publishing rate on both chains; requires operational excellence to earn |
| User lock-in | Service is stateless for users (submit hash, get timestamp); switching cost is near zero |

The founder reward mechanism (0.5% per chain, capped) is the only
structural incentive for the original team. It is deliberately designed
to be small (1% total), time-limited (capped at 10 BTC + 500 ETH),
and conditional (requires max publishing rate on both chains). A
competitor who skips the founder reward starts with a 1pp structural
advantage on fuel efficiency.

### 4.4 If-Then Causal Chain

```
IF   the spec and code are open
THEN anyone can fork the service

IF   anyone can fork the service
THEN the original team has no monopoly

IF   there is no monopoly
THEN operators compete on trust and efficiency

IF   operators compete on trust
THEN the most trusted operator attracts the most fuel

IF   the most trusted operator gets the most fuel
THEN they publish the fastest (bonding curve rewards scale)

IF   they publish the fastest
THEN they provide the best service (lowest latency timestamps)

IF   they provide the best service
THEN users contribute more fuel (virtuous cycle)

THEREFORE: openness creates a self-reinforcing trust competition
           that governs operational accountability without authority
```

---

## Phase 5: BOUNDARY CONDITIONS

### Assumptions (must hold)

| # | Assumption | Risk if violated |
|---|---|---|
| A1 | Spec remains open and complete | Incomplete spec prevents meaningful forks |
| A2 | Code remains open and deployable | Non-deployable code creates de facto lock-in |
| A3 | Switching cost for users is near zero | High switching cost kills competition |
| A4 | Aqua Protocol is trusted for data accounting | Self-referential trust breaks if protocol is not credible |
| A5 | Multiple operators can economically sustain the service | Natural monopoly dynamics would undermine competition |

### Invariants (must never be violated)

1. **Never design for lock-in.** Every architectural decision must make
   forking easier, not harder.
2. **Never gate the spec.** The complete specification must be public.
   A competitor should never need to reverse-engineer behavior.
3. **Never introduce proprietary dependencies.** Every component the
   service depends on must be open or replaceable.
4. **Aqua-on-Aqua accounting is mandatory.** The operational budget
   must be tracked using the Aqua Protocol. This is not optional
   transparency; it is structural accountability.

### Exclusions

- **Legal structure:** How the operating entity is legally organized
  is out of scope for this model
- **Dispute resolution:** Conflicts between operators or between
  operators and users are not governed by this model
- **Minimum viable scale:** Whether the service has natural monopoly
  dynamics at small scale is an empirical question, not addressed here

### Risks

| Risk | Mitigation |
|---|---|
| No one forks (insufficient competition) | The spec is designed to be forkable regardless; competition is latent even if not active |
| Race to bottom destroys quality | The fuel bonding curve floor (1-2%) ensures minimum operational funding |
| Aqua-on-Aqua accounting is circular trust | External audits and cross-operator verification break the circularity |
| Dominant operator becomes de facto authority | No structural advantage; any lapse in trust opens the door to competitors |

---

## Formal Summary

### The model in one sentence

The operational budget is governed by competitive accountability: the service
is open and meant to be copied, so the most trusted operator wins and any
team that mismanages operations is abandoned in favor of a better fork.

### The model in one equation

There is no equation. That is the point. The hash world (A) is governed by
deterministic, verifiable on-chain math. The human world (B) is governed by
open competition. Trying to reduce (B) to a formula would be false precision.
The fuel bonding curve governs the boundary between (A) and (B); within (B),
the market governs.
