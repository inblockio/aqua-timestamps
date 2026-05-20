# Handover: Fuel Bonding Curve Design Session (2026-05-20)

## What was accomplished

Designed the Aqua L1 Operational Fuel Bonding Curve from scratch using the
logic model framework. Three spec documents were created or updated:

| Document | Status | Content |
|---|---|---|
| `Spec_Aqua_L1_Operational_Fuel_Bonding_Curve.md` | v0.1.0-draft | Two independent logarithmic fee curves (ETH + BTC), shared BTC difficulty clock, founder reward mechanics |
| `Spec_Aqua_Trust_Competition_Model.md` | v0.1.0-draft | Forkability as governance, race-to-bottom trust economics, Aqua-on-Aqua operational accounting |
| `Spec_Aqua_L1_Timestamping_Bonding_Curve.md` | Pre-existing | Publication rate curve (the "inverse" of the fuel curve); read as input, not modified |

Project `CLAUDE.md` was updated with a new "Economic design principles"
section capturing four hard rules: fuel not fee, complete orthogonality,
forkability is governance, Aqua-on-Aqua accountability.

## Key design decisions made

1. **"Fuel" not "fee".** The service is free. Fuel is what contributors
   provide to power the machine.

2. **Two independent curves, one shared clock.** BTC and ETH are the same
   model in two orthogonal worlds. BTC hash difficulty epoch (~2 weeks) is
   the shared evaluation clock. The difficulty VALUE never enters any formula.

3. **Logarithmic decay from 50% to 2%.** Single tuning parameter `L` shared
   across both chains. `L = 2 * ln(I_half / I_threshold)`.

4. **Founder reward: 0.5% per chain, independent caps.** BTC capped at 10 BTC,
   ETH capped at 500 ETH. Each cap hit reduces that chain's fuel by 0.5pp.
   Terminal rate after both caps: 1%.

5. **Founder activation gate.** Reward only activates when max publishing rate
   is achieved on BOTH chains (r_eth >= 0.99 AND r_btc >= 0.99).

6. **Publication speed is separate from fuel allocation.** Fuel curve is
   strategic (biweekly). Publication rate is tactical: ETH every 300 blocks
   (~1h), BTC every 6 blocks (~1h). Both normalize to monthly projection
   assuming no new fuel.

7. **Forkability is governance.** The spec is open and meant to be copied.
   Operational accountability comes from competitive pressure.

## Corrections made during session

- **BTC hash difficulty is a clock, not a formula input.** Initial model
  incorrectly used difficulty as a normalization factor for the fee curve.
  Corrected to: difficulty triggers evaluation; the value never enters
  any calculation.

- **BTC publication rate adjusts every 6 blocks (~1h), not every 2016
  blocks (~2w).** Same hourly cadence as ETH's 300-block adjustment.

---

## FIRST TOPIC FOR NEXT SESSION

### The (A)/(B) split is NOT managed operationally

The fuel curve spec currently says the split between (A) anchoring and
(B) operational budget is "managed operationally, not by formula." This
is WRONG. The corrected design:

**The (A)/(B) split is managed by smart contract, evaluated biweekly,
with BTC piped into Ethereum via wrapped BTC.**

### What we know

1. **An Ethereum smart contract governs the fuel split.** The contract
   receives fuel and distributes it between:
   - (A) The spending wallet (anchoring: gas for publishing hashes)
   - (B) The operational wallet (infrastructure, development, etc.)

2. **Wrapped BTC as price mapper.** Payments made in BTC are wrapped and
   made available in the Ethereum world. The wrapping bridges BTC into
   the smart contract's domain so a single Ethereum contract can govern
   the split for BOTH chains' fuel.

3. **Founder key controls wallet assignment.** Three wallets are involved:
   - The **smart contract wallet** (holds incoming fuel)
   - The **spending wallet** (receives (A) anchoring allocation)
   - The **operational wallet** (receives (B) operational allocation)

   The founder's key is the only authorization needed for initial setup.
   The founder can SET the spending wallet and operational wallet addresses.
   After init, the smart contract executes the split deterministically
   based on the fuel curve.

4. **Evaluation cadence.** The split is recalculated every 2 weeks (aligned
   with the BTC difficulty epoch clock), matching the fuel curve evaluation.

### What we don't know (the biggest open question)

**How do we pipe BTC into Ethereum in a trustless way so it is available
for the smart contract?**

Options to explore (starting points, not exhaustive):

| Approach | Trust model | Maturity |
|---|---|---|
| **wBTC (BitGo)** | Custodial (BitGo consortium) | Production, high liquidity |
| **tBTC v2 (Threshold Network)** | Threshold cryptography (honest majority) | Production, moderate liquidity |
| **renBTC** | Deprecated (Ren shutdown 2023) | Dead |
| **sBTC (Stacks)** | Bitcoin-native, Stacks consensus | Newer, different trust assumptions |
| **BitVM bridges** | Optimistic verification on Bitcoin | Experimental, potentially trustless |
| **Atomic swaps** | Trustless (HTLC) | No wrapping; requires counterparty |

Key questions to resolve:
- What trust level is acceptable? (Custodial wBTC vs threshold tBTC vs experimental BitVM)
- Does the wrapping need to be fully trustless, or is threshold trust acceptable given that the service itself is forkable (trust competition model)?
- How does wrapping latency affect the biweekly evaluation cycle?
- What is the minimum viable bridge for an MVP? (Can we start with tBTC and upgrade later?)

### Architectural implication

This changes the "complete orthogonality" principle. BTC and ETH remain
orthogonal for INCOME TRACKING and PUBLICATION RATE, but the smart contract
unifies them for FUEL DISTRIBUTION. The two chains' fuel flows through a
single Ethereum contract:

```
BTC fuel in -----> [wrap to tBTC/wBTC] ----+
                                           |
                                    [Ethereum Smart Contract]
                                    [  Fuel Split Logic     ]
                                    [  f% ops / (1-f)% anchor]
                                           |
ETH fuel in ----------------------------->-+
                                           |
                          +----------------+----------------+
                          |                                 |
                   (B) Operational wallet            (A) Spending wallet
                   (set by founder key)              (set by founder key)
                                                           |
                                                +----------+----------+
                                                |                     |
                                          ETH anchoring         BTC anchoring
                                          (native ETH)          (unwrap? or
                                                                 separate BTC
                                                                 wallet?)
```

This raises a follow-on question: does the spending wallet also handle
BTC anchoring via unwrapping, or does BTC anchoring use a separate native
BTC wallet funded through a different path?

### Specs to update after resolution

- `Spec_Aqua_L1_Operational_Fuel_Bonding_Curve.md`: Section 4.5
  "Governance of Operational Budget" needs rewrite. The (A)/(B) split
  is contract-governed, not operationally managed.
- `Spec_Aqua_Trust_Competition_Model.md`: The trust competition model
  still holds for the HUMAN side of (B), but the split itself is now
  deterministic and on-chain. Update to reflect this.
- `CLAUDE.md`: "Economic design principles" may need a fifth bullet
  about contract-governed fuel distribution.

## Other deferred items (not for immediate next session)

- **Choose `L`** (curve shape parameter): 10x ratio (L = 4.61) is the
  balanced default; needs confirmation
- **Subscription model**: per-wallet rate limits tied to fuel contribution
  (captured in hand-over notes in fuel spec)
- **BTC anchoring mechanism**: OP_RETURN or alternative
- **Numerical walk-through validation**: confirm the ETH/BTC tables in
  the fuel spec match the formulas

## Memory records created

| Memory | Type | Key content |
|---|---|---|
| `feedback-difficulty-is-clock` | feedback | BTC difficulty is clock only, never formula input |
| `feedback-fuel-not-fee` | feedback | "Fuel" not "fee"; service is free |
| `project-orthogonal-chain-cadences` | project | ETH 300-block / BTC 6-block pub rate; fuel eval every 2w |
| `project-handover-subscription-model` | project | Deferred subscription model details |
| `project-trust-competition-model` | project | Forkability is governance; race-to-bottom trust |

## Files touched this session

```
New:
  Spec_Aqua_L1_Operational_Fuel_Bonding_Curve.md
  Spec_Aqua_Trust_Competition_Model.md
  docs/handover/session-2026-05-20-fuel-curve-design.md  (this file)

Modified:
  CLAUDE.md  (added "Economic design principles" section)

Not committed. All changes are unstaged.
```
