# Aqua L1 Operational Fuel Bonding Curve

## Version History

| Version | Date | Changes |
|---|---|---|
| 0.1.0-draft | 2026-05-20 | Initial design session. Two independent curves, shared BTC difficulty clock. |
| 0.2.0-draft | 2026-05-20 | Added on-chain fuel split enforcement (ETH smart contract + BTC automated split tx), tBTC v2 bridge for operational funds, 3-key BTC wallet architecture, HSM upgrade path. |

## Logic Model: Adaptive Operational Fuel for Dual-Chain Timestamping

---

## Phase 1: CONTEXT

### What exists

The Aqua Timestamping Service produces root hashes and anchors them to
Ethereum L1 and (planned) Bitcoin. The **publication rate bonding curve**
(`Spec_Aqua_L1_Timestamping_Bonding_Curve.md`) governs how fast to publish
based on available balance and gas cost.

This spec governs the **inverse**: how much of incoming fuel (contributions
to the service) is allocated to anchoring versus operational budget, and how
the fuel percentage decays as the service matures.

### Key terminology

**Fuel, not fee.** The service is free to use. "Fuel" is what contributors
provide to power the machine. It is the total percentage of contributions
that drives both anchoring and operations.

### Operating environment

| Parameter | ETH | BTC |
|---|---|---|
| Block time | ~12 seconds | ~10 minutes |
| Blocks per day | 7,200 | 144 |
| Blocks per 2 weeks | 100,800 | 2,016 |
| Max publication rate | 1 tx / 12s | 1 tx / 10min |
| Fuel evaluation epoch | 100,800 ETH blocks (~2w) | 2,016 BTC blocks (~2w) |
| Publication rate adjustment | Every 300 ETH blocks (~1h) | Every 6 BTC blocks (~1h) |

### Architectural principle: Complete orthogonality

BTC and ETH are **two orthogonal worlds** running the **same model**:

- BTC fuel drives BTC timestamping. ETH fuel drives ETH timestamping.
- No cross-chain binding, no exchange rate, no shared balance.
- The only shared element is the **clock**: BTC difficulty adjustment epoch
  (~2 weeks) triggers evaluation on BOTH chains.
- The BTC hash difficulty value itself does NOT enter any formula. It is
  purely a clock.

---

## Phase 2: GOAL

**Design a fuel bonding curve that:**

1. Starts at 50% fuel allocation during bootstrap
2. Decays logarithmically toward 2% as the service matures
3. Includes a 0.5% founder reward per chain (1% total), capped at 10 BTC
   and 500 ETH independently
4. Founder reward activates only when maximum publishing rate is achieved
   on both chains
5. Each founder cap hit reduces that chain's fuel by 0.5pp independently
6. Drops to 1% terminal rate after both founder caps are reached
7. Operates independently per chain with a shared BTC difficulty epoch clock

**Acceptance criterion:** Two closed-form functions `f_eth(I_eth)` and
`f_btc(I_btc)` with a single shared tuning parameter `L`, provable cap
guarantees, and complete chain orthogonality.

---

## Phase 3: INPUTS

### Variables (per chain, tracked independently)

| Symbol | Meaning | Unit | Source |
|---|---|---|---|
| `I_eth` | Monthly ETH income (2-week rolling avg) | ETH | On-chain accounting |
| `I_btc` | Monthly BTC income (2-week rolling avg) | BTC | On-chain accounting |
| `f_eth` | ETH fuel percentage | `[0.01, 0.50]` | **Output of the ETH curve** |
| `f_btc` | BTC fuel percentage | `[0.01, 0.50]` | **Output of the BTC curve** |
| `r_eth` | ETH publication rate | per block `[0, 1]` | From publication curve (separate spec) |
| `r_btc` | BTC publication rate | per block `[0, 1]` | From publication curve (separate spec) |
| `F_eth` | Cumulative ETH founder payout | ETH | Tracked on-chain |
| `F_btc` | Cumulative BTC founder payout | BTC | Tracked on-chain |

### Constants

| Symbol | Value | Meaning |
|---|---|---|
| `f_0` | 0.50 | Bootstrap fuel percentage |
| `f_min` | 0.02 | Logarithmic floor (1% ops + 0.5% founder) |
| `f_terminal` | 0.01 | Terminal rate (ops only, post-founder) |
| `I_eth_threshold` | 3 ETH/month | ETH bootstrap exit (fixed) |
| `I_btc_threshold` | 0.1 BTC/month | BTC bootstrap exit (fixed) |
| `F_eth_cap` | 500 ETH | ETH founder lifetime cap |
| `F_btc_cap` | 10 BTC | BTC founder lifetime cap |

### Fuel allocation split

| Category | What it covers |
|---|---|
| **(A) Sending hashes** | Gas (ETH) / fees (BTC) for anchoring transactions |
| **(B) Operational budget** | Infrastructure, compute, storage, service development |

The fuel percentage `f` is the total percentage of incoming contributions.
From each contribution:

- `f%` goes to the service (split between operational costs and founder reward)
- `(1-f)%` goes to the anchoring wallet (drives the publication bonding curve)

As the service matures and `f` drops, more fuel flows to anchoring, less to
overhead. The machine becomes more efficient.

### Single tuning parameter

| Symbol | Meaning |
|---|---|
| `L` | Logarithmic decay constant: `L = 2 * ln(I_half / I_threshold)` |

`L` is shared between both chains (same curve shape, different thresholds).
It simultaneously controls:

- **Decay rate**: how quickly fuel percentage drops as income grows
- **Floor income**: the income level at which the 2% floor is reached

This is the complexity collapse: one parameter governs the entire fuel
trajectory on both chains.

### Shared clock

BTC hash difficulty adjustment epoch (~2016 blocks, ~2 weeks). Triggers
evaluation of both chains' fuel curves. The difficulty VALUE does not enter
any formula.

### Evaluation cadences

| Chain | Fuel curve (macro) | Publication rate (micro) | Normalization |
|---|---|---|---|
| ETH | Every 100,800 blocks (~2w) | Every 300 blocks (~1h) | Monthly projection |
| BTC | Every 2,016 blocks (~2w) | Every 6 blocks (~1h) | Monthly projection |

Both chains adjust publication speed hourly. Both evaluate the fuel
percentage biweekly. Same model, same cadences, two orthogonal worlds.

---

## Phase 4: ACTIVITIES + OUTPUTS

### 4.1 The Fuel Bonding Curves

#### Core functions

ETH:

```
f_eth(I_eth) = max( 0.02,  0.50 - 0.48 * ln(I_eth / 3) / L )
```

BTC:

```
f_btc(I_btc) = max( 0.02,  0.50 - 0.48 * ln(I_btc / 0.1) / L )
```

Where `I_eth` and `I_btc` are 2-week rolling averages of monthly income in
ETH and BTC respectively, evaluated at each BTC difficulty epoch.

#### Properties (identical shape per chain)

| Condition | `f` | Behavior |
|---|---|---|
| `I < I_threshold` | `0.50` | Bootstrap: maximum fuel allocation |
| `I = I_threshold` | `0.50` | Phase transition point |
| `I = I_half` | `0.26` | Midpoint (half-activation) |
| `I = I_floor` | `0.02` | Floor reached |
| Post-founder-cap | `0.01` | Terminal rate |

Where `I_floor = I_half^2 / I_threshold` (derived from the curve reaching 2%).

#### Visualization (log-income scale, identical shape for both chains)

```
f (fuel %)
0.50 |*
     | *
     |  *
     |   *
     |    *
0.26 |_ _ _*_ _ _ _ _ _ _ _ _ _ _ _  (midpoint)
     |      *
     |       *
     |        *
     |         *
0.02 |_ _ _ _ _ _*_________________  (floor: 1% ops + 0.5% founder)
0.01 |. . . . . . . . . . . . . . .  (terminal: ops only)
     |            |
0.00 |____________|_________________
     I_threshold  I_half   I_floor   I (log scale)
```

### 4.2 Fuel Decomposition by Phase

```
PHASE 1: BOOTSTRAP
  f = 50%  -->  [50% to service (A+B)]  /  [50% to anchoring wallet]
  Exit: I >= I_threshold (per chain, independently)

PHASE 2: LOGARITHMIC DECAY
  f(I) from 50% --> 2%

  Before founder activation:
    [f% to service (A+B)]  /  [(1-f)% to anchoring wallet]

  After founder activation (r_eth >= 0.99 AND r_btc >= 0.99):
    [(f - 0.5%) service (A+B)] + [0.5% founder]  /  [(1-f)% anchoring]

PHASE 3a: ONE CHAIN'S FOUNDER CAP HIT
  That chain's fuel drops by 0.5pp
  Other chain unaffected

PHASE 3b: BOTH CHAINS' FOUNDER CAPS HIT
  f = 1% on both chains  -->  [1% ops]  /  [99% anchoring]
  Permanent terminal state
```

### 4.3 Separation of Fuel Curve from Publication Speed

The fuel curve and the publication rate curve are **orthogonal calculations**:

```
                    FUEL IN (contributions)
                         |
              +----------+----------+
              |  FUEL CURVE (this)  |  Evaluated every ~2 weeks
              |  f(I) = 50% --> 2%  |  (shared BTC difficulty clock)
              +----------+----------+
                         |
              +----------+----------+
              |                     |
         f% to service       (1-f)% to anchoring
         (ops + founder)      wallet balance B
                                    |
                         +----------+----------+
                         |  PUBLICATION CURVE   |  Evaluated every ~1 hour
                         |  r(B,g) = 1-e^(-N)  |  (300 ETH / 6 BTC blocks)
                         +----------+----------+
                                    |
                              Hash published
                              to L1 chain
```

**ETH publication rate** (adjusts every 300 blocks, ~1 hour):

```
B_eth = current ETH anchoring wallet balance
N_eth = B_eth / g_eth
r_eth = 1 - exp(-N_eth / N_half_eth)
```

Monthly normalization: `N_half_eth` is chosen so the minimum runway is
~1 month (216,000 blocks). Every 300 blocks, the rate re-evaluates based
on current balance, assuming no new fuel arrives.

**BTC publication rate** (adjusts every 6 blocks, ~1 hour):

```
B_btc = current BTC anchoring wallet balance
N_btc = B_btc / g_btc
r_btc = 1 - exp(-N_btc / N_half_btc)
```

Monthly normalization: `N_half_btc` chosen for ~1 month runway (4,320 blocks).

The fuel curve feeds the anchoring wallet. The publication curve spends
the anchoring wallet. They are connected by the balance but governed by
independent formulas.

### 4.4 Founder Reward Mechanics

| Rule | Detail |
|---|---|
| Rate | 0.5% per chain (1% total across both chains) |
| Activation gate | `r_eth >= 0.99` AND `r_btc >= 0.99` (max publishing on BOTH chains) |
| ETH cap | 500 ETH lifetime |
| BTC cap | 10 BTC lifetime |
| On ETH cap | ETH fuel drops 0.5pp (independent of BTC) |
| On BTC cap | BTC fuel drops 0.5pp (independent of ETH) |
| On both caps | Terminal 1% on both chains |
| Address binding | BTC and ETH payout addresses signed by the service Ethereum wallet |

The founder reward is carved from the total fuel percentage, not additive on
top. At the 2% floor: 1% operational + 0.5% founder = the full fuel
allocation. Founders are only paid if the project succeeded (both chains at
max publishing rate).

### 4.5 Governance of Operational Budget

The fuel percentage `f` governs the boundary between the hash world (A) and
the human world (B). The boundary is enforced by on-chain mechanisms on both
chains; within (B), accountability comes from two mechanisms:

1. **Aqua-on-Aqua accounting.** The operational budget is tracked using the
   Aqua Protocol itself. The service that provides data integrity uses its
   own product to account for its own operations.

2. **Competitive accountability.** The spec and service are open and **meant
   to be copied**. If a competitor runs the service leaner and builds more
   trust, users migrate. The original team gets abandoned. Competition is
   the formula that no equation can replace.

No formula governs (B) because no formula can govern human spending. The
fuel bonding curve governs the boundary; within (B), the market governs.

See `Spec_Aqua_Trust_Competition_Model.md` for the full logic model of this
governance mechanism.

### 4.6 On-Chain Fuel Split Enforcement

#### ETH side: Smart contract

An Ethereum smart contract is the source of truth for `f_eth` and `f_btc`.
It receives native ETH fuel, computes the bonding curve, and distributes to
the anchoring wallet and operational wallet deterministically. No human
discretion in the split.

The contract also publishes `f_btc` as readable state so the BTC-side
automation can consume it.

#### BTC side: Automated split transaction

BTC fuel stays in the BTC world. The split is executed as a native Bitcoin
transaction, not routed through Ethereum. Three keys, derived from different
paths on the same mnemonic, control the BTC wallets:

| Wallet | Key derivation | Purpose |
|---|---|---|
| **Intake** | path 1 | Receives all BTC fuel contributions |
| **Anchoring** | path 2 | Funds BTC timestamping (OP_RETURN or similar) |
| **Founder** | path 3 | Founder payout (set at init, signed via Aqua as public proof) |

**Cadence:** Batched biweekly, aligned to the BTC difficulty epoch (~2016
blocks). BTC accumulates in the intake wallet between epochs.

**Execution:** At each epoch boundary, the service:

1. Reads `f_btc` from the Ethereum smart contract (RPC call)
2. Constructs a split transaction from the intake wallet:
   - `(1-f)%` to the anchoring wallet (stays BTC)
   - `0.5%` to the founder wallet (stays BTC; skipped when below dust
     limit of 546 sats, accumulated to next epoch)
   - `(B)%` remainder to the operational accumulator
3. Signs and broadcasts the split transaction

This is fully automated by the service. No manual intervention.

**Operational funds bridge:** The operational accumulator auto-sends to the
tBTC v2 bridge when its balance exceeds **0.01 BTC**. This threshold keeps
bridge fees under 1% of the transferred amount. Below threshold, funds
accumulate until the next epoch pushes the balance over.

The bridge destination is a pre-defined, auditable tBTC v2 minting address.
Upgrade path: BitVM bridge or ZK light client relay when production-ready
(estimated 2027+).

**What crosses the bridge:** Only the operational (B) portion of BTC fuel,
plus the accounting information (how much was raised). Anchoring funds and
founder payout never leave the BTC world.

```
BTC contributors -----> [Intake Wallet]
                              |
                    every ~2016 blocks:
                    read f_btc from ETH contract
                    sign split tx
                              |
              +---------------+---------------+
              |               |               |
        (1-f)% to       0.5% to         (B)% to
        Anchoring        Founder        Operational
        Wallet           Wallet         Accumulator
        (BTC native)     (BTC native)        |
              |                              |
        BTC timestamps              when balance > 0.01 BTC:
        (OP_RETURN)                 auto-bridge via tBTC v2
                                    to ETH operational wallet
```

#### Wallet lifecycle

| Phase | Key storage | Transition trigger |
|---|---|---|
| **Bootstrap** | Software wallet (mnemonic in secure enclave or env) | Service launch |
| **Operational** | HSM (self-hosted HashiCorp Vault + secp256k1 plugin) | Traction warrants it |

All three BTC keys and the ETH service key migrate together. The HSM
upgrade does not change addresses (same mnemonic, same derivation paths).

#### Auditability

Every split transaction is a public Bitcoin transaction. Anyone can:

1. Read `f_btc` from the Ethereum smart contract
2. Verify the split transaction outputs match the published percentage
3. Confirm founder payout matches the 0.5% carve-out (or was correctly skipped)
4. Trace operational funds through the tBTC bridge to the ETH operational wallet

Discrepancies are visible on-chain and tracked via Aqua-on-Aqua accounting.
If the operator cheats, the service gets forked (see
`Spec_Aqua_Trust_Competition_Model.md`).

#### Orthogonality, refined

BTC and ETH remain orthogonal for income tracking and publication rate.
The bridge introduces a narrow, one-directional dependency: the BTC split
reads `f_btc` from the Ethereum contract, and operational funds flow
BTC-to-ETH. No value flows ETH-to-BTC. No cross-chain exchange rate enters
any formula. The bridge carries a parameter and operational funds, not
anchoring logic.

### 4.7 If-Then Causal Chain

```
IF   contributors provide ETH fuel
THEN the Ethereum smart contract receives it, tracks I_eth, computes f_eth

IF   contributors provide BTC fuel
THEN the BTC intake wallet accumulates it until the next epoch

IF   BTC difficulty epoch boundary is reached (~2016 blocks)
THEN evaluate both fuel curves with current 2-week rolling averages
     ETH: contract updates f_eth on-chain
     BTC: service reads f_btc from contract, signs split tx

IF   I_chain < I_threshold for that chain
THEN f = 50% (bootstrap; maximum fuel to service)

IF   I_chain >= I_threshold
THEN f = logarithmic curve from 50% --> 2%

IF   ETH fuel percentage f_eth is determined
THEN contract distributes (1-f)% to ETH anchoring wallet, f% to operational

IF   BTC split tx is broadcast
THEN (1-f)% to BTC anchoring wallet, 0.5% to founder, (B)% to accumulator

IF   BTC operational accumulator balance > 0.01 BTC
THEN auto-bridge to ETH via tBTC v2 (pre-defined auditable address)

IF   anchoring wallet has balance (either chain)
THEN publication curve determines publishing speed
     (ETH: re-evaluated every 300 blocks, ~1h)
     (BTC: re-evaluated every 6 blocks, ~1h)
     (both normalized to monthly projection assuming no new fuel)

IF   r_eth >= 0.99 AND r_btc >= 0.99
THEN founder reward activates (0.5% per chain carved from fuel)

IF   founder cap reached on a chain (500 ETH or 10 BTC)
THEN that chain's fuel drops 0.5pp; other chain unaffected

IF   both founder caps reached
THEN terminal 1% fuel rate on both chains (permanent)
```

---

## Phase 5: BOUNDARY CONDITIONS

### Assumptions (must hold)

| # | Assumption | Risk if violated |
|---|---|---|
| A1 | BTC difficulty epochs occur ~every 2016 blocks | Evaluation cadence changes; use block count as fallback |
| A2 | ETH block time remains ~12s | 300-block window changes in wall-clock time |
| A3 | BTC block time remains ~10min | 6-block window changes in wall-clock time |
| A4 | Service has funded wallets on both chains | Cannot publish on unfunded chain |
| A5 | tBTC v2 bridge maintains 1:1 BTC peg and remains operational | Operational funds stuck in BTC accumulator; anchoring + founder unaffected |
| A6 | BTC anchoring mechanism exists (OP_RETURN or similar) | BTC timestamping cannot start without this |
| A7 | Service can read Ethereum contract state from the BTC-side automation | BTC split falls back to last known f_btc; never stalls |
| A8 | Same mnemonic, different derivation paths produces distinct keys | Standard BIP-32/44; well-established |

### Exclusions (out of scope)

- **Cross-chain normalization:** No BTC/ETH exchange rate, difficulty scaling,
  or shared balance
- **Subscription model:** Out of scope (see Hand-Over Notes)
- **Fuel acquisition model:** How fuel enters the system is separate from how
  it is allocated
- **L2 or sidechain considerations:** L1 only on both chains
- **Bridge selection beyond tBTC v2:** BitVM / ZK light client upgrades are
  acknowledged as future path; not designed here
- **HSM key ceremony:** Migration from software wallet to HSM is operational;
  the spec assumes it preserves addresses

### Invariants (must never be violated)

1. **BTC and ETH curves are completely orthogonal** for income tracking and publication rate
2. **BTC difficulty value never enters any formula** (clock only)
3. **Founder reward never activates before max publishing rate on BOTH chains**
4. **Fuel percentage never goes below 1%** (terminal floor)
5. **Fuel percentage never exceeds 50%** (bootstrap ceiling)
6. **Each founder cap triggers only its own chain's 0.5pp reduction**
7. **BTC anchoring funds and founder payout never leave the BTC world**
8. **Only operational (B) funds cross the tBTC bridge** (one direction: BTC to ETH)
9. **The Ethereum smart contract is the single source of truth for f_btc and f_eth**
10. **All three BTC keys derive from the same mnemonic** (different paths)

### Risks

| Risk | Mitigation |
|---|---|
| One chain has income, other doesn't | Independent curves; each chain operates at its own pace |
| Founder activation gate never reached | Founders get nothing; service runs sustainably |
| Gas/fee spike on one chain | Publication curve auto-reduces rate; fuel curve unaffected |
| BTC difficulty epoch timing varies | Use block count (2016), not wall clock |
| tBTC v2 bridge goes down or loses peg | Operational funds accumulate in BTC; anchoring + founder unaffected. Resume bridging when restored. Upgrade path: BitVM / ZK relay |
| Ethereum RPC unreachable at BTC epoch | Fall back to last known f_btc; log the fallback; retry next block |
| BTC split tx fee spike makes small epochs uneconomical | Batched biweekly already minimizes tx count; skip split if accumulated balance is below 2x estimated fee |
| Mnemonic compromise | Software phase: same risk as current service key. HSM phase: key material never leaves hardware |

---

## Parameter Selection Guide

### Choosing L (shared curve shape)

`L = 2 * ln(I_half / I_threshold)`. Since both chains share `L` but have
different thresholds, the ratio `I_half / I_threshold` is the real knob:

| `I_half / I_threshold` ratio | `L` | Character | ETH I_half | BTC I_half |
|---|---|---|---|---|
| 5x | 3.22 | Aggressive (fast decay) | 15 ETH/mo | 0.5 BTC/mo |
| 10x | 4.61 | Balanced | 30 ETH/mo | 1.0 BTC/mo |
| 20x | 5.99 | Conservative | 60 ETH/mo | 2.0 BTC/mo |
| 50x | 7.82 | Very conservative | 150 ETH/mo | 5.0 BTC/mo |

### Derivation: "How much income for X% fuel?"

For a target fuel `f_target`:

```
I_needed = I_threshold * exp( (0.50 - f_target) * L / 0.48 )
```

| Target fuel | Multiplier on `I_threshold` (L = 4.61) |
|---|---|
| 40% | 2.15x |
| 30% | 4.64x |
| 26% | 6.81x (= I_half / I_threshold) |
| 20% | 14.7x |
| 10% | 68.5x |
| 5% | 316x |
| 2% | 4,642x (= I_floor / I_threshold) |

### Numerical walk-through (ETH, L = 4.61)

`I_threshold = 3 ETH/month`, `I_half = 30 ETH/month`,
`I_floor = 300 ETH/month`

| Monthly ETH income | Fuel % | Anchoring % | Phase |
|---|---|---|---|
| 1 ETH | 50.0% | 50.0% | Bootstrap |
| 3 ETH | 50.0% | 50.0% | Transition |
| 10 ETH | 37.5% | 62.5% | Log decay |
| 30 ETH | 26.0% | 74.0% | Midpoint |
| 100 ETH | 13.5% | 86.5% | Log decay |
| 200 ETH | 6.2% | 93.8% | Log decay |
| 300 ETH | 2.0% | 98.0% | Floor |
| Post-cap | 1.0% | 99.0% | Terminal |

### Numerical walk-through (BTC, same L = 4.61)

`I_threshold = 0.1 BTC/month`, `I_half = 1.0 BTC/month`,
`I_floor = 10 BTC/month`

| Monthly BTC income | Fuel % | Anchoring % | Phase |
|---|---|---|---|
| 0.05 BTC | 50.0% | 50.0% | Bootstrap |
| 0.1 BTC | 50.0% | 50.0% | Transition |
| 0.33 BTC | 37.5% | 62.5% | Log decay |
| 1.0 BTC | 26.0% | 74.0% | Midpoint |
| 3.3 BTC | 13.5% | 86.5% | Log decay |
| 6.7 BTC | 6.2% | 93.8% | Log decay |
| 10 BTC | 2.0% | 98.0% | Floor |
| Post-cap | 1.0% | 99.0% | Terminal |

---

## Relationship to Publication Rate Curve

This spec and the existing publication rate spec
(`Spec_Aqua_L1_Timestamping_Bonding_Curve.md`) are orthogonal:

| Concern | This spec (Fuel) | Publication spec (Speed) |
|---|---|---|
| Question answered | How much fuel to allocate? | How fast to publish? |
| Formula | `f(I) = max(0.02, 0.50 - 0.48*ln(I/I_thr)/L)` | `r(B,g) = 1 - exp(-B/(g*N_half))` |
| Input | Income `I` | Balance `B`, cost `g` |
| Output | Fuel percentage `f` | Publication rate `r` |
| Curve type | Logarithmic decay (50% to 2%) | Exponential saturation (0 to 1) |
| Connection | Fuel `(1-f)%` feeds the anchoring wallet balance `B` |

The fuel curve determines HOW MUCH goes into the publishing wallet.
The publication curve determines HOW FAST to spend it. They are connected
by the balance but governed by independent formulas and independent
evaluation cadences.

---

## Formal Summary

### The model in two equations

ETH:

```
f_eth(I_eth) = max( 0.02,  0.50 - 0.48 * ln(I_eth / 3) / L )
```

BTC:

```
f_btc(I_btc) = max( 0.02,  0.50 - 0.48 * ln(I_btc / 0.1) / L )
```

### The model in one sentence

The fuel percentage is a logarithmic decay curve over monthly income,
evaluated independently per chain at a shared two-week cadence (BTC
difficulty epoch), with a single parameter `L` that sets the decay rate
and a founder reward that activates only at maximum publishing capacity.

### Why logarithmic and not another curve

| Alternative | Why rejected |
|---|---|
| Exponential: `f = f_min + (f_0-f_min) * exp(-I/k)` | Drops too fast at moderate income; rewards early growth less |
| Linear: `f = f_0 - k*I` | No natural floor; fuel goes negative at high income |
| Hyperbolic: `f = k/I` | Two parameters; no clean floor guarantee |
| Step function | No gradual adaptation; wasteful above threshold |

The logarithmic curve `f_0 - k * ln(I)` rewards early growth (fast fuel
reduction at moderate income) while compressing slowly at high volumes
(the last few percent are hard to earn). This matches the economic reality:
early operational overhead is high and drops quickly with scale, but the
final margin compression takes sustained, large-scale operation.

---

## Hand-Over Notes (Out of Scope for v0.1.0)

### Subscription model (future spec)

The service will limit:

- Number of new wallets that can register
- Maximum hashes transmittable per wallet per day

Based on contribution to fuel:

- Track fuel contribution per wallet
- Hashes/day allocation increases with contribution
- **1 hash/second is free** with a starting config of **epoch = 10 minutes**

### Address binding

BTC and ETH founder payout addresses are set at init time and signed via
Aqua Protocol as public proof of the configuration. The BTC founder wallet
address is derived from the same mnemonic (different path) and published as
part of the service's public init documentation.

### Bridge upgrade path

tBTC v2 is the initial bridge for operational funds. When trustless
alternatives reach production maturity:

| Bridge | Expected maturity | Trust model |
|---|---|---|
| tBTC v2 (current) | Production now | Threshold (~100 operators) |
| BitVM bridge | ~2027 | 1-of-n fraud proof (near-trustless) |
| ZK light client relay | ~2027-2028 | Cryptographic proof (trustless) |

The bridge destination address is a configurable parameter. Upgrading the
bridge means changing one address and verifying the new bridge's minting
contract. No other part of the system changes.
