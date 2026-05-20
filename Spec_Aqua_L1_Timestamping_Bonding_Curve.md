# Aqua L1 Timestamping Bonding Curve

## Logic Model: Adaptive Publication Rate for Ethereum Settlement

---

## Phase 1: CONTEXT

### What exists

Aqua protocol produces **root hashes** (32-byte Keccak-256 digests) summarizing the
current state of hash chains. These hashes need to be anchored to Ethereum L1 for
timestamping and integrity verification.

### Operating environment

| Parameter | Value |
|---|---|
| Ethereum block time | ~12 seconds (PoS, post-Merge) |
| Blocks per day | 7,200 |
| Blocks per week | 50,400 |
| Max publication rate | 1 transaction per block |
| Cost per transaction | `gas_units x gas_price` (variable) |
| Typical gas units (hash store) | ~45,000 gas |
| Gas price | Fluctuates per block (EIP-1559: base fee + priority fee) |

### Constraints

- L1 Ethereum settlement only (no L2, no sidechains)
- Single wallet as the publishing agent
- No external income model in scope (the curve governs spend rate, not fundraising)
- Gas price is exogenous and uncontrollable

---

## Phase 2: GOAL

**Design a single-parameter bonding curve that continuously adjusts root hash publication
frequency on Ethereum L1 based on available ETH balance and current gas costs, such that:**

1. Zero funds produces zero publications
2. Abundant funds approaches one publication per block (12s settlement)
3. The transition is exponential
4. The system never depletes funds faster than a guaranteed minimum runway
5. Gas price fluctuations are absorbed automatically

**Acceptance criterion:** A closed-form function `r(B, g)` with provable sustainability
guarantees and a single tuning parameter.

---

## Phase 3: INPUTS

### Variables

| Symbol | Meaning | Unit | Source |
|---|---|---|---|
| `B` | Current ETH balance of the publishing wallet | wei | On-chain query |
| `g` | Cost of one timestamp transaction | wei | `gas_units x gas_price` |
| `N` | Affordable transaction count (`B / g`) | dimensionless | Derived |
| `r` | Publication rate | publications per block, `[0, 1]` | **Output of the curve** |
| `Delta` | Block interval between publications (`ceil(1/r)`) | blocks | Derived from `r` |

### Single tuning parameter

| Symbol | Meaning | Unit |
|---|---|---|
| `N_half` | Half-activation threshold (affordable txs at which rate reaches ~63%) | transactions |

`N_half` simultaneously controls:
- **Activation sensitivity:** how quickly the rate ramps up with balance
- **Minimum runway guarantee:** the system always maintains at least `N_half` blocks of operation

This dual role is a complexity collapse: one parameter, two concerns, zero tradeoff.

---

## Phase 4: ACTIVITIES + OUTPUTS

### 4.1 The Bonding Curve

#### Core function

```
r(B, g) = 1 - exp(-B / (g * N_half))
```

Equivalently, using the affordable transaction count `N = B / g`:

```
r(N) = 1 - exp(-N / N_half)
```

#### Properties

| Condition | Rate `r` | Behavior |
|---|---|---|
| `B = 0` | `0` | No funds, no publishing |
| `B = g * N_half` | `0.632` | 63% of max rate (half-activation point) |
| `B = 3 * g * N_half` | `0.950` | Near-max rate |
| `B = 4.6 * g * N_half` | `0.990` | Effectively every block |
| `B -> infinity` | `1.0` | Every block (12s L1 settlement) |

#### Visualization

```
r (rate)
1.0 |                                    ___________________
    |                                ////
    |                            ////
    |                        ////
    |                    ////
0.63|_ _ _ _ _ _ _ _ _/_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _
    |                /
    |             ///
    |          ///
    |       ///
    |    ///
    | ///
0.0 |/______________|__________________|__________________
    0            N_half            3*N_half          N = B/g
                                               (affordable txs)
```

### 4.2 Sustainability Proof

**Claim:** The minimum operational runway is always >= `N_half` blocks,
regardless of balance level.

**Proof:**

The ETH burn rate per block is `r * g`. The runway in blocks is:

```
R(B, g) = B / (r * g) = N / r = N / (1 - exp(-N / N_half))
```

Taking the limit as `N -> 0` using L'Hopital's rule (or Taylor expansion):

```
lim(N->0) N / (1 - exp(-N/N_half))
= lim(N->0) N / (N/N_half)     [first-order Taylor: 1 - e^(-x) ~ x for small x]
= N_half
```

For all `N > 0`:

```
R(N) = N / (1 - exp(-N/N_half)) > N_half
```

This holds because `(1 - e^(-x))/x` is strictly decreasing for `x > 0`, starting
from `1/N_half` at `x = 0` and approaching `0` as `x -> infinity`.

**Therefore:** the system always maintains a minimum runway of `N_half` blocks.
At the half-activation point (`N = N_half`), the actual runway is `1.58 * N_half`.
At high balances, the runway grows linearly: `R ~ N` (i.e., `R ~ B/g`).

### 4.3 Gas Price Absorption

The curve automatically handles gas price fluctuations because the rate depends on
the *ratio* `B/g`, not on `B` or `g` independently:

| Event | Effect on `B/g` | Effect on `r` | Interpretation |
|---|---|---|---|
| Gas price doubles | `N` halves | `r` decreases | Publishes less often (preserves runway) |
| Gas price halves | `N` doubles | `r` increases | Publishes more often (exploits cheap gas) |
| Balance deposit | `N` increases | `r` increases | Immediate speed-up |
| Balance withdrawal | `N` decreases | `r` decreases | Immediate slow-down |

No explicit gas price oracle or smoothing is required in the base model. The ratio
`B/g` already encodes "how many transactions can I afford right now."

**Optional refinement:** Use an exponential moving average (EMA) of gas price over
the last ~50 blocks to dampen oscillation during temporary spikes:

```
g_smooth = alpha * g_current + (1 - alpha) * g_smooth_prev
```

where `alpha ~ 0.02` (roughly 50-block half-life).

### 4.4 Publication Interval (Discrete)

Since transactions occur on integer block boundaries:

```
Delta = max(1, ceil(1 / r))
```

| `r` (rate) | `Delta` (blocks) | Wall-clock interval |
|---|---|---|
| 1.0 | 1 | 12 seconds |
| 0.5 | 2 | 24 seconds |
| 0.1 | 10 | 2 minutes |
| 0.01 | 100 | 20 minutes |
| 0.001 | 1,000 | 3.3 hours |
| 0.0001 | 10,000 | 33.3 hours |

### 4.5 Full Decision Algorithm

```python
# Constants
N_HALF = 7200            # tuning parameter (= 1 day of blocks)
GAS_UNITS = 45_000       # gas consumed per timestamp tx
MIN_BALANCE = GAS_UNITS * 2  # don't attempt if can't afford 2 txs at current price

# State
last_published_block = 0
current_interval = infinity

def on_new_block(block_number, gas_price, wallet_balance):
    # Cost of one timestamp at current gas price
    g = GAS_UNITS * gas_price

    # Guard: insufficient funds
    if wallet_balance < g * 2:
        return  # skip, can't even afford the tx + buffer

    # Affordable transaction count
    N = wallet_balance / g

    # Bonding curve: publication rate
    r = 1.0 - exp(-N / N_HALF)

    # Discrete interval
    interval = max(1, ceil(1.0 / r))

    # Publish if interval elapsed
    if (block_number - last_published_block) >= interval:
        root_hash = get_current_root_hash()
        submit_timestamp_tx(root_hash)
        last_published_block = block_number
```

### 4.6 If-Then Causal Chain

```
IF   wallet has ETH balance B and gas costs g per tx
THEN we can compute N = B/g affordable transactions

IF   N and N_half are known
THEN r = 1 - exp(-N/N_half) gives the publication rate

IF   rate r is known
THEN Delta = ceil(1/r) gives the block interval

IF   Delta blocks have passed since last publish
THEN submit root hash to Ethereum L1

IF   root hash is submitted
THEN Aqua chain state is anchored to L1 with block-level timestamp

IF   the curve governs all publishing
THEN minimum runway >= N_half blocks is guaranteed (sustainability)
```

Each arrow is a testable hypothesis. The sustainability claim is proven in Section 4.2.

---

## Phase 5: BOUNDARY CONDITIONS

### Assumptions (must hold)

| # | Assumption | Risk if violated |
|---|---|---|
| A1 | Wallet has a funded EOA on Ethereum mainnet | No publishing possible |
| A2 | Gas price is observable per block | Cannot compute `g`; use last known price as fallback |
| A3 | Transaction inclusion within 1-2 blocks | Interval calculation assumes prompt inclusion |
| A4 | Root hash computation is fast relative to block time | Cannot miss publishing windows |
| A5 | Single publisher (no concurrent wallets) | Multiple publishers would drain faster than modeled |

### Exclusions (out of scope)

- **Revenue model / top-up strategy:** The curve governs *spend rate*, not income
- **L2 fallback:** No rollup or sidechain publishing in this model
- **Batch aggregation:** Each tx publishes exactly one root hash
- **MEV considerations:** Assumes standard mempool inclusion
- **Multi-chain:** Ethereum L1 only

### Invariants (must never be violated)

1. **Never publish if balance < 2 * g** (safety margin for gas estimation error)
2. **Never override the curve to publish faster than it prescribes**
3. **N_half must be > 0** (division by zero protection)
4. **One publish per block maximum** (Ethereum constraint, not a choice)

### Risks

| Risk | Mitigation |
|---|---|
| Prolonged gas spike depletes wallet | Curve auto-reduces rate; runway guarantee holds |
| Wallet compromise | Out of scope (operational security, not curve design) |
| Ethereum network halt | No publications possible; resume when network resumes |
| Gas estimation error causes underpayment | Use `MIN_BALANCE = 2 * g` guard + EIP-1559 maxFeePerGas |

---

## Parameter Selection Guide

### Choosing N_half

`N_half` is the *only* tuning parameter. It represents:
- The number of affordable transactions at which publication rate reaches 63%
- The guaranteed minimum runway (in blocks) regardless of balance level

| `N_half` | Minimum runway | Character | Use case |
|---|---|---|---|
| 720 | ~2.4 hours | Aggressive | High-frequency settlement, well-funded |
| 7,200 | ~1 day | Balanced | Production default for moderate budgets |
| 50,400 | ~1 week | Conservative | Budget-constrained, long-horizon anchoring |
| 216,000 | ~1 month | Very conservative | Minimal budget, archival-grade timestamping |

### Budget implications (at 30 gwei gas price, ~45,000 gas/tx)

| `N_half` | ETH for 63% rate | ETH for 95% rate | ETH for 99% rate |
|---|---|---|---|
| 720 | 0.97 ETH | 2.92 ETH | 4.47 ETH |
| 7,200 | 9.72 ETH | 29.16 ETH | 44.71 ETH |
| 50,400 | 68.04 ETH | 204.12 ETH | 313.0 ETH |

*Costs scale linearly with gas price. At 10 gwei, divide by 3. At 100 gwei, multiply by 3.3.*

### Derivation: "How much ETH do I need for X% rate?"

For a target rate `r_target`:

```
B_needed = -g * N_half * ln(1 - r_target)
```

| Target rate | Multiplier on `g * N_half` |
|---|---|
| 50% | 0.693 |
| 63% | 1.000 |
| 80% | 1.609 |
| 90% | 2.303 |
| 95% | 2.996 |
| 99% | 4.605 |
| 99.9% | 6.908 |

---

## Formal Summary

### The model in one equation

```
r(B, g) = 1 - exp( -B / (g * N_half) )
```

### The model in one sentence

The publication rate is an exponential saturation curve over the ratio of available
balance to transaction cost, with a single parameter `N_half` that simultaneously
sets the activation threshold and guarantees a minimum operational runway.

### Why this curve and not another

| Alternative | Why rejected |
|---|---|
| Linear: `r = min(1, N/K)` | No runway guarantee; depletes funds at constant rate regardless of balance |
| Logistic: `r = 1/(1+exp(-k(N-N0)))` | Inflection point creates a "dead zone" at low funds where rate barely responds |
| Power law: `r = min(1, (N/K)^a)` | Two parameters; no clean runway guarantee; can overshoot or undershoot |
| Step function | No gradual adaptation; wastes funds when above threshold |

The exponential CDF `1 - e^(-x)` is the unique single-parameter monotone curve that:
1. Passes through `(0, 0)` and asymptotes to `1`
2. Has maximum marginal responsiveness at zero (funds immediately increase rate)
3. Provides a provable minimum runway guarantee equal to its single parameter
4. Makes the ratio `B/g` the sole input (gas price absorbed automatically)

---

## Appendix: Numerical Walk-Through

### Scenario: N_half = 7,200, gas price = 30 gwei

**Wallet balance: 1 ETH (~$2,400)**

```
g = 45,000 * 30 * 10^9 = 1.35 * 10^15 wei = 0.00135 ETH
N = 1 / 0.00135 = 741 transactions affordable
r = 1 - exp(-741 / 7200) = 1 - exp(-0.103) = 0.098
Delta = ceil(1/0.098) = 11 blocks = 132 seconds between publications
Runway = 741 / 0.098 = 7,561 blocks = ~25.2 hours
Daily cost = (7200 / 11) * 0.00135 = 0.883 ETH/day
```

**Wallet balance: 10 ETH (~$24,000)**

```
N = 10 / 0.00135 = 7,407 transactions
r = 1 - exp(-7407 / 7200) = 1 - exp(-1.029) = 0.643
Delta = ceil(1/0.643) = 2 blocks = 24 seconds
Runway = 7407 / 0.643 = 11,520 blocks = ~38.4 hours
Daily cost = (7200 / 2) * 0.00135 = 4.86 ETH/day
```

**Wallet balance: 50 ETH (~$120,000)**

```
N = 50 / 0.00135 = 37,037 transactions
r = 1 - exp(-37037 / 7200) = 1 - exp(-5.144) = 0.9942
Delta = ceil(1/0.9942) = 1 block = 12 seconds (MAXIMUM RATE)
Runway = 37037 / 0.9942 = 37,253 blocks = ~5.2 days
Daily cost = 7200 * 0.00135 = 9.72 ETH/day
```

### Scenario: Gas price spikes to 200 gwei (everything else equal, B = 10 ETH)

```
g = 45,000 * 200 * 10^9 = 0.009 ETH
N = 10 / 0.009 = 1,111 transactions
r = 1 - exp(-1111 / 7200) = 1 - exp(-0.154) = 0.143
Delta = ceil(1/0.143) = 7 blocks = 84 seconds
Runway = 1111 / 0.143 = 7,769 blocks = ~25.9 hours
```

The curve automatically slowed from every 2 blocks to every 7 blocks, preserving
the runway guarantee despite a 6.7x gas price increase. No manual intervention needed.
