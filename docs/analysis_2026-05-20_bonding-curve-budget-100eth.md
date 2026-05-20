# Budget Analysis: 100 ETH over 2 Weeks (Ethereum L1)

**Date:** 2026-05-20
**Scenario:** Private funding of ~100 ETH for a 2-week evaluation period, Ethereum L1 timestamping only.

## Method

All numbers are derived from three fixed inputs and one variable (gas price):

1. **Budget:** 100 ETH, uniformly averaged over 14 days = 7.143 ETH/day.
2. **Gas units per timestamp tx:** 50,000 (conservative upper bound for a `witness(bytes32)` call; actual usage ~45,000). Source: `crates/aqua-timestamp/src/oracle.rs`, constant `TIMESTAMP_GAS_UNITS`.
3. **Blocks per day:** 7,200 (Ethereum PoS, 12s block time).
4. **Gas price:** variable; tables show multiple scenarios from 5 to 100 gwei.

**Cost per transaction:**

```
g = TIMESTAMP_GAS_UNITS * gas_price
  = 50,000 * gas_price_in_gwei * 10^9  (wei)
```

**Transactions per day (linear budget):**

```
txs_per_day = daily_budget / g = (100 / 14) / g
```

Capped at 7,200 (one tx per block maximum).

**Publication rate as fraction of blocks:**

```
rate = min(1.0, txs_per_day / 7200)
```

**Average interval:**

```
interval_seconds = 86,400 / txs_per_day   (if txs_per_day < 7,200)
interval_seconds = 12                       (if capped)
```

**Total ETH for every-block publishing over 14 days:**

```
total_cost = 7,200 blocks/day * 14 days * g = 100,800 * g
```

## Results: Daily throughput (100 ETH / 14 days = 7.14 ETH/day)

| Gas price | Cost per tx (ETH) | Txs/day | % of blocks | Avg interval |
|-----------|--------------------|---------|-------------|--------------|
| 5 gwei   | 0.00025            | 28,571  | **100% (capped at 7,200)** | 12s (every block) |
| 10 gwei  | 0.0005             | 14,286  | **100% (capped at 7,200)** | 12s (every block) |
| 20 gwei  | 0.001              | 7,143   | 99.2%       | ~12s |
| 30 gwei  | 0.0015             | 4,762   | 66.1%       | ~18s |
| 50 gwei  | 0.0025             | 2,857   | 39.7%       | ~30s |
| 100 gwei | 0.005              | 1,429   | 19.8%       | ~60s |

## Results: Total ETH needed for every-block publishing, 14 days

| Gas price | Total cost (100,800 txs) | Surplus from 100 ETH |
|-----------|--------------------------|----------------------|
| 5 gwei   | 25.2 ETH                 | +74.8 ETH            |
| 10 gwei  | 50.4 ETH                 | +49.6 ETH            |
| 20 gwei  | 100.8 ETH                | -0.8 ETH (barely short) |
| 30 gwei  | 151.2 ETH                | -51.2 ETH            |

## Bonding curve dynamics

The bonding curve does not spend uniformly. It publishes faster when the balance is high and slows as the balance drops.

**Curve:** `r(B, g) = 1 - exp(-B / (g * N_half))`

With default `N_half = 7,200` at 30 gwei:

```
Initial N = 100 / 0.0015 = 66,667 affordable txs
Initial r = 1 - exp(-66,667 / 7,200) = 0.99990 (effectively every block)
Daily spend at max rate = 7,200 * 0.0015 = 10.8 ETH/day
Days at near-max rate = ~9.3 days
```

The system publishes every block for ~9 days, then decays into a long tail. This is not a uniform 14-day spread.

**To spread spending over the full 14 days at 30 gwei**, raise `N_half` to 50,000-60,000. This keeps the initial rate moderate (~66%) rather than pegging to 100%.

At low gas prices (5-20 gwei), the default `N_half = 7,200` works fine because 100 ETH exceeds the 14-day budget at max rate.

## Interpretation

At **typical 2025 mainnet gas (5-20 gwei):** 100 ETH buys every single block for 2 weeks with ETH left over. The bonding curve parameter is not the binding constraint; gas price is.

At **30 gwei:** ~4,762 timestamps/day (every ~18s). Still high throughput, sub-minute settlement on average.

At **100 gwei (congestion):** ~1,429 timestamps/day (every ~60s). Still minute-level settlement.

100 ETH is a generous evaluation budget. Under any realistic 2025 gas price regime, it sustains near-max or max publication rate for the full evaluation period.
