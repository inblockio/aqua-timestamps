# Budget Analysis: 0.055 ETH over 2 Weeks (Ethereum L1)

**Date:** 2026-05-20
**Scenario:** Minimal funding of 0.055 ETH for a 2-week evaluation period, Ethereum L1 timestamping only.

## Method

Identical derivation method to the 100 ETH analysis. Three fixed inputs, one variable:

1. **Budget:** 0.055 ETH, uniformly averaged over 14 days = 0.003929 ETH/day.
2. **Gas units per timestamp tx:** 50,000 (conservative upper bound for `witness(bytes32)`). Source: `crates/aqua-timestamp/src/oracle.rs`, constant `TIMESTAMP_GAS_UNITS`.
3. **Blocks per day:** 7,200 (Ethereum PoS, 12s block time).
4. **Gas price:** variable; tables show multiple scenarios.

**Formulas:**

```
g              = 50,000 * gas_price_gwei * 10^9     (wei per tx)
txs_per_day    = (0.055 / 14) / g                   (linear uniform spend)
total_txs_14d  = 0.055 / g                          (total affordable over full period)
interval_hours = 24 / txs_per_day                   (average hours between publications)
```

**Bonding curve rate at a given balance B:**

```
r(B, g) = 1 - exp(-B / (g * N_half))
```

**Minimum runway guarantee:** `N_half` blocks (proven in Spec Section 4.2 via L'Hopital on `N / (1 - exp(-N/N_half))` as `N -> 0`).

**N_half selection for 14-day runway:** `N_half = 14 * 7,200 = 100,800 blocks`.

**Verification that the curve matches the linear budget at N_half = 100,800 (10 gwei example):**

```
N     = 0.055 / 0.0005 = 110 affordable txs
r     = 1 - exp(-110 / 100,800) = 1 - exp(-0.001091) = 0.001090
Delta = ceil(1 / 0.001090) = 917 blocks = 11,004 seconds = 3.06 hours
txs/day = 7,200 / 917 = 7.85
daily cost = 7.85 * 0.0005 = 0.003925 ETH  (matches 0.055/14 = 0.003929)
```

The small rounding difference (0.003925 vs 0.003929) comes from `ceil()` discretization.

## Results: Daily throughput (0.055 ETH / 14 days = 0.00393 ETH/day)

| Gas price | Cost per tx (ETH) | Txs/day | Total txs (14d) | Avg interval |
|-----------|--------------------|---------|-----------------|--------------|
| 5 gwei   | 0.00025            | 15.7    | 220             | ~1.5 hours   |
| 10 gwei  | 0.0005             | 7.9     | 110             | ~3 hours     |
| 20 gwei  | 0.001              | 3.9     | 55              | ~6 hours     |
| 30 gwei  | 0.0015             | 2.6     | 37              | ~9 hours     |
| 50 gwei  | 0.0025             | 1.6     | 22              | ~15 hours    |
| 100 gwei | 0.005              | 0.8     | 11              | ~30 hours    |

## Bonding curve: N_half selection is critical

With the default `N_half = 7,200`, the curve drains 0.055 ETH in approximately **1 day**, not 14. Demonstration at 10 gwei:

```
N     = 0.055 / 0.0005 = 110 affordable txs
r     = 1 - exp(-110 / 7,200) = 1 - exp(-0.01528) = 0.01516
Delta = ceil(1 / 0.01516) = 66 blocks = 792 seconds = 13.2 minutes
txs/day = 7,200 / 66 = 109
daily cost = 109 * 0.0005 = 0.0545 ETH  (nearly the entire budget in one day)
```

**Required setting: `N_half = 100,800`** (14 days of blocks).

This places the system deep in the curve's linear regime (`N << N_half`), where `r` is approximately `N / N_half`. In this regime, the rate decays proportionally with the balance, producing a roughly uniform spend rate over the evaluation period.

### Verification across gas prices at N_half = 100,800

| Gas price | N (affordable txs) | Rate r | Delta (blocks) | Interval | Txs/day | Daily cost (ETH) |
|-----------|--------------------|--------|----------------|----------|---------|------------------|
| 5 gwei   | 220                | 0.00218 | 459           | ~1.5 hrs | 15.7    | 0.00393          |
| 10 gwei  | 110                | 0.00109 | 917           | ~3.1 hrs | 7.9     | 0.00393          |
| 20 gwei  | 55                 | 0.000546 | 1,832         | ~6.1 hrs | 3.9     | 0.00393          |
| 30 gwei  | 36.7               | 0.000364 | 2,748         | ~9.2 hrs | 2.6     | 0.00393          |
| 50 gwei  | 22                 | 0.000218 | 4,587         | ~15.3 hrs | 1.6    | 0.00393          |
| 100 gwei | 11                 | 0.000109 | 9,174         | ~30.6 hrs | 0.8    | 0.00393          |

Daily cost is consistent at ~0.00393 ETH across all gas prices because the curve absorbs gas price changes through the `B/g` ratio. Higher gas means fewer but identically-budgeted transactions.

## Recommended config

```toml
[bonding_curve]
enabled = true
n_half = 100800          # 14-day minimum runway guarantee
poll_interval_secs = 12
min_balance_multiplier = 2
```

## Interpretation

0.055 ETH is an archival-grade budget. The system proves state existed within a window of hours, not seconds or minutes.

| Gas price | Character | Suitable for |
|-----------|-----------|-------------|
| 5 gwei   | One anchor per 1.5 hours | Hourly batch settlement, document integrity |
| 10 gwei  | One anchor per 3 hours | Quarter-day settlement, audit trails |
| 30 gwei  | One anchor per 9 hours | Morning/afternoon/overnight anchoring |
| 100 gwei | Less than one per day | Barely operational; consider pausing until gas drops |

This budget is valid for use cases where the anchoring interval is measured in hours: daily settlement batches, document notarization, periodic audit checkpoints. It is not suitable for near-real-time L1 finality.

The bonding curve with `N_half = 100,800` ensures the system never runs dry before the 2-week evaluation completes, automatically slowing publication when gas spikes and recovering when gas drops.
