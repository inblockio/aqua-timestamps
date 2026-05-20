---
name: timestamping-bonding-curve
description: Use when working on the adaptive publication rate (bonding curve), troubleshooting epoch timing, debugging low-balance sealing behaviour, tuning N_half, or understanding why the sealer is publishing faster or slower than expected. Triggers on bonding curve, adaptive sealer, publication rate, N_half, runway, gas cost, epoch frequency, balance oracle.
---

# Timestamping Bonding Curve

## Spec reference

`Spec_Aqua_L1_Timestamping_Bonding_Curve.md` (repo root) contains the full
mathematical model, sustainability proof, parameter selection guide, and
numerical walk-throughs. Read the spec before making changes to the curve logic.

## What this does

Replaces the fixed-interval epoch sealer with one that adapts publication
frequency to the wallet's ETH balance and current gas cost. When funds are
low, it publishes rarely. When funds are abundant, it approaches one
publication per Ethereum block (12s L1 settlement).

The curve:

```
r(B, g) = 1 - exp( -B / (g * N_half) )
```

- `B` = wallet balance (wei)
- `g` = gas cost per timestamp tx (wei)
- `N_half` = single tuning parameter (default 7200, about 1 day of blocks)
- `r` = publication rate in [0, 1] (0 = never, 1 = every block)

The discrete block interval is `ceil(1 / r)`.

## Key property: minimum runway guarantee

For any balance `B > 0`, the system maintains at least `N_half` blocks of
operational runway. This is proven in the spec (Section 4.2) and tested in
`bonding_curve::tests::minimum_runway_guarantee`.

The parameter `N_half` simultaneously controls:
1. Activation sensitivity (how fast rate ramps up)
2. Minimum runway (how long the wallet lasts at minimum)

One parameter, two concerns, no tradeoff.

## Architecture

```
config.toml [bonding_curve]
    |
    v
lib.rs build_app()
    |
    +--> AlloyOracle (oracle.rs)         <-- queries RPC: get_balance + get_gas_price
    |       implements BalanceOracle trait (bonding_curve.rs)
    |
    +--> BondingCurveParams              <-- from config
    |
    v
sealer.rs run_sealer_with_bonding_curve()
    |
    +-- every poll_interval_secs:
    |     1. oracle.balance_and_gas_cost()
    |     2. bonding_curve::publication_rate(B, g, N_half)
    |     3. bonding_curve::block_interval(rate)
    |     4. if elapsed >= interval: seal_once()
    |
    v
seal_once() --> witnesses --> fjall storage
```

### Module layout

| File | Crate | Purpose |
|------|-------|---------|
| `crates/aqua-timestamp-core/src/bonding_curve.rs` | core | Pure math: `publication_rate`, `block_interval`, `runway_blocks`, `required_balance`. Also defines `BalanceOracle` trait, `MockOracle`, `FailingOracle`. |
| `crates/aqua-timestamp-core/src/sealer.rs` | core | `run_sealer_with_bonding_curve()` loop + `BondingCurveParams` struct. Lives alongside the existing `run_sealer_with_interval`. |
| `crates/aqua-timestamp/src/oracle.rs` | main | `AlloyOracle`: implements `BalanceOracle` using alloy's `Provider` for `get_balance` + `get_gas_price`. |
| `crates/aqua-timestamp/src/config.rs` | main | `BondingCurveConfig` struct: `enabled`, `n_half`, `poll_interval_secs`, `min_balance_multiplier`. |
| `crates/aqua-timestamp/src/lib.rs` | main | Wiring in `build_app()`: if `bonding_curve.enabled`, constructs `AlloyOracle` from `[anchors.evm].rpc_url` + wallet address and spawns the bonding curve sealer instead of the fixed-interval one. |

### Trait boundary

The `BalanceOracle` trait in core insulates the sealer from the RPC library.
Tests use `MockOracle` / `FailingOracle`. Production uses `AlloyOracle`.
Same pattern as `AnchorProvider`.

## Config

```toml
[bonding_curve]
enabled = true                  # default: false (opt-in)
n_half = 7200                   # default: 7200 (~1 day of blocks)
poll_interval_secs = 12         # default: 12 (one Ethereum block)
min_balance_multiplier = 2      # default: 2 (skip if balance < 2 * gas_cost)
```

- `enabled = false` (default) keeps the fixed-interval sealer. No code path
  changes, no RPC queries, no regression risk.
- The bonding curve reuses `[anchors.evm].rpc_url` for RPC queries. No
  separate RPC config needed. Works with direct node URLs, Alchemy, Infura,
  or any JSON-RPC endpoint.
- The wallet address is derived from the same mnemonic
  (`AQUA_TIMESTAMP_ANCHOR_MNEMONIC`) used for anchoring.

### Choosing N_half

| N_half | Min runway | Budget for 63% rate (30 gwei) | Character |
|--------|------------|-------------------------------|-----------|
| 720 | ~2.4 hours | ~1 ETH | Aggressive |
| 7,200 | ~1 day | ~10 ETH | Balanced (default) |
| 50,400 | ~1 week | ~68 ETH | Conservative |

To compute ETH needed for a target rate:
`B = -g * N_half * ln(1 - target_rate)`

Use `bonding_curve::required_balance(target_rate, gas_cost, n_half)` in code.

## Troubleshooting

### Sealer not publishing (rate near zero)

1. Check wallet balance: `cast balance <address> --rpc-url <url>`
2. Check gas price: `cast gas-price --rpc-url <url>`
3. Compute affordable txs: `balance / (gas_units * gas_price)`. If this is
   small relative to `n_half`, the rate will be very low.
4. Check logs for `"balance below safety margin"` (balance < `min_balance_multiplier * gas_cost`).
5. Fix: add ETH to the wallet, or lower `n_half` to increase sensitivity.

### Sealer publishing too slowly

The curve is conservative by design. At `N = N_half` affordable txs, rate is
only 63%. To reach 95%, you need `~3 * N_half` affordable txs.

Options:
- Lower `n_half` (trades runway guarantee for faster publishing)
- Add more ETH
- Use a cheaper RPC endpoint or wait for lower gas prices

### Sealer publishing every block (rate ~1.0)

This happens when `B >> g * N_half`. This is correct behaviour. Daily cost
will be approximately `7200 * gas_cost` (one tx per block).

### Oracle errors in logs

`"bonding curve oracle query failed"` means the RPC endpoint is unreachable
or returning errors. The sealer retries on the next poll interval without
sealing. No data is lost; epochs accumulate normally and seal when the oracle
recovers.

Check:
- RPC URL validity in `[anchors.evm].rpc_url`
- Rate limits on Alchemy/Infura (the oracle makes 2 calls per poll: `eth_getBalance` + `eth_gasPrice`)
- Network connectivity from the container

### Gas cost estimation

The oracle uses a fixed `TIMESTAMP_GAS_UNITS = 50,000` multiplied by the
current `eth_gasPrice`. This is a conservative upper bound for the
`witness(bytes32)` contract call (~45,000 actual). The 10% margin prevents
underestimation during EIP-1559 base fee fluctuations.

If actual gas usage changes (contract upgrade, different calldata), update
`TIMESTAMP_GAS_UNITS` in `oracle.rs`.

## Testing

```bash
# All bonding curve math tests (20 tests)
cargo test -p aqua-timestamp-core bonding_curve

# Adaptive sealer tests (3 tests: seal-on-interval, skip-low-balance, survive-oracle-failure)
cargo test -p aqua-timestamp-core bonding_curve_sealer

# Full workspace (verifies no regression)
cargo test --workspace
```

The sealer tests use `tokio::time::pause` + `MockOracle` for deterministic
timing. The `start_paused = true` attribute on the test function enables this;
the `test-util` feature is added as a dev-dependency in the core crate.

## Invariants

1. `publication_rate(0, g, n_half) == 0.0` for all `g > 0`, `n_half > 0`
2. `publication_rate(B, g, n_half) < 1.0` for all finite `B`
3. `runway_blocks(B, g, n_half) >= n_half` for all `B > 0`
4. The fixed-interval sealer is completely untouched when `bonding_curve.enabled = false`
5. Oracle failure never causes a panic or seal failure; the loop retries next interval

## Dependencies added

| Crate | Scope | Why |
|-------|-------|-----|
| `alloy` (workspace) | aqua-timestamp | `Provider::get_balance` + `get_gas_price` for the oracle |
| `async-trait` | aqua-timestamp | Already in core; needed in main crate for `BalanceOracle` impl |
| `tokio[test-util]` | core dev-dep | Deterministic time advancement in sealer tests |
