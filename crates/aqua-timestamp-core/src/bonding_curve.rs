//! Adaptive publication rate for L1 Ethereum settlement.
//!
//! Implements the bonding curve `r(B, g) = 1 - exp(-B / (g * N_half))`
//! where B is the wallet balance (wei), g is the cost per timestamp tx
//! (wei), and N_half is the single tuning parameter that simultaneously
//! controls activation sensitivity and minimum runway guarantee.
//!
//! See `Spec_Aqua_L1_Timestamping_Bonding_Curve.md` for the full
//! mathematical specification and proofs.

use async_trait::async_trait;

/// Compute the publication rate r in [0.0, 1.0].
///
/// `r = 1 - exp(-N / N_half)` where `N = balance / gas_cost`.
///
/// Returns 0.0 when balance or gas_cost is zero.
pub fn publication_rate(balance_wei: u128, gas_cost_wei: u128, n_half: u64) -> f64 {
    if gas_cost_wei == 0 || n_half == 0 || balance_wei == 0 {
        return 0.0;
    }
    let n = balance_wei as f64 / gas_cost_wei as f64;
    let n_half_f = n_half as f64;
    1.0 - (-n / n_half_f).exp()
}

/// Discrete block interval: `max(1, ceil(1 / r))`.
///
/// Returns `u64::MAX` when rate is zero (effectively "never publish").
pub fn block_interval(rate: f64) -> u64 {
    if rate <= 0.0 {
        return u64::MAX;
    }
    if rate >= 1.0 {
        return 1;
    }
    let interval = (1.0 / rate).ceil() as u64;
    interval.max(1)
}

/// Runway in blocks: `B / (r * g)`.
///
/// Returns `f64::INFINITY` when rate is zero. Minimum is N_half.
pub fn runway_blocks(balance_wei: u128, gas_cost_wei: u128, n_half: u64) -> f64 {
    let rate = publication_rate(balance_wei, gas_cost_wei, n_half);
    if rate <= 0.0 || gas_cost_wei == 0 {
        return f64::INFINITY;
    }
    balance_wei as f64 / (rate * gas_cost_wei as f64)
}

/// ETH balance (wei) required to achieve a target publication rate.
///
/// Derived from inverting the curve: `B = -g * N_half * ln(1 - r_target)`.
///
/// Panics if `target_rate` is not in (0.0, 1.0).
pub fn required_balance(target_rate: f64, gas_cost_wei: u128, n_half: u64) -> u128 {
    assert!(
        target_rate > 0.0 && target_rate < 1.0,
        "target_rate must be in (0, 1)"
    );
    let b = -(gas_cost_wei as f64) * (n_half as f64) * (1.0 - target_rate).ln();
    b as u128
}

#[derive(thiserror::Error, Debug)]
pub enum OracleError {
    #[error("rpc query failed: {0}")]
    Rpc(String),
    #[error("wallet not funded")]
    ZeroBalance,
}

/// Async oracle that returns the current wallet balance and the estimated
/// gas cost for one timestamp transaction. Trait-based so tests can plug
/// in a [`MockOracle`] while production uses an alloy-backed implementation.
#[async_trait]
pub trait BalanceOracle: Send + Sync {
    /// Returns `(balance_wei, gas_cost_wei)` for the publishing wallet.
    async fn balance_and_gas_cost(&self) -> Result<(u128, u128), OracleError>;
}

/// Test oracle that returns caller-supplied values.
pub struct MockOracle {
    pub balance_wei: u128,
    pub gas_cost_wei: u128,
}

#[async_trait]
impl BalanceOracle for MockOracle {
    async fn balance_and_gas_cost(&self) -> Result<(u128, u128), OracleError> {
        Ok((self.balance_wei, self.gas_cost_wei))
    }
}

/// Test oracle that always errors.
pub struct FailingOracle {
    pub message: String,
}

#[async_trait]
impl BalanceOracle for FailingOracle {
    async fn balance_and_gas_cost(&self) -> Result<(u128, u128), OracleError> {
        Err(OracleError::Rpc(self.message.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const N_HALF: u64 = 7200;
    const GAS_COST: u128 = 1_350_000_000_000_000; // 0.00135 ETH in wei

    // H1: zero balance produces zero rate
    #[test]
    fn zero_balance_gives_zero_rate() {
        assert_eq!(publication_rate(0, GAS_COST, N_HALF), 0.0);
    }

    #[test]
    fn zero_gas_cost_gives_zero_rate() {
        assert_eq!(publication_rate(1_000_000, 0, N_HALF), 0.0);
    }

    #[test]
    fn zero_n_half_gives_zero_rate() {
        assert_eq!(publication_rate(1_000_000, GAS_COST, 0), 0.0);
    }

    // H2: large balance approaches rate 1.0
    #[test]
    fn large_balance_approaches_max_rate() {
        let large_balance = GAS_COST * (N_HALF as u128) * 10;
        let rate = publication_rate(large_balance, GAS_COST, N_HALF);
        assert!(rate > 0.999, "rate={rate}, expected > 0.999");
    }

    // H3: at N_half affordable txs, rate ≈ 0.632
    #[test]
    fn half_activation_rate() {
        let balance = GAS_COST * (N_HALF as u128);
        let rate = publication_rate(balance, GAS_COST, N_HALF);
        let expected = 1.0 - (-1.0_f64).exp(); // 1 - e^(-1) ≈ 0.6321
        assert!(
            (rate - expected).abs() < 0.001,
            "rate={rate}, expected ~{expected}"
        );
    }

    // H4: runway is always >= N_half blocks
    #[test]
    fn minimum_runway_guarantee() {
        let test_balances: Vec<u128> = vec![
            GAS_COST,                         // 1 affordable tx
            GAS_COST * 10,                    // 10 txs
            GAS_COST * 100,                   // 100 txs
            GAS_COST * (N_HALF as u128),      // exactly N_half txs
            GAS_COST * (N_HALF as u128) * 10, // 10x N_half
        ];
        for balance in test_balances {
            let runway = runway_blocks(balance, GAS_COST, N_HALF);
            assert!(
                runway >= N_HALF as f64,
                "balance={balance}, runway={runway}, N_half={N_HALF}"
            );
        }
    }

    #[test]
    fn runway_at_half_activation() {
        let balance = GAS_COST * (N_HALF as u128);
        let runway = runway_blocks(balance, GAS_COST, N_HALF);
        let expected = N_HALF as f64 / (1.0 - (-1.0_f64).exp());
        assert!(
            (runway - expected).abs() < 1.0,
            "runway={runway}, expected ~{expected}"
        );
    }

    #[test]
    fn runway_at_zero_balance_is_infinite() {
        let runway = runway_blocks(0, GAS_COST, N_HALF);
        assert!(runway.is_infinite());
    }

    // Block interval tests
    #[test]
    fn block_interval_at_max_rate() {
        assert_eq!(block_interval(1.0), 1);
    }

    #[test]
    fn block_interval_at_half_rate() {
        assert_eq!(block_interval(0.5), 2);
    }

    #[test]
    fn block_interval_at_zero_rate() {
        assert_eq!(block_interval(0.0), u64::MAX);
    }

    #[test]
    fn block_interval_at_ten_percent() {
        assert_eq!(block_interval(0.1), 10);
    }

    #[test]
    fn block_interval_at_one_percent() {
        assert_eq!(block_interval(0.01), 100);
    }

    // Required balance inversion
    #[test]
    fn required_balance_round_trips() {
        let target = 0.95;
        let balance = required_balance(target, GAS_COST, N_HALF);
        let rate = publication_rate(balance, GAS_COST, N_HALF);
        assert!(
            (rate - target).abs() < 0.01,
            "rate={rate}, expected ~{target}"
        );
    }

    #[test]
    fn required_balance_at_63_percent() {
        let balance = required_balance(0.6321, GAS_COST, N_HALF);
        let expected = GAS_COST * (N_HALF as u128);
        let ratio = balance as f64 / expected as f64;
        assert!(
            (ratio - 1.0).abs() < 0.01,
            "balance={balance}, expected ~{expected}"
        );
    }

    // Mock oracle
    #[tokio::test]
    async fn mock_oracle_returns_values() {
        let oracle = MockOracle {
            balance_wei: 10_000_000_000_000_000_000, // 10 ETH
            gas_cost_wei: GAS_COST,
        };
        let (b, g) = oracle.balance_and_gas_cost().await.unwrap();
        assert_eq!(b, 10_000_000_000_000_000_000);
        assert_eq!(g, GAS_COST);
    }

    #[tokio::test]
    async fn failing_oracle_returns_error() {
        let oracle = FailingOracle {
            message: "rpc down".into(),
        };
        let err = oracle.balance_and_gas_cost().await.unwrap_err();
        assert!(err.to_string().contains("rpc down"));
    }

    // Integration: full pipeline from oracle to interval
    #[tokio::test]
    async fn full_pipeline_oracle_to_interval() {
        let oracle = MockOracle {
            balance_wei: 10_000_000_000_000_000_000, // 10 ETH
            gas_cost_wei: GAS_COST,
        };
        let (balance, gas_cost) = oracle.balance_and_gas_cost().await.unwrap();
        let rate = publication_rate(balance, gas_cost, N_HALF);
        let interval = block_interval(rate);
        // 10 ETH / 0.00135 ETH = ~7407 txs, r ≈ 0.643, interval = 2
        assert_eq!(interval, 2);
        let runway = runway_blocks(balance, gas_cost, N_HALF);
        assert!(runway > N_HALF as f64);
    }

    // Monotonicity: rate increases with balance
    #[test]
    fn rate_increases_with_balance() {
        let mut prev_rate = 0.0;
        for multiplier in [1, 10, 100, 1000, 10_000] {
            let balance = GAS_COST * multiplier;
            let rate = publication_rate(balance, GAS_COST, N_HALF);
            assert!(
                rate >= prev_rate,
                "rate should be monotonically increasing: {rate} < {prev_rate}"
            );
            prev_rate = rate;
        }
    }

    // Gas price absorption: rate decreases when gas doubles
    #[test]
    fn gas_spike_reduces_rate() {
        let balance = GAS_COST * (N_HALF as u128);
        let rate_normal = publication_rate(balance, GAS_COST, N_HALF);
        let rate_spike = publication_rate(balance, GAS_COST * 2, N_HALF);
        assert!(
            rate_spike < rate_normal,
            "gas spike should reduce rate: {rate_spike} >= {rate_normal}"
        );
    }
}
