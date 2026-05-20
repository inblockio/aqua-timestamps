//! Alloy-backed [`BalanceOracle`] for the bonding curve sealer.
//!
//! Queries the publishing wallet's ETH balance and estimates the gas
//! cost of one timestamp transaction via JSON-RPC. Works with any
//! Ethereum RPC endpoint: direct node URL, Alchemy, Infura, or public
//! nodes on mainnet or Sepolia.

use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder};
use aqua_timestamp_core::bonding_curve::{BalanceOracle, OracleError};
use async_trait::async_trait;

/// Fixed gas units for one `witness(bytes32)` call to the timestamp
/// smart contract. This is a reasonable upper bound; actual usage is
/// slightly lower but the safety margin prevents underestimation.
const TIMESTAMP_GAS_UNITS: u128 = 50_000;

pub struct AlloyOracle {
    rpc_url: String,
    wallet_address: Address,
}

impl AlloyOracle {
    pub fn new(rpc_url: String, wallet_address: Address) -> Self {
        Self {
            rpc_url,
            wallet_address,
        }
    }
}

#[async_trait]
impl BalanceOracle for AlloyOracle {
    async fn balance_and_gas_cost(&self) -> Result<(u128, u128), OracleError> {
        let rpc_url: alloy::transports::http::reqwest::Url = self
            .rpc_url
            .parse()
            .map_err(|e| OracleError::Rpc(format!("invalid RPC URL {:?}: {e}", self.rpc_url)))?;
        let provider = ProviderBuilder::new().connect_http(rpc_url);

        let balance = provider
            .get_balance(self.wallet_address)
            .await
            .map_err(|e| OracleError::Rpc(format!("get_balance failed: {e}")))?;

        let gas_price = provider
            .get_gas_price()
            .await
            .map_err(|e| OracleError::Rpc(format!("get_gas_price failed: {e}")))?;

        let balance_u128: u128 = balance.try_into().unwrap_or(u128::MAX);
        let gas_cost = TIMESTAMP_GAS_UNITS * gas_price;

        if balance_u128 == 0 {
            return Err(OracleError::ZeroBalance);
        }

        Ok((balance_u128, gas_cost))
    }
}
