use serde::{Deserialize, Serialize};

/// One row per contributor wallet.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContributorEntry {
    pub did: String,
    pub fuel_contributed_wei: u128,
    pub fuel_contributed_sat: u64,
    pub hashes_submitted: u64,
    pub last_active: u64,
}

/// A single detected ETH transfer to the service wallet.
#[derive(Debug, Clone)]
pub struct FuelTransfer {
    pub sender: [u8; 20],
    pub value_wei: u128,
    pub block_number: u64,
    pub block_timestamp: u64,
}

pub const CONTRIBUTOR_STATS_PARTITION: &str = "contributor_stats";
pub const WATCHER_WATERMARK_PARTITION: &str = "watcher_watermark";
