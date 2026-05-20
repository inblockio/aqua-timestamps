use std::time::Duration;

use alloy::consensus::Transaction as _;
use alloy::network::primitives::BlockTransactions;
use alloy::primitives::{Address, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::Transaction;
use thiserror::Error;
use tracing::{info, warn};

use aqua_timestamp_core::leaderboard::{ContributorEntry, FuelTransfer};
use aqua_timestamp_core::storage::Store;

#[derive(Debug, Error)]
pub enum WatcherError {
    #[error("RPC error: {0}")]
    Rpc(String),
    #[error("block {0} not found")]
    BlockNotFound(u64),
    #[error("parse error: {0}")]
    Parse(String),
}

pub struct BlockWatcher {
    rpc_url: String,
    wallet_address: Address,
    chain_id: u64,
}

impl BlockWatcher {
    pub fn new(rpc_url: String, wallet_address: Address, chain_id: u64) -> Self {
        Self {
            rpc_url,
            wallet_address,
            chain_id,
        }
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub async fn latest_block(&self) -> Result<u64, WatcherError> {
        let url = self
            .rpc_url
            .parse()
            .map_err(|e| WatcherError::Rpc(format!("{e}")))?;
        let provider = ProviderBuilder::new().connect_http(url);
        let block_number = provider
            .get_block_number()
            .await
            .map_err(|e| WatcherError::Rpc(format!("{e}")))?;
        Ok(block_number)
    }

    /// Scan blocks `from..=to` (capped at 100 blocks per call) and return
    /// all ETH transfers to the wallet address.
    pub async fn scan_blocks(&self, from: u64, to: u64) -> Result<Vec<FuelTransfer>, WatcherError> {
        let url = self
            .rpc_url
            .parse()
            .map_err(|e| WatcherError::Rpc(format!("{e}")))?;
        let provider = ProviderBuilder::new().connect_http(url);

        let cap = to.min(from.saturating_add(99));
        let mut transfers = Vec::new();

        for n in from..=cap {
            let block = provider
                .get_block_by_number(n.into())
                .full()
                .await
                .map_err(|e| WatcherError::Rpc(format!("block {n}: {e}")))?
                .ok_or(WatcherError::BlockNotFound(n))?;

            let block_timestamp = block.header.timestamp;

            let txs = match block.transactions {
                BlockTransactions::Full(txs) => txs,
                _ => continue,
            };

            let found = filter_transfers(&txs, self.wallet_address, n, block_timestamp);
            transfers.extend(found);
        }

        Ok(transfers)
    }
}

/// Pure filter function: extract inbound ETH transfers to `wallet` from a
/// block's full transaction list.
pub fn filter_transfers(
    txs: &[Transaction],
    wallet: Address,
    block_number: u64,
    block_timestamp: u64,
) -> Vec<FuelTransfer> {
    txs.iter()
        .filter(|tx| tx.inner.to() == Some(wallet) && tx.inner.value() > U256::ZERO)
        .map(|tx| {
            let sender_addr = tx.inner.signer();
            let mut sender = [0u8; 20];
            sender.copy_from_slice(sender_addr.as_slice());
            FuelTransfer {
                sender,
                value_wei: tx.inner.value().to::<u128>(),
                block_number,
                block_timestamp,
            }
        })
        .collect()
}

pub fn did_for_sender(chain_id: u64, sender: &[u8; 20]) -> String {
    format!("did:pkh:eip155:{}:0x{}", chain_id, hex::encode(sender))
}

/// Spawn the background block-watcher task.
pub fn spawn_watcher(
    store: Store,
    watcher: BlockWatcher,
    poll_interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let chain_id = watcher.chain_id();
        let chain_label = "eth";

        let mut watermark = match store.get_watermark(chain_label) {
            Ok(Some(w)) => w,
            Ok(None) => match watcher.latest_block().await {
                Ok(b) => {
                    info!(
                        block = b,
                        "watcher: no watermark, starting from current block"
                    );
                    b
                }
                Err(e) => {
                    warn!("watcher: failed to get initial block: {e}");
                    0
                }
            },
            Err(e) => {
                warn!("watcher: failed to read watermark: {e}");
                0
            }
        };

        loop {
            tokio::time::sleep(poll_interval).await;

            let latest = match watcher.latest_block().await {
                Ok(b) => b,
                Err(e) => {
                    warn!("watcher: latest_block failed: {e}");
                    continue;
                }
            };

            if latest <= watermark {
                continue;
            }

            let scan_end = latest.min(watermark.saturating_add(100));
            let scan_start = watermark.saturating_add(1);

            let fuel_transfers = match watcher.scan_blocks(scan_start, scan_end).await {
                Ok(t) => t,
                Err(e) => {
                    warn!(
                        from = scan_start,
                        to = scan_end,
                        "watcher: scan failed: {e}"
                    );
                    continue;
                }
            };

            if !fuel_transfers.is_empty() {
                let mut updates: Vec<([u8; 20], ContributorEntry)> = Vec::new();

                for ft in &fuel_transfers {
                    let existing = store.get_contributor(&ft.sender).ok().flatten();
                    let entry = match existing {
                        Some(mut e) => {
                            e.fuel_contributed_wei =
                                e.fuel_contributed_wei.saturating_add(ft.value_wei);
                            if ft.block_timestamp > e.last_active {
                                e.last_active = ft.block_timestamp;
                            }
                            e
                        }
                        None => ContributorEntry {
                            did: did_for_sender(chain_id, &ft.sender),
                            fuel_contributed_wei: ft.value_wei,
                            fuel_contributed_sat: 0,
                            hashes_submitted: 0,
                            last_active: ft.block_timestamp,
                        },
                    };
                    updates.push((ft.sender, entry));
                }

                if let Err(e) =
                    store.upsert_contributors_and_watermark(&updates, chain_label, scan_end)
                {
                    warn!("watcher: batch upsert failed: {e}");
                    continue;
                }

                info!(
                    from = scan_start,
                    to = scan_end,
                    transfers = fuel_transfers.len(),
                    "watcher: processed blocks"
                );
            } else if let Err(e) = store.set_watermark(chain_label, scan_end) {
                warn!("watcher: watermark update failed: {e}");
            }

            watermark = scan_end;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_format() {
        let sender = [0xAB; 20];
        let did = did_for_sender(11155111, &sender);
        assert_eq!(
            did,
            "did:pkh:eip155:11155111:0xabababababababababababababababababababab"
        );
    }

    #[test]
    fn did_mainnet() {
        let sender = [0x01; 20];
        let did = did_for_sender(1, &sender);
        assert!(did.starts_with("did:pkh:eip155:1:0x"));
    }
}
