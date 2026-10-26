//! An honest simulated EVM chain for the seal tests (PCA-0030 hosts fetch, the SDK judges).
//!
//! Before PCA-0030 the seal test hosts answered `verify_transaction` with `true` for every
//! claim. A host now only fetches facts and `core::evm_anchor` judges them, so "the chain
//! confirms the witness" means: the witness provider anchors its root on this chain
//! ([`anchor`]) and [`HonestChain`] serves the facts of that transaction, an honest, finalized,
//! successful anchor whose sender, contract and calldata are the ones the witness claims and
//! whose block time is the claimed time. A transaction the chain never saw reads `Ok(None)`.

#![allow(dead_code)]

use aqua_rs_sdk::{EvmChainHead, EvmInclusion, EvmTransactionFacts, HostError};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// The sender every honest test witness claims.
pub const SENDER: &str = "0x1111111111111111111111111111111111111111";
/// The contract the default honest test witness claims.
pub const CONTRACT: &str = "0x269ff9a5cb9bd5319bd95b248d2579aa1e9d78fe";
/// The network the default honest test witness claims.
pub const NETWORK: &str = "sepolia";

/// Height of every anchoring block: above the first proof-of-stake block of every chain the
/// SDK supports, so finality tags apply.
const BLOCK: u64 = 20_000_100;
/// A block above the chain's finalized and safe heads but below its latest head: an anchor here
/// is included, not yet final (the SDK grades it `Included`).
const PENDING_BLOCK: u64 = BLOCK + 60;

struct Anchor {
    from: [u8; 20],
    to: [u8; 20],
    input: Vec<u8>,
    time: u64,
    block: u64,
}

fn chain() -> &'static Mutex<HashMap<String, Anchor>> {
    static CHAIN: OnceLock<Mutex<HashMap<String, Anchor>>> = OnceLock::new();
    CHAIN.get_or_init(|| Mutex::new(HashMap::new()))
}

fn bytes<const N: usize>(s: &str) -> Option<[u8; N]> {
    hex::decode(s.strip_prefix("0x")?).ok()?.try_into().ok()
}

/// Anchor `merkle_root` (wire form) on `network` from `sender` at `contract` at block time
/// `time`, and return the transaction hash (`0x` and 64 lowercase hex digits). A claim the SDK
/// cannot parse is not put on the chain (the SDK never asks for it).
pub fn anchor(network: &str, sender: &str, contract: &str, merkle_root: &str, time: u64) -> String {
    anchor_in(network, sender, contract, merkle_root, time, false)
}

/// As [`anchor`], but the anchor is included in a block that is not yet final (`pending`).
pub fn anchor_in(
    network: &str,
    sender: &str,
    contract: &str,
    merkle_root: &str,
    time: u64,
    pending: bool,
) -> String {
    let mut h = Sha3_256::new();
    for part in [network, sender, contract, merkle_root, &time.to_string()] {
        h.update(part.as_bytes());
        h.update([0u8]);
    }
    if pending {
        h.update(b"pending\0");
    }
    let tx = format!("0x{}", hex::encode(h.finalize()));
    let root = merkle_root
        .strip_prefix("0x")
        .and_then(|r| hex::decode(r).ok());
    if let (Some(from), Some(to), Some(root)) = (bytes::<20>(sender), bytes::<20>(contract), root) {
        let mut input = vec![0x11, 0x4e, 0xe1, 0x97];
        input.extend_from_slice(&root);
        chain().lock().expect("chain").insert(
            tx.clone(),
            Anchor {
                from,
                to,
                input,
                time,
                block: if pending { PENDING_BLOCK } else { BLOCK },
            },
        );
    }
    tx
}

/// Serves the facts of every transaction [`anchor`] put on the chain.
pub struct HonestChain;

impl HonestChain {
    pub fn facts(chain_id: u64, tx_hash: &str) -> Result<Option<EvmTransactionFacts>, HostError> {
        let chain = chain().lock().expect("chain");
        let Some(a) = chain.get(tx_hash) else {
            return Ok(None);
        };
        Ok(Some(EvmTransactionFacts {
            chain_id,
            tx_hash: bytes::<32>(tx_hash).expect("32-byte tx hash"),
            from: a.from,
            to: Some(a.to),
            input: a.input.clone(),
            inclusion: Some(EvmInclusion {
                block_number: a.block,
                block_hash: [0xee; 32],
                block_time: a.time,
                succeeded: true,
            }),
            head: EvmChainHead {
                latest: BLOCK + 100,
                safe: Some(BLOCK + 50),
                finalized: Some(BLOCK + 20),
            },
        }))
    }
}

impl aqua_rs_sdk::BlockchainHost for HonestChain {
    fn transaction_facts(
        &self,
        chain_id: u64,
        tx_hash: &str,
    ) -> Result<Option<EvmTransactionFacts>, HostError> {
        Self::facts(chain_id, tx_hash)
    }
}
