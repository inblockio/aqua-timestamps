//! Epoch sealing task: closes the current epoch, builds its Merkle root,
//! and persists the `EpochRecord`, its leaf set, AND every per-leaf
//! witness revision pair (M3).
//!
//! Production uses [`run_sealer_with_interval`], which ticks
//! `epoch_duration_secs` on the tokio runtime clock. Tests use
//! [`run_sealer_with_channel`], which seals once per message on the
//! supplied [`SealTick`] channel; this keeps tests deterministic without
//! needing `tokio::time::advance`.

use std::sync::Arc;
use std::time::Duration;

use aqua_rs_sdk::Secp256k1Signer;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::accumulator::{Accumulator, SealedSnapshot};
use crate::anchors::AnchorProvider;
use crate::epoch::{EpochRecord, HASH_TYPE_LABEL};
use crate::merkle::{merkle_root_for_leaves, Hash32};
use crate::storage::{Store, StoreError};
use crate::time::Clock;
use crate::witness::{
    mint_witnesses_for_epoch, AnchorMethod, MethodAnchorOutcome, MintedWitness, WitnessError,
};

/// Per-process configuration the sealer needs in addition to its
/// already-required `(accumulator, store, clock, duration)` quad: which
/// methods to mint, what static labels to put in the witness payloads,
/// and (optionally) live anchor providers for each method.
///
/// Cloned cheaply (only owned strings + `Arc`s).
#[derive(Clone)]
pub struct WitnessContext {
    pub signer: Arc<Secp256k1Signer>,
    /// EIP-55 ethereum address of the service key, prefixed with `0x`.
    pub service_eth_address: String,
    /// Network name written into the EVM witness payload (e.g. `"sepolia"`).
    pub evm_network: String,
    /// Methods to mint per leaf. Production uses both; tests can mint one.
    pub methods: Vec<AnchorMethod>,
    /// Live EVM anchor provider. When `Some`, the sealer submits the
    /// per-epoch Merkle root to Sepolia (or whatever chain the provider
    /// was constructed for) and folds the resulting `transaction_hash`,
    /// `sender`, `smart_contract_address`, `network` into every leaf's
    /// EVM witness payload. When `None`, EVM witnesses carry stub anchor
    /// data and look identical to what M3 emitted.
    pub evm_anchor: Option<Arc<dyn AnchorProvider>>,
    /// Live qTSA anchor provider. Always `None` until M5; included so the
    /// shape is stable across milestones.
    pub qtsa_anchor: Option<Arc<dyn AnchorProvider>>,
}

impl WitnessContext {
    pub fn new(
        signer: Arc<Secp256k1Signer>,
        service_eth_address: String,
        evm_network: String,
        methods: Vec<AnchorMethod>,
    ) -> Self {
        Self {
            signer,
            service_eth_address,
            evm_network,
            methods,
            evm_anchor: None,
            qtsa_anchor: None,
        }
    }

    /// Builder-style: attach a live EVM anchor provider.
    pub fn with_evm_anchor(mut self, anchor: Arc<dyn AnchorProvider>) -> Self {
        self.evm_anchor = Some(anchor);
        self
    }

    /// Builder-style: attach a live qTSA anchor provider. M5+ only.
    pub fn with_qtsa_anchor(mut self, anchor: Arc<dyn AnchorProvider>) -> Self {
        self.qtsa_anchor = Some(anchor);
        self
    }
}

#[derive(Debug, Error)]
pub enum SealError {
    #[error("storage: {0}")]
    Store(#[from] StoreError),
    #[error("witness: {0}")]
    Witness(#[from] WitnessError),
}

/// A test-driven seal request. The contained `now` value is used as the
/// `closed_at` timestamp for the sealed epoch and as the opening time for
/// the next epoch. Production code never constructs these directly.
#[derive(Debug, Clone, Copy)]
pub struct SealTick {
    pub now: u64,
}

/// Run a single seal cycle and return the persisted record together with
/// every witness minted during the cycle.
///
/// `closed_at` is the moment the seal observed; the next epoch opens at
/// `closed_at` and closes `duration_secs` later. When `witness_ctx` is
/// `None`, the seal still produces an `EpochRecord` but skips witness
/// minting (used by accumulator-only tests and by the M2-shape callers
/// that have not yet plumbed in a signer).
///
/// Live anchors are best-effort. Each per-method provider in
/// `witness_ctx` is invoked exactly once per non-empty epoch with the
/// final Merkle root; on success the returned [`TimestampValue`] is
/// folded into every per-leaf witness for that method, on failure the
/// sealer logs a `warn!` and falls back to stub data for that method's
/// witnesses this epoch. Sealing never fails because an anchor failed;
/// the next epoch retries.
///
/// Empty epochs are never anchored: when `snapshot.leaves.is_empty()` the
/// live provider is not called (no gas / RPC traffic for a degenerate
/// root) and no witnesses are minted, matching the M3 behaviour for
/// empty epochs.
pub async fn seal_once(
    accumulator: &Accumulator,
    store: &Store,
    closed_at: u64,
    duration_secs: u64,
    witness_ctx: Option<&WitnessContext>,
) -> Result<(EpochRecord, Vec<MintedWitness>), SealError> {
    let snapshot = accumulator.swap_and_open_next(closed_at, closed_at, duration_secs);
    let (record, sorted_leaves) = build_record_and_sorted_leaves(&snapshot);

    let witnesses = if let Some(ctx) = witness_ctx {
        let merkle_root_hex = format!("0x{}", hex::encode(record.merkle_root));
        let outcomes = resolve_method_outcomes(ctx, record.id, &merkle_root_hex, &snapshot).await;
        let minted = mint_witnesses_for_epoch(
            &snapshot,
            &record.merkle_root,
            &sorted_leaves,
            &outcomes,
            Arc::clone(&ctx.signer),
            closed_at,
        )
        .await?;
        for w in &minted {
            info!(
                leaf = %format!("0x{}", hex::encode(w.leaf)),
                method = %w.method.as_str(),
                tip = %format!("0x{}", hex::encode(w.signature_hash)),
                epoch = w.epoch_id,
                "witness minted"
            );
        }
        minted
    } else {
        Vec::new()
    };

    store.persist_sealed_epoch(&record, &snapshot.leaves, &witnesses)?;

    info!(
        id = record.id,
        root = %record.merkle_root_hex(),
        leaves = record.leaf_count,
        witnesses = witnesses.len(),
        "epoch sealed"
    );
    Ok((record, witnesses))
}

/// Resolve the per-method anchor outcomes for one seal cycle.
///
/// Walks `ctx.methods` in order and produces a `(method, outcome)` tuple
/// for each: if a live provider for the method is wired AND the snapshot
/// has leaves, call the provider and translate the result; otherwise
/// build a stub outcome with the same shape so the witness minter sees
/// uniform inputs.
///
/// All anchor errors are caught here and logged via `warn!`; never
/// surfaced upward. The fall-back outcome carries the configured
/// `network` / EIP-55 address so a stub-fallback witness is
/// indistinguishable from a real witness except for the all-zero
/// `transaction_hash` and contract address.
async fn resolve_method_outcomes(
    ctx: &WitnessContext,
    epoch_id: u64,
    merkle_root_hex: &str,
    snapshot: &SealedSnapshot,
) -> Vec<(AnchorMethod, MethodAnchorOutcome)> {
    let mut out: Vec<(AnchorMethod, MethodAnchorOutcome)> = Vec::with_capacity(ctx.methods.len());
    for method in &ctx.methods {
        let outcome = match method {
            AnchorMethod::Evm => {
                resolve_evm_outcome(ctx, epoch_id, merkle_root_hex, snapshot).await
            }
            AnchorMethod::Qtsa => {
                resolve_qtsa_outcome(ctx, epoch_id, merkle_root_hex, snapshot).await
            }
        };
        out.push((*method, outcome));
    }
    out
}

async fn resolve_qtsa_outcome(
    ctx: &WitnessContext,
    epoch_id: u64,
    merkle_root_hex: &str,
    snapshot: &SealedSnapshot,
) -> MethodAnchorOutcome {
    let stub = MethodAnchorOutcome::stub_qtsa;
    let Some(anchor) = ctx.qtsa_anchor.as_ref() else {
        return stub();
    };
    // Same guard as EVM: empty epoch never triggers a live RFC 3161
    // request even if a provider is attached.
    if snapshot.leaves.is_empty() {
        return stub();
    }
    match anchor.create_timestamp(merkle_root_hex).await {
        Ok(value) => {
            info!(
                epoch_id,
                merkle_root_hex,
                tx_hash = %value.transaction_hash,
                tsa_provider = %value.tsa_provider,
                tsa_url = %value.smart_contract_address,
                gen_time = value.timestamp,
                "qtsa anchor submitted"
            );
            MethodAnchorOutcome::from_tsa_timestamp_value(&value)
        }
        Err(e) => {
            warn!(
                epoch_id,
                merkle_root_hex,
                error = %e,
                "qtsa anchor failed, falling back to stub"
            );
            stub()
        }
    }
}

async fn resolve_evm_outcome(
    ctx: &WitnessContext,
    epoch_id: u64,
    merkle_root_hex: &str,
    snapshot: &SealedSnapshot,
) -> MethodAnchorOutcome {
    let stub = || MethodAnchorOutcome::stub_evm(&ctx.service_eth_address, &ctx.evm_network);
    let Some(anchor) = ctx.evm_anchor.as_ref() else {
        return stub();
    };
    // Defensive: a non-empty `evm_anchor` slot should only ever be hit
    // for non-empty epochs (the sealer is the only call-site and skips
    // the anchor for empty snapshots by the time `resolve_*` runs only
    // when the snapshot is non-empty). Keep the guard so a future caller
    // can't burn gas on an empty root by accident.
    if snapshot.leaves.is_empty() {
        return stub();
    }
    match anchor.create_timestamp(merkle_root_hex).await {
        Ok(value) => {
            info!(
                epoch_id,
                merkle_root_hex,
                tx_hash = %value.transaction_hash,
                sender = %value.sender_account_address,
                "evm anchor submitted"
            );
            MethodAnchorOutcome::from_evm_timestamp_value(&value)
        }
        Err(e) => {
            warn!(
                epoch_id,
                merkle_root_hex,
                error = %e,
                "evm anchor failed, falling back to stub"
            );
            stub()
        }
    }
}

/// Pure helper: convert an in-memory [`SealedSnapshot`] into the on-disk
/// [`EpochRecord`] and the sorted leaf list used both for the Merkle root
/// and the per-leaf inclusion proofs. Leaves are sorted lexicographically
/// by raw bytes before being fed to the SDK Merkle builder, so the root
/// is independent of submission order (the property the test suite
/// asserts).
fn build_record_and_sorted_leaves(snapshot: &SealedSnapshot) -> (EpochRecord, Vec<Hash32>) {
    let mut sorted: Vec<Hash32> = snapshot.leaves.iter().map(|e| e.leaf).collect();
    sorted.sort_unstable();
    let root = merkle_root_for_leaves(&sorted);
    let record = EpochRecord {
        id: snapshot.epoch_id,
        opened_at: snapshot.opened_at,
        closed_at: snapshot.closed_at,
        merkle_root: root,
        leaf_count: snapshot.leaves.len() as u64,
        hash_type: HASH_TYPE_LABEL.to_string(),
    };
    (record, sorted)
}

/// Spawn the production seal loop on the current tokio runtime. Returns
/// the join handle so the supervisor (or test) can await shutdown.
pub fn run_sealer_with_interval<C: Clock + 'static>(
    accumulator: Arc<Accumulator>,
    store: Store,
    clock: C,
    duration_secs: u64,
    witness_ctx: Option<WitnessContext>,
    event_bus: Option<crate::events::EventBus>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(duration_secs.max(1)));
        // First tick fires immediately; skip it so the first seal happens
        // one duration after startup, not on boot.
        interval.tick().await;
        loop {
            interval.tick().await;
            let now = clock.now_secs();
            match seal_once(
                &accumulator,
                &store,
                now,
                duration_secs,
                witness_ctx.as_ref(),
            )
            .await
            {
                Ok((record, _witnesses)) => {
                    if let Some(ref bus) = event_bus {
                        bus.send(crate::events::SseEvent::EpochSealed {
                            epoch_id: record.id,
                            leaf_count: record.leaf_count,
                            merkle_root: record.merkle_root_hex(),
                            timestamp: now,
                        });
                    }
                }
                Err(e) => {
                    error!(error = %e, "seal cycle failed");
                }
            }
        }
    })
}

/// Bonding-curve parameters passed from the config layer.
#[derive(Debug, Clone)]
pub struct BondingCurveParams {
    pub n_half: u64,
    pub poll_interval_secs: u64,
    pub min_balance_multiplier: u64,
}

/// Spawn an adaptive seal loop driven by the bonding curve. Instead of
/// sealing on a fixed timer, this loop polls `oracle` for the current
/// wallet balance and gas cost, computes the publication rate via
/// `bonding_curve::publication_rate`, and seals when the resulting block
/// interval has elapsed.
///
/// Falls back to the minimum-runway behaviour automatically: when funds
/// are low the interval grows; when the oracle fails the loop retries
/// after `poll_interval_secs` without sealing.
pub fn run_sealer_with_bonding_curve<C: Clock + 'static>(
    accumulator: Arc<Accumulator>,
    store: Store,
    clock: C,
    oracle: Arc<dyn crate::bonding_curve::BalanceOracle>,
    params: BondingCurveParams,
    witness_ctx: Option<WitnessContext>,
    event_bus: Option<crate::events::EventBus>,
) -> tokio::task::JoinHandle<()> {
    use crate::bonding_curve;

    tokio::spawn(async move {
        let poll = Duration::from_secs(params.poll_interval_secs.max(1));
        let mut last_seal_block: u64 = 0;
        let mut virtual_block: u64 = 0;

        loop {
            tokio::time::sleep(poll).await;
            virtual_block += 1;

            let (balance, gas_cost) = match oracle.balance_and_gas_cost().await {
                Ok(pair) => pair,
                Err(e) => {
                    warn!(error = %e, "bonding curve oracle query failed, skipping cycle");
                    continue;
                }
            };

            if gas_cost == 0 {
                warn!("oracle returned zero gas cost, skipping cycle");
                continue;
            }

            let min_balance = gas_cost * params.min_balance_multiplier as u128;
            if balance < min_balance {
                info!(
                    balance_wei = balance,
                    min_balance_wei = min_balance,
                    "balance below safety margin, skipping seal"
                );
                continue;
            }

            let rate = bonding_curve::publication_rate(balance, gas_cost, params.n_half);
            let interval = bonding_curve::block_interval(rate);
            let runway = bonding_curve::runway_blocks(balance, gas_cost, params.n_half);

            if (virtual_block - last_seal_block) >= interval {
                let now = clock.now_secs();
                info!(
                    rate = format!("{rate:.4}"),
                    interval_blocks = interval,
                    runway_blocks = format!("{runway:.0}"),
                    balance_wei = balance,
                    gas_cost_wei = gas_cost,
                    "bonding curve seal triggered"
                );
                match seal_once(
                    &accumulator,
                    &store,
                    now,
                    params.poll_interval_secs,
                    witness_ctx.as_ref(),
                )
                .await
                {
                    Ok((record, _witnesses)) => {
                        if let Some(ref bus) = event_bus {
                            bus.send(crate::events::SseEvent::EpochSealed {
                                epoch_id: record.id,
                                leaf_count: record.leaf_count,
                                merkle_root: record.merkle_root_hex(),
                                timestamp: now,
                            });
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "bonding curve seal cycle failed");
                    }
                }
                last_seal_block = virtual_block;
            }
        }
    })
}

/// Test alternative to the real timer: seal once per message received.
pub fn run_sealer_with_channel(
    accumulator: Arc<Accumulator>,
    store: Store,
    mut rx: mpsc::Receiver<SealTick>,
    duration_secs: u64,
    witness_ctx: Option<WitnessContext>,
    event_bus: Option<crate::events::EventBus>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(tick) = rx.recv().await {
            match seal_once(
                &accumulator,
                &store,
                tick.now,
                duration_secs,
                witness_ctx.as_ref(),
            )
            .await
            {
                Ok((record, _witnesses)) => {
                    if let Some(ref bus) = event_bus {
                        bus.send(crate::events::SseEvent::EpochSealed {
                            epoch_id: record.id,
                            leaf_count: record.leaf_count,
                            merkle_root: record.merkle_root_hex(),
                            timestamp: tick.now,
                        });
                    }
                }
                Err(e) => {
                    error!(error = %e, "seal cycle failed");
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anchors::{FailingProvider, MockProvider};
    use crate::time::FixedClock;
    use aqua_rs_sdk::schema::{timestamp::TimestampValue, AnyRevision};
    use tempfile::tempdir;

    const DID_A: &str = "did:pkh:eip155:1:0xaaaa000000000000000000000000000000000000";
    const DID_B: &str = "did:pkh:eip155:1:0xbbbb000000000000000000000000000000000000";
    const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";

    async fn build_signer() -> Arc<Secp256k1Signer> {
        let (_addr, _eip55, pk_hex) = aqua_rs_sdk::primitives::get_wallet(TEST_MNEMONIC)
            .await
            .unwrap();
        let pk = hex::decode(pk_hex.trim_start_matches("0x")).unwrap();
        Arc::new(Secp256k1Signer::new(pk))
    }

    fn base_ctx(signer: Arc<Secp256k1Signer>) -> WitnessContext {
        WitnessContext::new(
            signer,
            "0x0000000000000000000000000000000000000000".into(),
            "sepolia".into(),
            vec![AnchorMethod::Evm, AnchorMethod::Qtsa],
        )
    }

    fn canned_evm_value() -> TimestampValue {
        TimestampValue {
            merkle_proof: vec![],
            sender_account_address: "0xCAFE000000000000000000000000000000000000".into(),
            tsa_provider: String::new(),
            transaction_hash: "0xfeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface"
                .into(),
            smart_contract_address: "0xDEAD000000000000000000000000000000000000".into(),
            network: "sepolia".into(),
            merkle_root: "0x00".into(),
            timestamp: 60,
            batch_tree_size: 1,
            batch_leaf_index: 0,
            shielding_nonce: String::new(),
        }
    }

    fn extract_evm_payloads(witnesses: &[MintedWitness]) -> Vec<serde_json::Value> {
        witnesses
            .iter()
            .filter(|w| w.method == AnchorMethod::Evm)
            .filter_map(|w| match &w.object_revision {
                AnyRevision::Typed(obj) => {
                    let value = serde_json::to_value(obj).unwrap();
                    value.get("payloads").cloned()
                }
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn happy_path_live_evm_anchor_populates_payloads() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let acc = Accumulator::new(1, 0, 60);
        acc.append_batch(&[[1u8; 32]], DID_A);
        let signer = build_signer().await;
        let mock: Arc<dyn AnchorProvider> = Arc::new(MockProvider {
            value: canned_evm_value(),
        });
        let ctx = base_ctx(signer).with_evm_anchor(Arc::clone(&mock));
        let (_rec, witnesses) = seal_once(&acc, &store, 60, 60, Some(&ctx)).await.unwrap();
        let evm_payloads = extract_evm_payloads(&witnesses);
        assert_eq!(evm_payloads.len(), 1);
        let p = &evm_payloads[0];
        assert_eq!(
            p["transaction_hash"].as_str().unwrap(),
            "0xfeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface"
        );
        assert_eq!(
            p["sender_account_address"].as_str().unwrap(),
            "0xCAFE000000000000000000000000000000000000"
        );
        assert_eq!(
            p["smart_contract_address"].as_str().unwrap(),
            "0xDEAD000000000000000000000000000000000000"
        );
        assert_eq!(p["network"].as_str().unwrap(), "sepolia");
    }

    #[tokio::test]
    async fn fall_back_path_failing_anchor_does_not_fail_seal() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let acc = Accumulator::new(1, 0, 60);
        acc.append_batch(&[[2u8; 32]], DID_A);
        let signer = build_signer().await;
        let failing: Arc<dyn AnchorProvider> = Arc::new(FailingProvider {
            message: "synthetic".into(),
        });
        let ctx = base_ctx(signer).with_evm_anchor(Arc::clone(&failing));
        let (rec, witnesses) = seal_once(&acc, &store, 60, 60, Some(&ctx)).await.unwrap();
        assert_eq!(rec.leaf_count, 1);
        let evm_payloads = extract_evm_payloads(&witnesses);
        assert_eq!(evm_payloads.len(), 1);
        let p = &evm_payloads[0];
        // Stub fall-back: 64 zeros + 40 zeros, service address + sepolia.
        assert_eq!(
            p["transaction_hash"].as_str().unwrap(),
            format!("0x{}", "0".repeat(64))
        );
        assert_eq!(
            p["smart_contract_address"].as_str().unwrap(),
            format!("0x{}", "0".repeat(40))
        );
        assert_eq!(
            p["sender_account_address"].as_str().unwrap(),
            "0x0000000000000000000000000000000000000000"
        );
        assert_eq!(p["network"].as_str().unwrap(), "sepolia");
    }

    #[tokio::test]
    async fn disabled_path_no_provider_uses_stub() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let acc = Accumulator::new(1, 0, 60);
        acc.append_batch(&[[3u8; 32]], DID_A);
        let signer = build_signer().await;
        // No `with_evm_anchor`: live provider is never constructed and
        // the sealer must not call any anchor service.
        let ctx = base_ctx(signer);
        let (_rec, witnesses) = seal_once(&acc, &store, 60, 60, Some(&ctx)).await.unwrap();
        let evm_payloads = extract_evm_payloads(&witnesses);
        assert_eq!(evm_payloads.len(), 1);
        assert_eq!(
            evm_payloads[0]["transaction_hash"].as_str().unwrap(),
            format!("0x{}", "0".repeat(64))
        );
    }

    #[tokio::test]
    async fn empty_epoch_skips_live_anchor() {
        // Tracking provider: counts invocations. If the sealer calls the
        // anchor on an empty epoch, this asserts a fail.
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Counting {
            n: Arc<AtomicUsize>,
        }
        #[async_trait::async_trait]
        impl AnchorProvider for Counting {
            async fn create_timestamp(
                &self,
                _root: &str,
            ) -> Result<TimestampValue, crate::anchors::AnchorError> {
                self.n.fetch_add(1, Ordering::SeqCst);
                Ok(canned_evm_value())
            }
        }
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let acc = Accumulator::new(1, 0, 60);
        let signer = build_signer().await;
        let n = Arc::new(AtomicUsize::new(0));
        let provider: Arc<dyn AnchorProvider> = Arc::new(Counting { n: Arc::clone(&n) });
        let ctx = base_ctx(signer).with_evm_anchor(provider);
        let (rec, witnesses) = seal_once(&acc, &store, 60, 60, Some(&ctx)).await.unwrap();
        assert_eq!(rec.leaf_count, 0);
        assert!(witnesses.is_empty());
        assert_eq!(n.load(Ordering::SeqCst), 0, "no anchor call on empty epoch");
    }

    fn canned_tsa_value() -> TimestampValue {
        TimestampValue {
            merkle_proof: vec![],
            sender_account_address: String::new(),
            tsa_provider: "Sectigo Limited".into(),
            transaction_hash: "0xfee1de1efee1de1efee1de1efee1de1efee1de1efee1de1efee1de1efee1de1e"
                .into(),
            smart_contract_address: "http://timestamp.sectigo.com/qualified".into(),
            network: "tsa".into(),
            merkle_root: "0x00".into(),
            timestamp: 1779010800,
            batch_tree_size: 1,
            batch_leaf_index: 0,
            shielding_nonce: String::new(),
        }
    }

    fn extract_qtsa_payloads(witnesses: &[MintedWitness]) -> Vec<serde_json::Value> {
        witnesses
            .iter()
            .filter(|w| w.method == AnchorMethod::Qtsa)
            .filter_map(|w| match &w.object_revision {
                AnyRevision::Typed(obj) => {
                    let value = serde_json::to_value(obj).unwrap();
                    value.get("payloads").cloned()
                }
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn happy_path_live_qtsa_anchor_populates_payloads() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let acc = Accumulator::new(1, 0, 60);
        acc.append_batch(&[[1u8; 32]], DID_A);
        let signer = build_signer().await;
        let mock: Arc<dyn AnchorProvider> = Arc::new(MockProvider {
            value: canned_tsa_value(),
        });
        let ctx = base_ctx(signer).with_qtsa_anchor(Arc::clone(&mock));
        let (_rec, witnesses) = seal_once(&acc, &store, 60, 60, Some(&ctx)).await.unwrap();
        let qtsa_payloads = extract_qtsa_payloads(&witnesses);
        assert_eq!(qtsa_payloads.len(), 1);
        let p = &qtsa_payloads[0];
        assert_eq!(
            p["transaction_hash"].as_str().unwrap(),
            "0xfee1de1efee1de1efee1de1efee1de1efee1de1efee1de1efee1de1efee1de1e"
        );
        assert_eq!(p["tsa_provider"].as_str().unwrap(), "Sectigo Limited");
    }

    #[tokio::test]
    async fn fall_back_path_failing_qtsa_does_not_fail_seal() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let acc = Accumulator::new(1, 0, 60);
        acc.append_batch(&[[2u8; 32]], DID_A);
        let signer = build_signer().await;
        let failing: Arc<dyn AnchorProvider> = Arc::new(FailingProvider {
            message: "tsa unreachable".into(),
        });
        let ctx = base_ctx(signer).with_qtsa_anchor(Arc::clone(&failing));
        let (rec, witnesses) = seal_once(&acc, &store, 60, 60, Some(&ctx)).await.unwrap();
        assert_eq!(rec.leaf_count, 1);
        let qtsa_payloads = extract_qtsa_payloads(&witnesses);
        assert_eq!(qtsa_payloads.len(), 1);
        let p = &qtsa_payloads[0];
        assert_eq!(
            p["transaction_hash"].as_str().unwrap(),
            format!("0x{}", "0".repeat(64))
        );
        assert_eq!(p["tsa_provider"].as_str().unwrap(), "stub");
    }

    #[tokio::test]
    async fn disabled_path_no_qtsa_provider_uses_stub() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let acc = Accumulator::new(1, 0, 60);
        acc.append_batch(&[[3u8; 32]], DID_A);
        let signer = build_signer().await;
        let ctx = base_ctx(signer);
        let (_rec, witnesses) = seal_once(&acc, &store, 60, 60, Some(&ctx)).await.unwrap();
        let qtsa_payloads = extract_qtsa_payloads(&witnesses);
        assert_eq!(qtsa_payloads.len(), 1);
        assert_eq!(
            qtsa_payloads[0]["transaction_hash"].as_str().unwrap(),
            format!("0x{}", "0".repeat(64))
        );
        assert_eq!(qtsa_payloads[0]["tsa_provider"].as_str().unwrap(), "stub");
    }

    #[tokio::test]
    async fn empty_epoch_skips_qtsa_anchor() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Counting {
            n: Arc<AtomicUsize>,
        }
        #[async_trait::async_trait]
        impl AnchorProvider for Counting {
            async fn create_timestamp(
                &self,
                _root: &str,
            ) -> Result<TimestampValue, crate::anchors::AnchorError> {
                self.n.fetch_add(1, Ordering::SeqCst);
                Ok(canned_tsa_value())
            }
        }
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let acc = Accumulator::new(1, 0, 60);
        let signer = build_signer().await;
        let n = Arc::new(AtomicUsize::new(0));
        let provider: Arc<dyn AnchorProvider> = Arc::new(Counting { n: Arc::clone(&n) });
        let ctx = base_ctx(signer).with_qtsa_anchor(provider);
        let (rec, witnesses) = seal_once(&acc, &store, 60, 60, Some(&ctx)).await.unwrap();
        assert_eq!(rec.leaf_count, 0);
        assert!(witnesses.is_empty());
        assert_eq!(
            n.load(Ordering::SeqCst),
            0,
            "no qtsa request on empty epoch"
        );
    }

    #[tokio::test]
    async fn seal_once_persists_record_and_leaves() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let acc = Accumulator::new(1, 0, 60);
        let l1 = [1u8; 32];
        let l2 = [2u8; 32];
        acc.append_batch(&[l1], DID_A);
        acc.append_batch(&[l2], DID_B);

        let (rec, witnesses) = seal_once(&acc, &store, 60, 60, None).await.expect("seal");
        assert_eq!(rec.id, 1);
        assert_eq!(rec.leaf_count, 2);
        assert!(witnesses.is_empty(), "no witness ctx → no witnesses");

        let mut leaves_sorted = vec![l1, l2];
        leaves_sorted.sort_unstable();
        let expected_root = merkle_root_for_leaves(&leaves_sorted);
        assert_eq!(rec.merkle_root, expected_root);

        // Next epoch is open.
        let view = acc.current_view();
        assert_eq!(view.epoch_id, 2);
    }

    #[tokio::test]
    async fn empty_epoch_seals_with_empty_root() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let acc = Accumulator::new(1, 0, 60);
        let (rec, _) = seal_once(&acc, &store, 60, 60, None).await.expect("seal");
        assert_eq!(rec.leaf_count, 0);
        assert_eq!(rec.merkle_root, crate::merkle::empty_merkle_root());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn channel_sealer_advances_epoch() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let acc = Arc::new(Accumulator::new(1, 0, 60));
        let (tx, rx) = mpsc::channel::<SealTick>(8);

        let _clock = FixedClock::new(0);
        let handle = run_sealer_with_channel(Arc::clone(&acc), store.clone(), rx, 60, None, None);

        acc.append_batch(&[[7u8; 32]], DID_A);
        tx.send(SealTick { now: 60 }).await.unwrap();

        // Give the task one yield to process; close the channel to let it
        // exit cleanly.
        tokio::task::yield_now().await;
        drop(tx);
        let _ = handle.await;

        let rec = store.get_epoch(1).unwrap().expect("sealed");
        assert_eq!(rec.id, 1);
        assert_eq!(rec.leaf_count, 1);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn bonding_curve_sealer_seals_on_computed_interval() {
        use crate::bonding_curve::MockOracle;

        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let acc = Arc::new(Accumulator::new(1, 0, 60));
        acc.append_batch(&[[8u8; 32]], DID_A);

        let clock = FixedClock::new(60);
        // 10 ETH balance, 0.00135 ETH gas => ~7407 txs => rate ~0.643 => interval 2
        let oracle = Arc::new(MockOracle {
            balance_wei: 10_000_000_000_000_000_000,
            gas_cost_wei: 1_350_000_000_000_000,
        }) as Arc<dyn crate::bonding_curve::BalanceOracle>;

        let params = BondingCurveParams {
            n_half: 7200,
            poll_interval_secs: 1,
            min_balance_multiplier: 2,
        };

        let handle = run_sealer_with_bonding_curve(
            Arc::clone(&acc),
            store.clone(),
            clock,
            oracle,
            params,
            None,
            None,
        );

        // Advance one tick at a time, yielding between each so the
        // spawned task processes each sleep wake-up.
        for _ in 0..4 {
            tokio::time::advance(std::time::Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
        }

        handle.abort();
        let _ = handle.await;

        let rec = store
            .get_epoch(1)
            .unwrap()
            .expect("epoch 1 should be sealed");
        assert_eq!(rec.leaf_count, 1);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn bonding_curve_sealer_skips_on_low_balance() {
        use crate::bonding_curve::MockOracle;

        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let acc = Arc::new(Accumulator::new(1, 0, 60));
        acc.append_batch(&[[9u8; 32]], DID_A);

        let clock = FixedClock::new(60);
        // Balance < 2 * gas_cost: should not seal
        let oracle = Arc::new(MockOracle {
            balance_wei: 1_000_000_000_000_000,  // 0.001 ETH
            gas_cost_wei: 1_350_000_000_000_000, // 0.00135 ETH
        }) as Arc<dyn crate::bonding_curve::BalanceOracle>;

        let params = BondingCurveParams {
            n_half: 7200,
            poll_interval_secs: 1,
            min_balance_multiplier: 2,
        };

        let handle = run_sealer_with_bonding_curve(
            Arc::clone(&acc),
            store.clone(),
            clock,
            oracle,
            params,
            None,
            None,
        );

        tokio::time::advance(std::time::Duration::from_secs(5)).await;
        tokio::task::yield_now().await;

        handle.abort();
        let _ = handle.await;

        assert!(
            store.get_epoch(1).unwrap().is_none(),
            "should not seal when balance is below safety margin"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn bonding_curve_sealer_survives_oracle_failure() {
        use crate::bonding_curve::FailingOracle;

        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let acc = Arc::new(Accumulator::new(1, 0, 60));
        acc.append_batch(&[[10u8; 32]], DID_A);

        let clock = FixedClock::new(60);
        let oracle = Arc::new(FailingOracle {
            message: "rpc down".into(),
        }) as Arc<dyn crate::bonding_curve::BalanceOracle>;

        let params = BondingCurveParams {
            n_half: 7200,
            poll_interval_secs: 1,
            min_balance_multiplier: 2,
        };

        let handle = run_sealer_with_bonding_curve(
            Arc::clone(&acc),
            store.clone(),
            clock,
            oracle,
            params,
            None,
            None,
        );

        tokio::time::advance(std::time::Duration::from_secs(3)).await;
        tokio::task::yield_now().await;

        handle.abort();
        let _ = handle.await;

        assert!(
            store.get_epoch(1).unwrap().is_none(),
            "should not seal when oracle fails"
        );
    }
}
