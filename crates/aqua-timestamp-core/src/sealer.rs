//! Epoch sealing task: closes the current epoch, prepares its SDK batch,
//! and persists the `EpochRecord`, its leaf set, AND every per-leaf
//! witness revision pair (M3).
//!
//! Production uses [`run_sealer_with_interval`], which ticks
//! `epoch_duration_secs` on the tokio runtime clock. Tests use
//! [`run_sealer_with_channel`], which seals once per message on the
//! supplied [`SealTick`] channel; this keeps tests deterministic without
//! needing `tokio::time::advance`.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use aqua_rs_sdk::Secp256k1Signer;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::accumulator::{Accumulator, SealedSnapshot};
use crate::anchors::AnchorProvider;
use crate::epoch::{EpochRecord, HASH_TYPE_LABEL};
use crate::merkle::{empty_merkle_root, Hash32};
use crate::storage::{Store, StoreError};
use crate::time::Clock;
use crate::witness::{
    mint_witnesses_for_epoch, AnchorMethod, EpochBatch, MethodAnchorOutcome, MintedWitness,
    PendingEpoch, WitnessError,
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
    /// Live EVM anchor provider. The sealer submits the per-epoch batch
    /// root through it and folds the resulting `transaction_hash`,
    /// `sender`, `smart_contract_address`, `network` into every leaf's EVM
    /// witness payload. Required when `methods` holds [`AnchorMethod::Evm`]
    /// ([`Self::validate`]); there is no placeholder witness (D51).
    pub evm_anchor: Option<Arc<dyn AnchorProvider>>,
    /// Live qTSA anchor provider. Required when `methods` holds
    /// [`AnchorMethod::Qtsa`].
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

    /// Builder-style: attach a live qTSA anchor provider.
    pub fn with_qtsa_anchor(mut self, anchor: Arc<dyn AnchorProvider>) -> Self {
        self.qtsa_anchor = Some(anchor);
        self
    }

    /// The provider wired for `method`, if any.
    pub fn provider(&self, method: AnchorMethod) -> Option<&Arc<dyn AnchorProvider>> {
        match method {
            AnchorMethod::Evm => self.evm_anchor.as_ref(),
            AnchorMethod::Qtsa => self.qtsa_anchor.as_ref(),
        }
    }

    /// Decision D51: every enabled method has a provider. A context that
    /// fails this must not start a sealer ([`seal_once`] refuses it before
    /// it closes the epoch).
    pub fn validate(&self) -> Result<(), SealError> {
        match self.methods.iter().find(|m| self.provider(**m).is_none()) {
            Some(m) => Err(SealError::MissingProvider(*m)),
            None => Ok(()),
        }
    }
}

#[derive(Debug, Error)]
pub enum SealError {
    #[error("storage: {0}")]
    Store(#[from] StoreError),
    #[error("witness: {0}")]
    Witness(#[from] WitnessError),
    #[error(
        "anchor method {} is enabled but has no anchor provider; configure it or disable the method",
        .0.as_str()
    )]
    MissingProvider(AnchorMethod),
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
/// Anchoring follows decision D51. Each tick first retries every
/// outstanding anchor ([`retry_pending`]), then closes the epoch: one SDK
/// batch, its root ([`EpochBatch::anchor_root`], `0x1620` + digest,
/// PCA-0015 section 3.8) anchored once per method. A method whose anchor
/// succeeds is minted now. A method whose anchor fails is minted never as a
/// placeholder: its witnesses stay pending, the prepared batch is persisted
/// with the epoch ([`PendingEpoch`]) and every later tick anchors the SAME
/// root again until it succeeds. The methods are independent. A context
/// with an enabled method and no provider is refused before the epoch is
/// closed ([`WitnessContext::validate`]).
///
/// The returned witnesses are every witness minted during the cycle: late
/// ones of earlier epochs (retries) first, then the closed epoch's.
///
/// Empty epochs are never anchored and mint nothing: no batch, no provider
/// call, no pending record.
pub async fn seal_once(
    accumulator: &Accumulator,
    store: &Store,
    closed_at: u64,
    duration_secs: u64,
    witness_ctx: Option<&WitnessContext>,
) -> Result<(EpochRecord, Vec<MintedWitness>), SealError> {
    if let Some(ctx) = witness_ctx {
        ctx.validate()?;
    }
    let (mut witnesses, down) = match witness_ctx {
        Some(ctx) => retry_pending(store, ctx).await,
        None => (Vec::new(), HashSet::new()),
    };

    let snapshot = accumulator.swap_and_open_next(closed_at, closed_at, duration_secs);
    let leaves: Vec<Hash32> = snapshot.leaves.iter().map(|e| e.leaf).collect();
    let batch = EpochBatch::prepare(&leaves)?;
    let record = build_record(&snapshot, batch.as_ref())?;

    let mut minted = Vec::new();
    let mut pending = None;
    if let (Some(ctx), Some(batch)) = (witness_ctx, batch.as_ref()) {
        let mut outcomes = Vec::with_capacity(ctx.methods.len());
        let mut pending_methods = Vec::new();
        for method in &ctx.methods {
            if down.contains(method) {
                warn!(
                    epoch_id = record.id,
                    method = method.as_str(),
                    "anchor provider failed earlier this tick; witnesses stay pending, retried next tick"
                );
                pending_methods.push(*method);
                continue;
            }
            match anchor_root(ctx, *method, record.id, batch.anchor_root()).await {
                Some(outcome) => outcomes.push((*method, outcome)),
                None => pending_methods.push(*method),
            }
        }
        minted =
            mint_witnesses_for_epoch(&snapshot, batch, &outcomes, Arc::clone(&ctx.signer)).await?;
        log_minted(&minted);
        if !pending_methods.is_empty() {
            pending = Some(PendingEpoch::new(&snapshot, batch, pending_methods));
        }
    }

    store.persist_sealed_epoch_with_pending(
        &record,
        &snapshot.leaves,
        &minted,
        pending.as_ref(),
    )?;

    info!(
        id = record.id,
        root = %record.merkle_root_hex(),
        leaves = record.leaf_count,
        witnesses = minted.len(),
        pending = ?pending.as_ref().map(|p| p.methods.iter().map(|m| m.as_str()).collect::<Vec<_>>()),
        "epoch sealed"
    );
    witnesses.extend(minted);
    Ok((record, witnesses))
}

fn log_minted(minted: &[MintedWitness]) {
    for w in minted {
        info!(
            leaf = %format!("0x{}", hex::encode(w.leaf)),
            method = %w.method.as_str(),
            tip = %format!("0x{}", hex::encode(w.signature_hash)),
            epoch = w.epoch_id,
            "witness minted"
        );
    }
}

/// Retry every outstanding anchor, oldest epoch first (decision D51).
///
/// Each pending `(epoch, method)` anchors the epoch's stored root through
/// the method's provider; on success the witnesses are minted from the
/// stored [`PendingEpoch`] (the SDK's own prepared batch, so the same root,
/// nonces and proofs) and persisted together with the shrunken pending
/// record. Per-tick cost: at most one failing provider call per method; a
/// method whose call failed is skipped for the rest of the tick (returned
/// in the second tuple element, so the new epoch does not call it again).
/// The qTSA provider's own request throttle applies to every call. A
/// pending method that is no longer enabled stays pending and is logged.
/// Nothing here fails the seal: errors are logged and retried next tick.
async fn retry_pending(
    store: &Store,
    ctx: &WitnessContext,
) -> (Vec<MintedWitness>, HashSet<AnchorMethod>) {
    let mut down = HashSet::new();
    let mut out = Vec::new();
    let pendings = match store.list_pending_epochs() {
        Ok(p) => p,
        Err(e) => {
            error!(error = %e, "reading pending anchors failed; retried next tick");
            return (out, down);
        }
    };
    for mut pending in pendings {
        for method in pending.methods.clone() {
            if !ctx.methods.contains(&method) {
                warn!(
                    epoch_id = pending.epoch_id,
                    method = method.as_str(),
                    "pending anchor for a disabled method; left pending"
                );
                continue;
            }
            if down.contains(&method) {
                continue;
            }
            let Some(outcome) =
                anchor_root(ctx, method, pending.epoch_id, pending.anchor_root()).await
            else {
                down.insert(method);
                continue;
            };
            let minted = match pending.restore() {
                Ok((snapshot, batch)) => {
                    mint_witnesses_for_epoch(
                        &snapshot,
                        &batch,
                        &[(method, outcome)],
                        Arc::clone(&ctx.signer),
                    )
                    .await
                }
                Err(e) => Err(e),
            };
            let minted = match minted {
                Ok(m) => m,
                Err(e) => {
                    error!(
                        epoch_id = pending.epoch_id,
                        method = method.as_str(),
                        error = %e,
                        "minting a pending anchor failed; retried next tick"
                    );
                    continue;
                }
            };
            let mut remaining = pending.clone();
            remaining.methods.retain(|m| *m != method);
            if let Err(e) = store.persist_pending_minted(&remaining, method, &minted) {
                error!(
                    epoch_id = pending.epoch_id,
                    method = method.as_str(),
                    error = %e,
                    "persisting a pending anchor's witnesses failed; retried next tick"
                );
                continue;
            }
            info!(
                epoch_id = pending.epoch_id,
                method = method.as_str(),
                witnesses = minted.len(),
                "pending anchor minted"
            );
            log_minted(&minted);
            out.extend(minted);
            pending = remaining;
        }
    }
    (out, down)
}

/// Anchor `root` (epoch `epoch_id`) through `method`'s provider. `None` when
/// the call failed: logged with the epoch and method, the witnesses stay
/// pending. The caller has validated that the provider exists.
async fn anchor_root(
    ctx: &WitnessContext,
    method: AnchorMethod,
    epoch_id: u64,
    root: &str,
) -> Option<MethodAnchorOutcome> {
    let anchor = ctx.provider(method)?;
    match anchor.create_timestamp(root).await {
        Ok(value) => {
            info!(
                epoch_id,
                method = method.as_str(),
                root,
                tx_hash = %value.transaction_hash,
                sender = %value.sender_account_address,
                tsa_provider = %value.tsa_provider,
                "anchor submitted"
            );
            Some(match method {
                AnchorMethod::Evm => MethodAnchorOutcome::from_evm_timestamp_value(&value),
                AnchorMethod::Qtsa => MethodAnchorOutcome::from_tsa_timestamp_value(&value),
            })
        }
        Err(e) => {
            warn!(
                epoch_id,
                method = method.as_str(),
                root,
                error = %e,
                "anchor failed; witnesses stay pending, retried next tick"
            );
            None
        }
    }
}

/// Pure helper: convert an in-memory [`SealedSnapshot`] into the on-disk
/// [`EpochRecord`]. The record's root is the digest of the SDK batch root
/// the epoch's anchors carry; an empty epoch prepares no batch and records
/// [`empty_merkle_root`].
fn build_record(
    snapshot: &SealedSnapshot,
    batch: Option<&EpochBatch>,
) -> Result<EpochRecord, WitnessError> {
    let root = match batch {
        Some(batch) => batch.root_digest()?,
        None => empty_merkle_root(),
    };
    Ok(EpochRecord {
        id: snapshot.epoch_id,
        opened_at: snapshot.opened_at,
        closed_at: snapshot.closed_at,
        merkle_root: root,
        leaf_count: snapshot.leaves.len() as u64,
        hash_type: HASH_TYPE_LABEL.to_string(),
    })
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
        let (_addr, _eip55, pk_hex) = aqua_evm_provider::get_wallet(TEST_MNEMONIC).await.unwrap();
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
        .with_evm_anchor(Arc::new(MockProvider {
            value: canned_evm_value(),
        }))
        .with_qtsa_anchor(Arc::new(MockProvider {
            value: canned_tsa_value(),
        }))
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
        let (rec, witnesses) = seal_once(&acc, &store, 60, 60, Some(&ctx)).await.unwrap();
        let evm_payloads = extract_evm_payloads(&witnesses);
        assert_eq!(evm_payloads.len(), 1);
        let p = &evm_payloads[0];
        // The record stores the digest of the SDK batch root the payload carries.
        assert_eq!(
            p["merkle_root"].as_str().unwrap(),
            aqua_rs_sdk::primitives::merkle::batch_root_wire(&rec.merkle_root)
        );
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
    async fn failing_evm_anchor_stays_pending_and_does_not_fail_seal() {
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
        assert!(
            extract_evm_payloads(&witnesses).is_empty(),
            "no EVM witness"
        );
        assert_eq!(extract_qtsa_payloads(&witnesses).len(), 1);
        let pending = store.list_pending_epochs().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].methods, vec![AnchorMethod::Evm]);
        assert_eq!(
            pending[0].anchor_root(),
            aqua_rs_sdk::primitives::merkle::batch_root_wire(&rec.merkle_root)
        );
    }

    #[tokio::test]
    async fn enabled_method_without_provider_refuses_before_closing_the_epoch() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let acc = Accumulator::new(1, 0, 60);
        acc.append_batch(&[[3u8; 32]], DID_A);
        let signer = build_signer().await;
        let mut ctx = base_ctx(signer);
        ctx.evm_anchor = None;
        let err = seal_once(&acc, &store, 60, 60, Some(&ctx))
            .await
            .expect_err("EVM enabled without a provider");
        assert!(matches!(err, SealError::MissingProvider(AnchorMethod::Evm)));
        assert!(err.to_string().contains("evm"), "{err}");
        // The epoch was not closed: the leaf is still in epoch 1.
        let ctx = base_ctx(build_signer().await);
        let (rec, witnesses) = seal_once(&acc, &store, 60, 60, Some(&ctx)).await.unwrap();
        assert_eq!((rec.id, rec.leaf_count, witnesses.len()), (1, 1, 2));
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
    async fn failing_qtsa_anchor_stays_pending_and_does_not_fail_seal() {
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
        assert!(
            extract_qtsa_payloads(&witnesses).is_empty(),
            "no qTSA witness"
        );
        assert_eq!(extract_evm_payloads(&witnesses).len(), 1);
        let pending = store.list_pending_epochs().unwrap();
        assert_eq!(pending[0].methods, vec![AnchorMethod::Qtsa]);
        assert_eq!(
            store
                .get_pending_epoch_for_leaf(&[2u8; 32], AnchorMethod::Qtsa)
                .unwrap(),
            Some(1)
        );
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

        assert_ne!(
            rec.merkle_root,
            crate::merkle::empty_merkle_root(),
            "a non-empty epoch records its SDK batch root"
        );

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
