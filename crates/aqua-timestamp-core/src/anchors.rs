//! Anchor providers: pluggable timestamp services that the seal-time
//! witness minter calls once per epoch to anchor the Merkle root.
//!
//! M3 carried hard-coded stub anchor outputs inside `witness.rs`. M4
//! extracts the "anchor for this Merkle root" surface into a tiny trait
//! ([`AnchorProvider`]) so production can plug in
//! `aqua_rs_sdk::CliEthTimestamper` while tests plug in a [`MockProvider`]
//! or a [`FailingProvider`]. The trait has a blanket impl over the SDK's
//! [`TimestampProvider`]: anything implementing the SDK contract is also
//! an [`AnchorProvider`] for free, no glue per provider.
//!
//! Empty epochs never reach an [`AnchorProvider`]: the sealer skips the
//! anchor call entirely when there are no leaves. See `sealer.rs` for the
//! call-site that enforces that.
//!
//! Failure semantics. The seal-time anchor is best-effort: an
//! [`AnchorProvider::create_timestamp`] error is logged and the sealer
//! falls back to stub witness data for that epoch's EVM method. Sealing
//! never fails because the anchor failed; the next epoch retries. The
//! `with_warn` / fall-back path is owned by the sealer, not this module.

use aqua_rs_sdk::{
    schema::timestamp::TimestampValue, TimestampError as SdkTimestampError, TimestampProvider,
};
use async_trait::async_trait;

/// Error returned by an [`AnchorProvider`]. Wraps the SDK's
/// [`TimestampError`] for parity with the real `CliEthTimestamper`, and
/// lets test mocks construct synthetic errors without depending on the
/// SDK's `Provider(String)` shape.
#[derive(thiserror::Error, Debug)]
pub enum AnchorError {
    /// Surfaced verbatim by the underlying provider. The seal-time
    /// fall-back path matches on this and emits a `warn!` with the
    /// embedded message.
    #[error("anchor provider failed: {0}")]
    Provider(String),
}

impl From<SdkTimestampError> for AnchorError {
    fn from(value: SdkTimestampError) -> Self {
        match value {
            SdkTimestampError::Config(s) => AnchorError::Provider(format!("config: {s}")),
            SdkTimestampError::Provider(s) => AnchorError::Provider(s),
            SdkTimestampError::NotSupported(s) => {
                AnchorError::Provider(format!("not supported: {s}"))
            }
        }
    }
}

/// Pluggable anchor service.
///
/// Implementations submit the per-epoch Merkle root to an external system
/// (Sepolia for EVM, an RFC 3161 TSA for qTSA) and return the resulting
/// [`TimestampValue`] (transaction hash, sender address, smart contract
/// address, network label, anchored timestamp). The witness minter folds
/// those values into every per-leaf TimestampObject payload in the
/// matching epoch, layering per-leaf inclusion proof / index / tree-size
/// on top.
///
/// The trait has a blanket impl over the SDK's
/// [`TimestampProvider`] so production code wires
/// [`aqua_rs_sdk::CliEthTimestamper`] directly: see
/// [`AnchorProvider::for_provider`].
#[async_trait]
pub trait AnchorProvider: Send + Sync {
    /// Submit a hex-encoded Merkle root (`"0x" + 64 hex chars`) to the
    /// anchor service and return the resulting [`TimestampValue`].
    async fn create_timestamp(&self, merkle_root_hex: &str) -> Result<TimestampValue, AnchorError>;
}

/// Blanket impl: any SDK [`TimestampProvider`] is also an
/// [`AnchorProvider`]. The seal-time minter only depends on the local
/// trait, so swapping providers (including a synthetic one in tests) is a
/// trait-object switch, not a structural change.
#[async_trait]
impl<T: TimestampProvider + ?Sized> AnchorProvider for T {
    async fn create_timestamp(&self, merkle_root_hex: &str) -> Result<TimestampValue, AnchorError> {
        TimestampProvider::create_timestamp(self, merkle_root_hex)
            .await
            .map_err(AnchorError::from)
    }
}

/// In-memory provider that returns a caller-supplied [`TimestampValue`].
/// Used by unit tests to assert that the minter folds the canned values
/// (transaction hash, sender, contract, network) into witness payloads.
pub struct MockProvider {
    pub value: TimestampValue,
}

#[async_trait]
impl AnchorProvider for MockProvider {
    async fn create_timestamp(
        &self,
        _merkle_root_hex: &str,
    ) -> Result<TimestampValue, AnchorError> {
        Ok(self.value.clone())
    }
}

/// Anchor provider that always errors. Used by unit tests to assert the
/// sealer falls back to stub witness data without panicking or failing
/// the seal.
pub struct FailingProvider {
    pub message: String,
}

#[async_trait]
impl AnchorProvider for FailingProvider {
    async fn create_timestamp(
        &self,
        _merkle_root_hex: &str,
    ) -> Result<TimestampValue, AnchorError> {
        Err(AnchorError::Provider(self.message.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canned_value() -> TimestampValue {
        TimestampValue {
            merkle_proof: vec![],
            sender_account_address: "0xabc".into(),
            tsa_provider: String::new(),
            transaction_hash: "0xdeadbeef".into(),
            smart_contract_address: "0xcaf".into(),
            network: "sepolia".into(),
            merkle_root: "0x00".into(),
            timestamp: 123,
            batch_tree_size: 1,
            batch_leaf_index: 0,
        }
    }

    #[tokio::test]
    async fn mock_provider_returns_canned_value() {
        let m = MockProvider {
            value: canned_value(),
        };
        let v = m.create_timestamp("0xroot").await.unwrap();
        assert_eq!(v.transaction_hash, "0xdeadbeef");
    }

    #[tokio::test]
    async fn failing_provider_returns_provider_error() {
        let f = FailingProvider {
            message: "synthetic".into(),
        };
        let err = f.create_timestamp("0xroot").await.unwrap_err();
        match err {
            AnchorError::Provider(msg) => assert_eq!(msg, "synthetic"),
        }
    }

    #[tokio::test]
    async fn blanket_impl_over_sdk_provider() {
        // Define an inline SDK TimestampProvider; assert it satisfies the
        // local AnchorProvider trait through the blanket impl.
        struct SdkOne;
        #[async_trait]
        impl TimestampProvider for SdkOne {
            async fn create_timestamp(
                &self,
                _root: &str,
            ) -> Result<TimestampValue, SdkTimestampError> {
                Ok(canned_value())
            }
        }
        let sdk: &dyn AnchorProvider = &SdkOne;
        let v = sdk.create_timestamp("0xroot").await.unwrap();
        assert_eq!(v.transaction_hash, "0xdeadbeef");
    }
}
