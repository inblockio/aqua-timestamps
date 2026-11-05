//! The reader's inputs of a seal run: which witnesses and which sealer signature the reader
//! accepts, and the hosts it asks. Inputs only: the admission itself is the SDK's.

use std::collections::BTreeSet;
use std::sync::Arc;

use anyhow::Result;
use aqua_rs_sdk::core::seal::{
    EvmAcceptance, EvmFinality, PolicyOrigin, SignatureCatalogue, TsaAcceptance, WitnessAcceptance,
    WitnessInput,
};
use aqua_rs_sdk::core::verification_policy::VerificationPolicy;
use aqua_rs_sdk::Aquafier;
use serde_json::{json, Value};

use crate::flow::ReaderConfig;
use crate::witness::ReaderHosts;

/// What a reader accepts. [`ReaderPolicy::open_witness`] is the pinned policy of the
/// openwitness.org witnesses.
#[derive(Debug, Clone)]
pub struct ReaderPolicy {
    pub tsa_policy_oid: String,
    /// Exact RFC 4514 text of the token signer's issuer.
    pub tsa_issuer: String,
    pub evm_chain_id: u64,
    pub evm_contract: String,
    /// The sealer signature type admitted: the standing identity signs EIP-191, and the SDK's
    /// default catalogue excludes it, so without this non-suppression reads `not_checked`.
    pub sealer_signature_type: String,
}

const CATALOGUE_SOURCE: &str = "reader policy openwitness-seal-e2e";

impl ReaderPolicy {
    pub fn open_witness() -> Self {
        Self {
            tsa_policy_oid: "0.4.0.2023.1.1".into(),
            tsa_issuer: "CN=Sectigo Qualified Time Stamping CA R35,O=Sectigo (Europe) SL,C=ES"
                .into(),
            evm_chain_id: 11_155_111,
            evm_contract: "0x269Ff9a5CB9BD5319bd95b248d2579Aa1e9D78FE".into(),
            sealer_signature_type: "ethereum:eip-191".into(),
        }
    }

    fn tsa(&self) -> TsaAcceptance {
        TsaAcceptance {
            policy_oids: BTreeSet::from([self.tsa_policy_oid.clone()]),
            issuers: Some(BTreeSet::from([self.tsa_issuer.clone()])),
        }
    }

    /// P2: the pinned dual stamp, TSA and EVM.
    pub fn dual(&self) -> WitnessInput {
        WitnessInput::policy(
            WitnessAcceptance {
                source: "reader policy openwitness-seal-e2e P2 (pinned dual)".into(),
                tsa: Some(self.tsa()),
                evm: Some(EvmAcceptance {
                    chain_ids: BTreeSet::from([self.evm_chain_id]),
                    contracts: BTreeSet::from([self.evm_contract.clone()]),
                    finality: EvmFinality::Finalized,
                }),
            },
            PolicyOrigin::ReaderLocal,
        )
    }

    /// P3: qTSA only, no EVM accepted.
    pub fn tsa_only(&self) -> WitnessInput {
        WitnessInput::policy(
            WitnessAcceptance {
                source: "reader policy openwitness-seal-e2e P3 (qTSA only)".into(),
                tsa: Some(self.tsa()),
                evm: None,
            },
            PolicyOrigin::ReaderLocal,
        )
    }

    pub fn catalogue(&self) -> SignatureCatalogue {
        SignatureCatalogue::custom(CATALOGUE_SOURCE, [self.sealer_signature_type.as_str()])
    }

    /// The policy as one JSON line for the step log: no hidden inputs.
    pub fn describe(&self, name: &str, with_evm: bool, label_pin: &str) -> String {
        let evm = if with_evm {
            json!({
                "chain_ids": [self.evm_chain_id],
                "contracts": [self.evm_contract],
                "finality": "finalized",
            })
        } else {
            Value::Null
        };
        json!({
            "policy": name,
            "origin": "ReaderLocal",
            "tsa": {"policy_oids": [self.tsa_policy_oid], "issuers": [self.tsa_issuer]},
            "evm": evm,
            "sealer_catalogue": {
                "kind": "Custom",
                "source": CATALOGUE_SOURCE,
                "admitted": [self.sealer_signature_type],
            },
            "attestation_label_pins": [label_pin],
        })
        .to_string()
    }
}

/// The builder and reader `Aquafier` with its policy. Strict, as every seal read here is.
#[derive(Clone)]
pub struct Reader {
    pub aq: Arc<Aquafier>,
    pub policy: ReaderPolicy,
}

impl Reader {
    pub fn new(hosts: ReaderHosts, policy: ReaderPolicy) -> Self {
        let aq = Aquafier::builder()
            .verification_policy(VerificationPolicy::strict())
            .web_host(hosts.web)
            .blockchain_host(hosts.blockchain)
            .build();
        Self {
            aq: Arc::new(aq),
            policy,
        }
    }

    /// The real hosts: the EU trust list for TSA tokens (no network) and the chain over RPC
    /// (`evm_rpc_url`, else the public Sepolia node). Needs a tokio runtime.
    pub fn live(evm_rpc_url: Option<String>) -> Result<Self> {
        let hosts = ReaderConfig::Live { evm_rpc_url }.hosts("sepolia")?;
        Ok(Self::new(hosts, ReaderPolicy::open_witness()))
    }
}
