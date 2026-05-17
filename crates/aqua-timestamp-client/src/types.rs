use aqua_rs_sdk::schema::AnyRevision;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum AnchorMethod {
    Evm,
    Qtsa,
}

impl AnchorMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            AnchorMethod::Evm => "evm",
            AnchorMethod::Qtsa => "qtsa",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "evm" => Some(AnchorMethod::Evm),
            "qtsa" => Some(AnchorMethod::Qtsa),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SubmissionReceipt {
    pub leaf: [u8; 32],
    pub epoch_id: u64,
    pub epoch_closes_at: u64,
    pub submitter_did: String,
}

#[derive(Clone, Debug)]
pub struct WitnessPair {
    pub object_revision: AnyRevision,
    pub signature_revision: AnyRevision,
    pub object_hash: String,
    pub signature_hash: String,
    pub anchor_method: AnchorMethod,
}

#[derive(Clone, Debug, Deserialize)]
pub struct EpochSchedule {
    pub current_epoch_id: u64,
    pub current_epoch_opened_at: u64,
    pub current_epoch_closes_at: u64,
    pub epoch_duration_secs: u64,
    pub last_sealed_epoch_id: Option<u64>,
    pub last_sealed_at: Option<u64>,
    pub anchor_methods: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ServerIdentity {
    pub did: String,
    pub address: String,
    pub identity_response_json: serde_json::Value,
}
