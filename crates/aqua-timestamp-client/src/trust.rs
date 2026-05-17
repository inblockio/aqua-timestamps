use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct ServerRotation {
    pub prior_did: String,
    pub discovered_did: String,
    pub discovered_identity_response: serde_json::Value,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RotationDecision {
    Accept,
    Reject,
}

#[derive(Clone)]
pub enum OnRotation {
    Refuse,
    Warn,
    Custom(Arc<dyn Fn(&ServerRotation) -> RotationDecision + Send + Sync>),
}

impl std::fmt::Debug for OnRotation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OnRotation::Refuse => f.write_str("OnRotation::Refuse"),
            OnRotation::Warn => f.write_str("OnRotation::Warn"),
            OnRotation::Custom(_) => f.write_str("OnRotation::Custom(<fn>)"),
        }
    }
}
