use std::time::Duration;

use crate::types::AnchorMethod;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("server returned {status}: {body}")]
    Server { status: u16, body: String },

    #[error("server identity at {base_url} could not be discovered: {source}")]
    IdentityDiscovery {
        base_url: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("server identity rotated from {prior} to {discovered}")]
    ServerIdentityRotated { prior: String, discovered: String },

    #[error("witness signature does not recover to pinned server DID")]
    SignatureMismatch,

    #[error("witness for leaf {leaf} via {method:?} not yet available")]
    NotYetSealed { leaf: String, method: AnchorMethod },

    #[error("witness for leaf {leaf} via {method:?} not found (epoch sealed but no witness present)")]
    WitnessMissing { leaf: String, method: AnchorMethod },

    #[error("timeout waiting for witness after {elapsed:?}")]
    Timeout { elapsed: Duration },

    #[error("invalid input: {0}")]
    Invalid(String),

    #[error("url error: {0}")]
    Url(#[from] url::ParseError),

    #[error("serialisation error: {0}")]
    Serde(#[from] serde_json::Error),
}
