//! Shared application state.

use std::{sync::Arc, time::Instant};

use aqua_auth::{ChallengeStore, SessionStore};
use aqua_timestamp_core::{accumulator::Accumulator, storage::Store};

use crate::{config::Config, identity::ServiceIdentity};

pub struct AppState {
    pub started_at: Instant,
    pub config: Config,
    pub identity: ServiceIdentity,
    pub identity_response_json: serde_json::Value,
    pub challenges: Arc<ChallengeStore>,
    pub sessions: Arc<SessionStore>,
    pub accumulator: Arc<Accumulator>,
    pub store: Store,
}

impl AppState {
    pub fn is_allowed(&self, did: &str) -> bool {
        let list = &self.config.auth.allowed_dids;
        list.is_empty() || list.iter().any(|d| d == did)
    }
}
