//! Shared application state.

use std::{sync::Arc, time::Instant};

use aqua_auth::{ChallengeStore, SessionStore};
use aqua_rs_sdk::Secp256k1Signer;
use aqua_timestamp_core::{accumulator::Accumulator, sealer::WitnessContext, storage::Store};

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
    /// EIP-191 signer constructed once at boot from the loaded service
    /// private key. Owned via `Arc` so the sealer task (running on a
    /// detached tokio task) and any future route handler that needs to
    /// sign on the request path can share it without copying the key
    /// material.
    pub signer: Arc<Secp256k1Signer>,
    /// Witness payload context: methods, network labels, signer. Kept on
    /// the state so handlers that surface "what would this leaf look like
    /// if we re-minted now?" can reach the same configuration.
    pub witness_ctx: WitnessContext,
    /// Pre-rendered self-served agent integration guide. Browser-friendly
    /// HTML served at `GET /docs`. Built once at boot from the loaded
    /// identity so DNS / IP / DID values are correct without an edit.
    pub docs_html: String,
    /// Pre-rendered agent skill markdown served at `GET /docs/skill.md`.
    /// Same content as `docs_html`, in the `~/.claude/skills/<name>/SKILL.md`
    /// format so an agent can drop it straight into its skill library.
    pub docs_skill_md: String,
}

impl AppState {
    pub fn is_allowed(&self, did: &str) -> bool {
        let list = &self.config.auth.allowed_dids;
        list.is_empty() || list.iter().any(|d| d == did)
    }
}
