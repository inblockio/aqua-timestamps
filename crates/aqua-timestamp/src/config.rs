//! TOML config loading.
//!
//! The mnemonic is **not** part of `config.toml`. It is supplied via the
//! `AQUA_TIMESTAMP_ANCHOR_MNEMONIC` environment variable at runtime so the
//! key material never sits next to anything that might end up in version
//! control or a container image.

use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub identity: IdentityConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub epoch: EpochConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub listen: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct IdentityConfig {
    /// Chain id used for `did:pkh:eip155:<chain_id>:<addr>` in the identity
    /// claim payload. Aquafire publishes its identity under chain `1`
    /// (mainnet) because the DID is independent of the anchor chain. M4
    /// will introduce a separate anchor chain id; M1 only needs the
    /// identity chain.
    #[serde(default = "default_chain_id")]
    pub chain_id: u64,

    /// Trust domain advertised in `/.well-known/aqua-identity`. Aquafire
    /// uses `"identity"`; this aggregator's domain is `"timestamp"`.
    #[serde(default = "default_trust_domain")]
    pub trust_domain: String,

    /// Public DNS name of the deployed server, used in the
    /// `service_claim_server` payload. Defaults to the production target so
    /// `cargo run` against the bundled `config.toml.example` produces the
    /// correct claim.
    #[serde(default = "default_dns")]
    pub dns: String,

    /// Public IPv4 address of the deployed server. Pre-filled with the
    /// agentic-hub IP for the same reason.
    #[serde(default = "default_ip")]
    pub ip: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthConfig {
    /// CAIP-122 challenge TTL in seconds. Spec recommendation: 5 minutes.
    #[serde(default = "default_challenge_ttl")]
    pub challenge_ttl_secs: u64,

    /// Bearer session TTL in seconds. Default: 1 hour.
    #[serde(default = "default_session_ttl")]
    pub session_ttl_secs: u64,

    /// DIDs allowed to submit leaves via `POST /v1/leaves`. An empty list
    /// is interpreted as "any authenticated DID may submit", which is the
    /// M1 default while the project is still in development.
    #[serde(default)]
    pub allowed_dids: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StorageConfig {
    /// Directory the fjall keyspace lives in. Created on first start.
    /// In Docker this should be a named volume; the deploy default
    /// mirrors `/var/lib/aqua-timestamp/state`.
    #[serde(default = "default_storage_path")]
    pub path: PathBuf,
}

#[derive(Debug, Deserialize, Clone)]
pub struct EpochConfig {
    /// How long a single accumulator window is open before the seal task
    /// fires. Default 600s (10 min) matches the design-spec target.
    #[serde(default = "default_epoch_duration")]
    pub duration_secs: u64,

    /// Hard cap on leaves per submission. The aggregator returns 400 for
    /// requests above this; M3 will rely on this bound when sizing the
    /// per-batch witness work.
    #[serde(default = "default_max_leaves_per_request")]
    pub max_leaves_per_request: usize,
}

fn default_chain_id() -> u64 {
    1
}
fn default_trust_domain() -> String {
    "timestamp".to_string()
}
fn default_dns() -> String {
    "timestamp.inblock.io".to_string()
}
fn default_ip() -> String {
    "139.59.144.60".to_string()
}
fn default_challenge_ttl() -> u64 {
    300
}
fn default_session_ttl() -> u64 {
    3600
}
fn default_storage_path() -> PathBuf {
    PathBuf::from("/var/lib/aqua-timestamp/state")
}
fn default_epoch_duration() -> u64 {
    600
}
fn default_max_leaves_per_request() -> usize {
    10_000
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            chain_id: default_chain_id(),
            trust_domain: default_trust_domain(),
            dns: default_dns(),
            ip: default_ip(),
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            challenge_ttl_secs: default_challenge_ttl(),
            session_ttl_secs: default_session_ttl(),
            allowed_dids: Vec::new(),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            path: default_storage_path(),
        }
    }
}

impl Default for EpochConfig {
    fn default() -> Self {
        Self {
            duration_secs: default_epoch_duration(),
            max_leaves_per_request: default_max_leaves_per_request(),
        }
    }
}

pub fn load(path: &Path) -> Result<Config> {
    let text = std::fs::read_to_string(path)?;
    let cfg: Config = toml::from_str(&text)?;
    Ok(cfg)
}
