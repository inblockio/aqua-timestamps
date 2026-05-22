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
    /// Legacy M3 `[anchor]` block. Retained so an M3 config still loads
    /// after the M4 upgrade without manual editing; the only field here
    /// is `evm_network`, which the resolver below promotes into the new
    /// `[anchors.evm]` shape if `[anchors.evm].network_label` is absent.
    /// Operators should migrate to `[anchors.evm]` at their next config
    /// edit; the legacy block will be removed at M6.
    #[serde(default, alias = "anchor")]
    pub anchor_legacy: AnchorConfig,
    /// M4+ anchors block. Defaults pick up Sepolia / live provider on,
    /// so an M3 config that doesn't mention `[anchors]` will start
    /// anchoring on Sepolia immediately after upgrade. Operators who
    /// don't want this (e.g. local dev without faucet ETH) should set
    /// `[anchors.evm].enabled = false`.
    #[serde(default)]
    pub anchors: AnchorsConfig,
    /// Adaptive publication rate based on wallet balance and gas cost.
    /// When enabled, replaces the fixed-interval sealer with one that
    /// adjusts epoch frequency via the bonding curve
    /// `r = 1 - exp(-B / (g * n_half))`.
    #[serde(default)]
    pub bonding_curve: BondingCurveConfig,
    /// Leaderboard / balance-tracking configuration.
    #[serde(default)]
    pub leaderboard: LeaderboardConfig,
}

impl Config {
    /// Resolve the effective `[anchors.evm]` for this config.
    ///
    /// Currently the only legacy-promotion rule is: if the deprecated
    /// `[anchor].evm_network` is present and `[anchors.evm].network_label`
    /// is still at its default, use the legacy value as the network
    /// label. This keeps existing M3 configs that say
    /// `[anchor]\nevm_network = "sepolia"` semantically equivalent to
    /// the new shape without an explicit edit.
    pub fn effective_evm_anchor(&self) -> EvmAnchorConfig {
        let mut evm = self.anchors.evm.clone();
        // Only inherit when the legacy value diverges from the modern
        // default; this avoids "promoting" the implicit default Sepolia.
        if self.anchor_legacy.evm_network != default_evm_network()
            && evm.network_label == default_evm_network()
        {
            evm.network_label = self.anchor_legacy.evm_network.clone();
        }
        evm
    }

    /// Derive a numeric chain id from the `[anchors.evm].chain` string.
    /// Used by the leaderboard module to query on-chain balances on the
    /// same chain the service is anchoring to.
    pub fn leaderboard_chain_id(&self) -> u64 {
        match self.anchors.evm.chain.as_str() {
            "mainnet" => 1,
            "sepolia" => 11155111,
            "holesky" => 17000,
            other if other.starts_with("custom:") => {
                other["custom:".len()..].parse().unwrap_or(11155111)
            }
            _ => 11155111,
        }
    }
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

/// Legacy M3 `[anchor]` block. Replaced by `[anchors.evm]` at M4 but kept
/// for one milestone so existing deploys load without manual editing.
#[derive(Debug, Deserialize, Clone)]
pub struct AnchorConfig {
    /// The `network` field embedded in EVM timestamp witness payloads.
    /// Defaults to `"sepolia"` so the M3 stub matches the M4 target chain.
    #[serde(default = "default_evm_network")]
    pub evm_network: String,
}

fn default_evm_network() -> String {
    "sepolia".to_string()
}

impl Default for AnchorConfig {
    fn default() -> Self {
        Self {
            evm_network: default_evm_network(),
        }
    }
}

/// New-shape anchors block. One sub-table per method.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct AnchorsConfig {
    #[serde(default)]
    pub evm: EvmAnchorConfig,
    #[serde(default)]
    pub qtsa: QtsaAnchorConfig,
}

/// `[anchors.evm]`. Every field has a default so an M3 config without the
/// block still loads and picks up live Sepolia anchoring automatically.
#[derive(Debug, Deserialize, Clone)]
pub struct EvmAnchorConfig {
    /// Live anchor toggle. `true` (default) constructs a
    /// `CliEthTimestamper` at boot and submits one tx per non-empty
    /// epoch. `false` keeps the M3 stub behaviour: witnesses are minted
    /// with zero `transaction_hash` / zero contract address.
    #[serde(default = "default_evm_enabled")]
    pub enabled: bool,

    /// JSON-RPC URL the live provider talks to. Public, free Sepolia
    /// endpoints (no API key) are fine for M4; production deployments
    /// should switch to a paid endpoint at M6 for SLA.
    #[serde(default = "default_evm_rpc_url")]
    pub rpc_url: String,

    /// One of `mainnet`, `sepolia`, `holesky`, or `custom:<chain_id>`.
    /// Parsed via [`Self::evm_chain`] into the SDK's `EvmChain`.
    #[serde(default = "default_evm_chain")]
    pub chain: String,

    /// Free-form network label the witness payload's `network` field
    /// carries. Usually the same string as `chain`. Kept separate so a
    /// custom chain id (`chain = "custom:12345"`) can still surface a
    /// human-readable network name in witnesses.
    #[serde(default = "default_evm_network")]
    pub network_label: String,
}

fn default_evm_enabled() -> bool {
    true
}
fn default_evm_rpc_url() -> String {
    "https://ethereum-sepolia-rpc.publicnode.com".to_string()
}
fn default_evm_chain() -> String {
    "sepolia".to_string()
}

impl Default for EvmAnchorConfig {
    fn default() -> Self {
        Self {
            enabled: default_evm_enabled(),
            rpc_url: default_evm_rpc_url(),
            chain: default_evm_chain(),
            network_label: default_evm_network(),
        }
    }
}

/// `[anchors.qtsa]`. Defaults to the operator's Sectigo-qualified
/// endpoint with the 16-second throttle the SDK's docstring recommends
/// for that provider. A free standard TSA (`http://timestamp.digicert.com`,
/// `min_request_interval_secs = 0`) is the simplest M5 alternative.
#[derive(Debug, Deserialize, Clone)]
pub struct QtsaAnchorConfig {
    /// Live anchor toggle. `true` (default) constructs an
    /// [`aqua_rs_sdk::web::tsa::TsaTimestamper`] at boot. `false` keeps
    /// the M3/M4 stub: qTSA witnesses are minted with zero
    /// `transaction_hash` and `tsa_provider = "stub"`.
    #[serde(default = "default_qtsa_enabled")]
    pub enabled: bool,

    /// RFC 3161 TSA endpoint. Eg.
    /// `http://timestamp.sectigo.com/qualified` (eIDAS-qualified) or
    /// `http://timestamp.digicert.com` (standard, no auth).
    #[serde(default = "default_qtsa_url")]
    pub url: String,

    /// Minimum spacing between requests, in seconds. The SDK's docstring
    /// recommends 16 for Sectigo qualified (and any eIDAS-qualified
    /// endpoint with similar rate-limit guidance). `0` disables the
    /// throttle entirely (suitable for free standard TSAs like DigiCert).
    #[serde(default = "default_qtsa_min_request_interval_secs")]
    pub min_request_interval_secs: u64,

    /// Free-form network label the witness payload's `network` field
    /// carries. Sectigo-qualified deployments use
    /// `"sectigo-qualified-tsa"`; a free standard TSA might pick `"tsa"`.
    #[serde(default = "default_qtsa_network_label")]
    pub network_label: String,
}

fn default_qtsa_enabled() -> bool {
    true
}
fn default_qtsa_url() -> String {
    "http://timestamp.sectigo.com/qualified".to_string()
}
fn default_qtsa_min_request_interval_secs() -> u64 {
    16
}
fn default_qtsa_network_label() -> String {
    "sectigo-qualified-tsa".to_string()
}

impl Default for QtsaAnchorConfig {
    fn default() -> Self {
        Self {
            enabled: default_qtsa_enabled(),
            url: default_qtsa_url(),
            min_request_interval_secs: default_qtsa_min_request_interval_secs(),
            network_label: default_qtsa_network_label(),
        }
    }
}

impl QtsaAnchorConfig {
    pub fn throttle(&self) -> Option<std::time::Duration> {
        if self.min_request_interval_secs == 0 {
            None
        } else {
            Some(std::time::Duration::from_secs(
                self.min_request_interval_secs,
            ))
        }
    }
}

/// `[bonding_curve]`. Adaptive epoch frequency driven by wallet balance
/// and gas cost. Disabled by default; when enabled the fixed-interval
/// sealer is replaced with one that polls balance/gas and computes the
/// publication interval via `r = 1 - exp(-B / (g * n_half))`.
#[derive(Debug, Deserialize, Clone)]
pub struct BondingCurveConfig {
    /// Master toggle. `false` (default) keeps the fixed-interval sealer.
    #[serde(default)]
    pub enabled: bool,

    /// Half-activation threshold: the number of affordable transactions
    /// at which the publication rate reaches ~63%. Also serves as the
    /// minimum guaranteed runway in blocks.
    #[serde(default = "default_bonding_n_half")]
    pub n_half: u64,

    /// How often (seconds) to re-query balance and gas price. Defaults
    /// to 12 (one Ethereum block).
    #[serde(default = "default_bonding_poll_interval")]
    pub poll_interval_secs: u64,

    /// Safety margin: skip publishing when balance < multiplier * gas_cost.
    #[serde(default = "default_bonding_min_balance_multiplier")]
    pub min_balance_multiplier: u64,
}

fn default_bonding_n_half() -> u64 {
    7200
}
fn default_bonding_poll_interval() -> u64 {
    12
}
fn default_bonding_min_balance_multiplier() -> u64 {
    2
}

impl Default for BondingCurveConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            n_half: default_bonding_n_half(),
            poll_interval_secs: default_bonding_poll_interval(),
            min_balance_multiplier: default_bonding_min_balance_multiplier(),
        }
    }
}

/// `[leaderboard]`. Controls the balance-tracking leaderboard that
/// monitors the service wallet's on-chain balance and manages the
/// contributor pool.
#[derive(Debug, Deserialize, Clone)]
pub struct LeaderboardConfig {
    /// Enable or disable the leaderboard subsystem.
    #[serde(default = "default_leaderboard_enabled")]
    pub enabled: bool,

    /// How often (in seconds) to poll the RPC for a fresh balance.
    #[serde(default = "default_leaderboard_poll_interval_secs")]
    pub poll_interval_secs: u64,

    /// JSON-RPC URL used for balance queries. Defaults to the same
    /// public Sepolia endpoint the EVM anchor uses.
    #[serde(default = "default_leaderboard_rpc_url")]
    pub rpc_url: String,

    /// Maximum number of wallets tracked in the contributor pool.
    #[serde(default = "default_leaderboard_max_pool_size")]
    pub max_pool_size: usize,

    /// The wallet address whose balance is monitored.
    #[serde(default = "default_leaderboard_wallet_address")]
    pub wallet_address: String,
}

fn default_leaderboard_enabled() -> bool {
    true
}
fn default_leaderboard_poll_interval_secs() -> u64 {
    15
}
fn default_leaderboard_rpc_url() -> String {
    default_evm_rpc_url()
}
fn default_leaderboard_max_pool_size() -> usize {
    500
}
fn default_leaderboard_wallet_address() -> String {
    "0x55Fcf9F8C1287cB462aa3c1C97E2298d221c634f".to_string()
}

impl Default for LeaderboardConfig {
    fn default() -> Self {
        Self {
            enabled: default_leaderboard_enabled(),
            poll_interval_secs: default_leaderboard_poll_interval_secs(),
            rpc_url: default_leaderboard_rpc_url(),
            max_pool_size: default_leaderboard_max_pool_size(),
            wallet_address: default_leaderboard_wallet_address(),
        }
    }
}

impl EvmAnchorConfig {
    /// Parse the `chain` string into the SDK's `EvmChain`.
    ///
    /// Recognised forms:
    /// - `"mainnet"` / `"sepolia"` / `"holesky"`
    /// - `"custom:<chain_id>"` (`chain_id` parsed as `u64`)
    ///
    /// Anything else is rejected at boot so a typo in the deploy config
    /// surfaces immediately rather than silently picking the default.
    pub fn evm_chain(&self) -> Result<aqua_rs_sdk::primitives::EvmChain> {
        use aqua_rs_sdk::primitives::EvmChain;
        match self.chain.as_str() {
            "mainnet" => Ok(EvmChain::Mainnet),
            "sepolia" => Ok(EvmChain::Sepolia),
            "holesky" => Ok(EvmChain::Holesky),
            other if other.starts_with("custom:") => {
                let id_str = &other["custom:".len()..];
                let chain_id: u64 = id_str.parse().map_err(|e| {
                    anyhow::anyhow!("invalid anchors.evm.chain={other:?}: {e}")
                })?;
                Ok(EvmChain::Custom {
                    chain_id,
                    name: None,
                })
            }
            other => Err(anyhow::anyhow!(
                "unknown anchors.evm.chain={other:?}: expected mainnet | sepolia | holesky | custom:<chain_id>"
            )),
        }
    }
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
    "openwitness.org".to_string()
}
fn default_ip() -> String {
    "142.93.168.4".to_string()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaderboard_defaults_without_section() {
        let cfg: Config = toml::from_str("[server]\nlisten = \"0.0.0.0:3000\"").unwrap();
        assert!(cfg.leaderboard.enabled);
        assert_eq!(cfg.leaderboard.poll_interval_secs, 15);
        assert_eq!(cfg.leaderboard.max_pool_size, 500);
    }

    #[test]
    fn leaderboard_config_with_section() {
        let toml_str = r#"
            [server]
            listen = "0.0.0.0:3000"
            [leaderboard]
            enabled = false
            poll_interval_secs = 30
            max_pool_size = 100
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(!cfg.leaderboard.enabled);
        assert_eq!(cfg.leaderboard.poll_interval_secs, 30);
        assert_eq!(cfg.leaderboard.max_pool_size, 100);
    }

    #[test]
    fn leaderboard_chain_id_derived() {
        let cfg: Config = toml::from_str("[server]\nlisten = \"0.0.0.0:3000\"").unwrap();
        // default chain is "sepolia"
        assert_eq!(cfg.leaderboard_chain_id(), 11155111);
    }
}
