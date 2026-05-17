//! Service identity: load the mnemonic, derive the secp256k1 key, build the
//! signed `service_claim_server` Aqua-tree, and assemble the
//! `/.well-known/aqua-identity` response.
//!
//! The mnemonic stays in process memory for the lifetime of the binary and
//! is never logged, written to a file, or returned in any response. Only
//! the derived address and DID are surfaced.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use aqua_rs_sdk::{
    core::{object::create_object_util, signature::sign_aqua_tree_with_signer},
    primitives::{get_wallet, Method},
    schema::template::BuiltInTemplate,
    schema::{templates::ServiceClaimServer, tree::Tree, AquaTreeWrapper},
    Secp256k1Signer,
};
use serde::Serialize;
use serde_json::{json, Value};

use crate::config::IdentityConfig;

/// The environment variable the operator sets on the host. The keyring
/// command for retrieval is documented in `CLAUDE.md`.
pub const MNEMONIC_ENV: &str = "AQUA_TIMESTAMP_ANCHOR_MNEMONIC";

/// Loaded service identity.
///
/// `private_key` is held inside an [`Arc`] purely so the wallet can be
/// shared between the identity-tree builder (constructed at startup) and
/// any future signers without copying the bytes around. The bytes are
/// dropped when the `Arc` drops; there is no fingerprinted copy elsewhere.
#[derive(Clone)]
pub struct ServiceIdentity {
    pub address_eip55: String,
    pub server_did: String,
    pub chain_id: u64,
    pub trust_domain: String,
    pub dns: String,
    pub ip: String,
    pub private_key: Arc<Vec<u8>>,
    /// BIP39 mnemonic the service key was derived from. Held in process
    /// memory so the M4 EVM anchor (`CliEthTimestamper`) can be
    /// constructed without re-reading the env var. Never logged, never
    /// surfaced over HTTP, dropped when the `Arc` drops.
    pub mnemonic: Arc<String>,
}

impl std::fmt::Debug for ServiceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceIdentity")
            .field("address_eip55", &self.address_eip55)
            .field("server_did", &self.server_did)
            .field("chain_id", &self.chain_id)
            .field("trust_domain", &self.trust_domain)
            .field("dns", &self.dns)
            .field("ip", &self.ip)
            .field("private_key", &"<redacted>")
            .field("mnemonic", &"<redacted>")
            .finish()
    }
}

impl ServiceIdentity {
    /// Load from the `AQUA_TIMESTAMP_ANCHOR_MNEMONIC` env var.
    ///
    /// Refuses to start when the env var is unset or empty.
    pub async fn from_env(cfg: &IdentityConfig) -> Result<Self> {
        let mnemonic = std::env::var(MNEMONIC_ENV)
            .map_err(|_| anyhow!("{MNEMONIC_ENV} is not set; refusing to start"))?;
        if mnemonic.trim().is_empty() {
            return Err(anyhow!("{MNEMONIC_ENV} is empty; refusing to start"));
        }
        Self::from_mnemonic(&mnemonic, cfg).await
    }

    /// Construct an identity from a known mnemonic. Intended for tests.
    pub async fn from_mnemonic(mnemonic: &str, cfg: &IdentityConfig) -> Result<Self> {
        let (_address, address_eip55, private_key_hex) = get_wallet(mnemonic)
            .await
            .map_err(|e| anyhow!("failed to derive secp256k1 wallet: {e}"))?;

        let pk_bytes = hex::decode(private_key_hex.trim_start_matches("0x"))
            .context("alloy returned a non-hex private key string")?;

        let server_did = format!(
            "did:pkh:eip155:{chain_id}:{addr}",
            chain_id = cfg.chain_id,
            addr = address_eip55,
        );

        Ok(Self {
            address_eip55,
            server_did,
            chain_id: cfg.chain_id,
            trust_domain: cfg.trust_domain.clone(),
            dns: cfg.dns.clone(),
            ip: cfg.ip.clone(),
            private_key: Arc::new(pk_bytes),
            mnemonic: Arc::new(mnemonic.trim().to_string()),
        })
    }
}

/// Knobs the snapshot test uses to make the identity tree deterministic.
///
/// In production both fields are `None` and the SDK uses wall-clock time
/// plus a fresh random nonce. The test sets `valid_from` to a fixed value
/// so the payload bytes are stable; the random nonces and SDK-internal
/// timestamps are normalised by the test rather than threaded through the
/// SDK (which would require modifying the read-only sister crate).
#[derive(Debug, Clone, Default)]
pub struct IdentityClaimOverrides {
    pub valid_from: Option<u64>,
}

/// Build the signed `service_claim_server` Aqua-tree for this identity.
///
/// Layout (mirroring `aquafire.inblock.io/.well-known/aqua-identity`):
///
/// 1. genesis `Anchor` with `structural_links = [ServiceClaimServer template hash]`,
/// 2. `Object` whose payload is the [`ServiceClaimServer`] claim,
/// 3. `Signature` over the object hash, signed EIP-191 by the service key.
///
/// Method is `Method::Scalar` for parity with the aquafire reference.
pub async fn build_identity_tree(
    identity: &ServiceIdentity,
    overrides: &IdentityClaimOverrides,
) -> Result<Tree> {
    let valid_from = overrides.valid_from.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    });

    let claim = ServiceClaimServer {
        signer_did: identity.server_did.clone(),
        service_kind: "server".to_string(),
        valid_from,
        valid_until: None,
        dns: identity.dns.clone(),
        ip: identity.ip.clone(),
        deploy_version: option_env!("CARGO_PKG_VERSION").map(|v| v.to_string()),
    };
    claim
        .validate()
        .map_err(|e| anyhow!("invalid service_claim_server payload: {e}"))?;

    let template_link =
        aqua_rs_sdk::primitives::RevisionLink::from_bytes(ServiceClaimServer::TEMPLATE_LINK);
    let payload: Value =
        serde_json::to_value(&claim).context("failed to serialise service_claim_server payload")?;

    let tree = create_object_util(template_link, None, payload, Method::Scalar)
        .map_err(|e| anyhow!("failed to build identity object: {e:?}"))?;

    let signer = Secp256k1Signer::new(identity.private_key.as_ref().clone());
    let wrapper = AquaTreeWrapper::new(tree, None, None);
    let op = sign_aqua_tree_with_signer(&wrapper, &signer, Method::Scalar, None)
        .await
        .map_err(|e| anyhow!("failed to sign identity tree: {e:?}"))?;
    Ok(op.aqua_tree)
}

/// Top-level shape of `/.well-known/aqua-identity`. Field order matches
/// the aquafire reference exactly so the JSON is byte-stable.
#[derive(Debug, Serialize)]
pub struct IdentityResponse {
    pub protocol: &'static str,
    pub version: &'static str,
    pub server_did: String,
    pub ethereum_address: String,
    pub trust_level: u8,
    pub trust_domain: String,
    pub supported_claims: Vec<String>,
    pub auth_method: &'static str,
    pub endpoints: Endpoints,
    pub identity_claim: Value,
}

#[derive(Debug, Serialize)]
pub struct Endpoints {
    pub auth: String,
    pub trees: String,
    pub submit: String,
    pub verify: String,
    /// Browser-friendly agent integration guide. Mirrors the structure
    /// of the well-known skills below for humans.
    pub docs: String,
    /// Machine-readable main agent skill in the
    /// `~/.claude/skills/<name>/SKILL.md` shape. Lets a remote agent
    /// self-bootstrap without out-of-band documentation. Under
    /// `/.well-known/` so it lives in the same well-known namespace as
    /// the identity claim above.
    pub well_known_skill: String,
    /// SIWE / CAIP-122 authentication deep-dive (sub-article). Linked
    /// from the main skill; same well-known convention.
    pub well_known_skill_auth: String,
}

impl IdentityResponse {
    pub fn new(identity: &ServiceIdentity, identity_claim: Value) -> Self {
        Self {
            protocol: aqua_timestamp_core::version::PROTOCOL,
            version: aqua_timestamp_core::version::PROTOCOL_VERSION,
            server_did: identity.server_did.clone(),
            ethereum_address: format!("0x{}", identity.address_eip55.trim_start_matches("0x")),
            trust_level: 2,
            trust_domain: identity.trust_domain.clone(),
            supported_claims: vec!["timestamp_anchor".to_string()],
            auth_method: "siwe",
            endpoints: Endpoints {
                auth: "/auth".to_string(),
                trees: "/trees".to_string(),
                submit: "/v1/leaves".to_string(),
                verify: "/api/explorer/trees/{tip}/verify".to_string(),
                docs: "/docs".to_string(),
                well_known_skill: "/.well-known/aqua-skill.md".to_string(),
                well_known_skill_auth: "/.well-known/aqua-skill-auth.md".to_string(),
            },
            identity_claim,
        }
    }
}

/// Helper used by both the live handler and the snapshot test: produce the
/// full JSON document, given a pre-built tree.
pub fn build_response(identity: &ServiceIdentity, tree: &Tree) -> Result<Value> {
    let tree_json = serde_json::to_value(tree).context("serialise identity tree")?;
    let response = IdentityResponse::new(identity, tree_json);
    serde_json::to_value(&response).context("serialise identity response")
}

/// Walk the `revisions` map and return hashes in topological order:
/// genesis (no `previous_revision`) first, then chained successors. Falls
/// back to BTreeMap iteration order for any revisions that can't be placed
/// (orphan / cycle), but in a well-formed identity tree every revision is
/// reachable from genesis.
fn topological_revision_order(map: &serde_json::Map<String, Value>) -> Vec<String> {
    let mut order: Vec<String> = Vec::new();
    let mut current: Option<String> = None;
    // Find the genesis revision: no `previous_revision` field (the SDK
    // omits it entirely on genesis anchors / objects).
    for (hash, rev) in map.iter() {
        if rev
            .get("previous_revision")
            .map(|v| v.is_null())
            .unwrap_or(true)
        {
            current = Some(hash.clone());
            break;
        }
    }
    while let Some(h) = current.take() {
        order.push(h.clone());
        for (next_hash, rev) in map.iter() {
            if rev.get("previous_revision").and_then(Value::as_str) == Some(h.as_str()) {
                current = Some(next_hash.clone());
                break;
            }
        }
    }
    // Append any orphans deterministically so the normaliser is total.
    for (hash, _) in map.iter() {
        if !order.contains(hash) {
            order.push(hash.clone());
        }
    }
    order
}

/// Returns a JSON value with all timestamps, nonces, signature bytes and
/// version-specific payload fields replaced by stable sentinels. Intended
/// for golden snapshot tests; exposed unconditionally so integration tests
/// in `tests/` can use it without an extra feature flag.
pub fn normalise_for_snapshot(mut value: Value) -> Value {
    fn walk(v: &mut Value) {
        match v {
            Value::Object(map) => {
                for (k, child) in map.iter_mut() {
                    match k.as_str() {
                        "nonce" => *child = json!("<NONCE>"),
                        "local_timestamp" => *child = json!(0u64),
                        "valid_from" => *child = json!(0u64),
                        "deploy_version" => *child = json!("<VERSION>"),
                        "signature" => {
                            // For the signature inner object, only blank the
                            // hex blob; leave signature_type / public_id
                            // intact for shape verification.
                            match child {
                                Value::String(_) => *child = json!("0x<SIG>"),
                                Value::Object(inner) => {
                                    if let Some(sig) = inner.get_mut("signature") {
                                        *sig = json!("0x<SIG>");
                                    }
                                    walk(child);
                                }
                                _ => walk(child),
                            }
                        }
                        _ => walk(child),
                    }
                }
            }
            Value::Array(items) => {
                for item in items.iter_mut() {
                    walk(item);
                }
            }
            _ => {}
        }
    }
    walk(&mut value);
    // The signed tree's three revision hashes also depend on the random
    // nonces and timestamps above, so collapse them to their *positions*
    // (anchor = 0, object = 1, signature = 2) inside `revisions` and
    // `file_index`. Use topological order (genesis → tip), not BTreeMap
    // key order which is hash-dependent and therefore not deterministic.
    if let Some(claim) = value.get_mut("identity_claim") {
        if let Some(claim_obj) = claim.as_object_mut() {
            // Capture hash→position mapping from `revisions` so we can
            // remap `file_index` (same keys) consistently.
            let mut hash_order: Vec<String> = Vec::new();
            if let Some(revisions) = claim_obj.get("revisions").and_then(Value::as_object) {
                hash_order = topological_revision_order(revisions);
            }
            for key in ["revisions", "file_index"] {
                if let Some(map_value) = claim_obj.get_mut(key) {
                    if let Some(map) = map_value.as_object() {
                        let mut new_map = serde_json::Map::new();
                        for (idx, hash) in hash_order.iter().enumerate() {
                            if let Some(v) = map.get(hash) {
                                new_map.insert(format!("REV_{idx}"), v.clone());
                            }
                        }
                        *map_value = Value::Object(new_map);
                    }
                }
            }
            // Also blank any inter-revision references that embed a hash.
            if let Some(revisions) = claim_obj.get_mut("revisions") {
                if let Some(map) = revisions.as_object_mut() {
                    for (_, rev) in map.iter_mut() {
                        if let Some(obj) = rev.as_object_mut() {
                            for k in [
                                "previous_revision",
                                "revision_type",
                                "structural_links",
                                "signer",
                            ] {
                                if let Some(slot) = obj.get_mut(k) {
                                    match slot {
                                        Value::String(_) => {
                                            *slot = json!(format!("<{}>", k.to_uppercase()))
                                        }
                                        Value::Array(arr) => {
                                            for item in arr.iter_mut() {
                                                *item = json!(format!("<{}>", k.to_uppercase()));
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            if let Some(sig) = obj.get_mut("signature") {
                                if let Some(sig_obj) = sig.as_object_mut() {
                                    if let Some(slot) =
                                        sig_obj.get_mut("signature_public_identifier")
                                    {
                                        *slot = json!("<SIGNER_ADDR>");
                                    }
                                }
                            }
                            if let Some(payloads) = obj.get_mut("payloads") {
                                if let Some(p_obj) = payloads.as_object_mut() {
                                    if let Some(slot) = p_obj.get_mut("signer_did") {
                                        *slot = json!("<SIGNER_DID>");
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if let Some(file_index) = claim_obj.get_mut("file_index") {
                if let Some(map) = file_index.as_object_mut() {
                    for (_, v) in map.iter_mut() {
                        *v = json!("<NAME>");
                    }
                }
            }
        }
    }
    // Top-level identity fields also depend on the address; blank them so
    // the golden is portable across different test mnemonics.
    for k in ["server_did", "ethereum_address"] {
        if let Some(slot) = value.get_mut(k) {
            *slot = json!(format!("<{}>", k.to_uppercase()));
        }
    }
    value
}
