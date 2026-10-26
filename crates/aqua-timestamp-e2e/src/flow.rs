//! End-to-end client flow for the aqua-timestamp aggregator.
//!
//! SIWE sign-in, submit the tip of a client tree, wait for the seal, fetch BOTH witnesses
//! (EVM and qTSA) and have the SDK verifier judge the client tree with them merged in
//! (see [`crate::witness`]). The flow takes the base URL as a parameter; the `live` subcommand
//! passes a deployed one (required, never defaulted), `selfcheck` an in-process server bound to
//! `http://127.0.0.1:<port>`.
//!
//! Two seams keep the flow testable without burning Sepolia time or epoch clock seconds:
//!
//! * [`SealTrigger`] lets a `selfcheck` caller drive the in-process sealer between submission
//!   and polling. The `live` caller passes [`SealTrigger::None`] and waits for the interval timer.
//! * [`FlowOptions`] carries the waits (seal, witnesses) and where the reader's hosts come from.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use aqua_rs_sdk::Secp256k1Signer;
use rand::RngCore;
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};

use crate::witness::{
    fetch_witness, new_client_tree, verify_with_sdk, MethodVerdict, ReaderHosts, WitnessMethod,
};

/// Steps print one line on success so a transcript looks like a checklist.
/// The closure receives `(step_number, label)`.
pub type StepLogger<'a> = &'a dyn Fn(usize, &str);

/// Future returned by a [`SealTrigger::Driver`] callback. Boxed so the
/// closure can hold arbitrary state (e.g. a `tokio::sync::mpsc::Sender`).
pub type SealTriggerFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Optional hook to nudge the in-process sealer in selfcheck mode.
pub enum SealTrigger {
    /// Live deployment: no test hook, the production interval timer seals.
    None,
    /// In-process server: invoke this to deliver a seal tick once the test
    /// submission has been accepted.
    Driver(Box<dyn Fn() -> SealTriggerFuture + Send + Sync>),
}

/// Cap on how long we will poll `/v1/schedule` before declaring failure.
///
/// `live_roundtrip` against a 600s production epoch picks
/// `PollBudget::from_epoch_close(close_at, now, 30)`; selfcheck (where the
/// seal is driven manually) picks a small fixed budget.
#[derive(Debug, Clone)]
pub struct PollBudget {
    pub deadline: Instant,
    pub interval: Duration,
}

impl PollBudget {
    /// Per success-criteria §M-E2E: failure threshold is `2 *
    /// (epoch_closes_at - now) + grace_secs`. Kept on the public API even
    /// though the `live` subcommand presently uses a wall-clock cap; a
    /// future change that switches to dynamic budgeting can pick this up
    /// without touching the flow itself.
    #[allow(dead_code)]
    pub fn from_epoch_close(epoch_closes_at: u64, now_secs: u64, grace_secs: u64) -> Self {
        let span = epoch_closes_at.saturating_sub(now_secs);
        let max_wait = 2 * span + grace_secs;
        Self {
            deadline: Instant::now() + Duration::from_secs(max_wait.max(60)),
            interval: Duration::from_secs(5),
        }
    }

    pub fn fast(seconds: u64) -> Self {
        Self {
            deadline: Instant::now() + Duration::from_secs(seconds.max(2)),
            interval: Duration::from_millis(50),
        }
    }
}

/// Outcome a successful end-to-end run produces. The `live` subcommand prints these; the
/// selfcheck test asserts on them.
#[derive(Debug)]
pub struct E2eOutcome {
    pub base_url: String,
    pub server_did: String,
    pub client_did: String,
    pub leaf_hex: String,
    pub epoch_id: u64,
    /// One SDK verdict per anchor method (EVM, then qTSA).
    pub witnesses: Vec<MethodVerdict>,
}

/// Which DID method the test client is using. The three values match the
/// three CAIP-122 namespaces that `aqua-rs-auth` verifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureMethod {
    /// `did:pkh:eip155:1:0x{40 hex}`, EIP-191 personal_sign over keccak256.
    Secp256k1Eip191,
    /// `did:pkh:ed25519:0x{64 hex}`, Ed25519 sign over the raw message bytes.
    Ed25519,
    /// `did:pkh:p256:0x{66 hex compressed}`, P-256 ECDSA over the raw message
    /// bytes. Sent as the 64-byte fixed-size encoding (the `r256` verifier
    /// accepts DER too, but fixed-size is what `aqua-rs-auth`'s tests use).
    P256,
}

impl SignatureMethod {
    pub fn label(self) -> &'static str {
        match self {
            Self::Secp256k1Eip191 => "secp256k1+eip191",
            Self::Ed25519 => "ed25519",
            Self::P256 => "p256",
        }
    }
}

/// Test client material. The private key bytes live behind an enum so the
/// flow logic stays the same shape across all three DID methods; only
/// [`ClientKey::sign_challenge`] dispatches.
pub struct ClientKey {
    pub did: String,
    /// Display string. For secp256k1 this is the EIP-55 address; for the
    /// other methods it's the raw pubkey hex (still useful in the log line).
    pub display_identifier: String,
    pub method: SignatureMethod,
    secret: KeyMaterial,
}

/// Held internally so callers cannot accidentally serialise it.
enum KeyMaterial {
    Secp256k1 {
        private_key: [u8; 32],
    },
    Ed25519 {
        signing_key: ed25519_dalek::SigningKey,
    },
    P256 {
        signing_key: p256::ecdsa::SigningKey,
    },
}

impl ClientKey {
    /// A secp256k1 client from a raw 32-byte private key (the standing identity's key file).
    pub fn from_secp256k1_bytes(private_key: [u8; 32]) -> Result<Self> {
        k256::ecdsa::SigningKey::from_slice(&private_key)
            .map_err(|e| anyhow!("invalid secp256k1 key: {e}"))?;
        let signer = Secp256k1Signer::new(private_key.to_vec());
        let (did, addr) = signer
            .derive_did_pkh()
            .map_err(|e| anyhow!("derive_did_pkh: {e}"))?;
        Ok(Self {
            did,
            display_identifier: eip55(&addr),
            method: SignatureMethod::Secp256k1Eip191,
            secret: KeyMaterial::Secp256k1 { private_key },
        })
    }

    /// Generate a fresh random client for the requested method. In-process runs only (the
    /// foreign-DID negative and the `selfcheck-all` ed25519 / p256 clients): a remote run uses
    /// the standing identity and creates no random DID.
    pub fn random(method: SignatureMethod) -> Result<Self> {
        match method {
            SignatureMethod::Secp256k1Eip191 => {
                let mut sk_bytes = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut sk_bytes);
                let _ = k256::ecdsa::SigningKey::from_slice(&sk_bytes)
                    .map_err(|e| anyhow!("random k256 signing key: {e}"))?;
                let signer = Secp256k1Signer::new(sk_bytes.to_vec());
                let (did, addr) = signer
                    .derive_did_pkh()
                    .map_err(|e| anyhow!("derive_did_pkh: {e}"))?;
                Ok(Self {
                    did,
                    display_identifier: eip55(&addr),
                    method,
                    secret: KeyMaterial::Secp256k1 {
                        private_key: sk_bytes,
                    },
                })
            }
            SignatureMethod::Ed25519 => {
                use ed25519_dalek::SigningKey;
                let mut rng = rand::rngs::OsRng;
                let signing_key = SigningKey::generate(&mut rng);
                let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
                let did = format!("did:pkh:ed25519:0x{pubkey_hex}");
                Ok(Self {
                    did: did.clone(),
                    display_identifier: format!("0x{pubkey_hex}"),
                    method,
                    secret: KeyMaterial::Ed25519 { signing_key },
                })
            }
            SignatureMethod::P256 => {
                use p256::ecdsa::SigningKey;
                let signing_key = SigningKey::random(&mut rand::rngs::OsRng);
                let compressed = signing_key.verifying_key().to_encoded_point(true);
                let pubkey_hex = hex::encode(compressed.as_bytes());
                let did = format!("did:pkh:p256:0x{pubkey_hex}");
                Ok(Self {
                    did,
                    display_identifier: format!("0x{pubkey_hex}"),
                    method,
                    secret: KeyMaterial::P256 { signing_key },
                })
            }
        }
    }

    /// Produce the `0x`-prefixed hex signature the server expects in the
    /// `POST /auth/session` body. The byte format matches what
    /// `aqua-rs-auth`'s verifier for this DID method consumes.
    pub fn sign_challenge(&self, message: &str) -> Result<String> {
        match &self.secret {
            KeyMaterial::Secp256k1 { private_key } => {
                let bytes = eip191_personal_sign(message, private_key)?;
                Ok(format!("0x{}", hex::encode(bytes)))
            }
            KeyMaterial::Ed25519 { signing_key } => {
                use ed25519_dalek::Signer;
                let sig = signing_key.sign(message.as_bytes());
                Ok(format!("0x{}", hex::encode(sig.to_bytes())))
            }
            KeyMaterial::P256 { signing_key } => {
                use p256::ecdsa::{signature::Signer, Signature};
                let sig: Signature = signing_key.sign(message.as_bytes());
                Ok(format!("0x{}", hex::encode(sig.to_bytes())))
            }
        }
    }
}

/// EIP-191 personal_sign over keccak256(prefix || message). Returns the
/// raw 65-byte `r || s || v` blob (with `v = recovery_id + 27`).
fn eip191_personal_sign(message: &str, private_key: &[u8; 32]) -> Result<[u8; 65]> {
    use k256::ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, Signature, SigningKey};
    let signing_key = SigningKey::from_slice(private_key).context("k256 SigningKey")?;
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut h = Keccak256::new();
    h.update(prefix.as_bytes());
    h.update(message.as_bytes());
    let prehash: [u8; 32] = h.finalize().into();
    let (sig, rec_id): (Signature, RecoveryId) = signing_key
        .sign_prehash(&prehash)
        .map_err(|e| anyhow!("sign_prehash: {e}"))?;
    let mut bytes = [0u8; 65];
    bytes[..64].copy_from_slice(&sig.to_bytes());
    bytes[64] = u8::from(rec_id) + 27;
    Ok(bytes)
}

async fn http_get(client: &Client, url: &str, bearer: Option<&str>) -> Result<reqwest::Response> {
    let mut req = client.get(url);
    if let Some(t) = bearer {
        req = req.bearer_auth(t);
    }
    req.send().await.with_context(|| format!("GET {url}"))
}

async fn http_post(
    client: &Client,
    url: &str,
    bearer: Option<&str>,
    body: &Value,
) -> Result<reqwest::Response> {
    let mut req = client.post(url).json(body);
    if let Some(t) = bearer {
        req = req.bearer_auth(t);
    }
    req.send().await.with_context(|| format!("POST {url}"))
}

/// Walk the full SIWE handshake for `client` and return its Bearer token.
async fn mint_bearer(client: &Client, base_url: &str, key: &ClientKey) -> Result<String> {
    let challenge_url = format!("{base_url}/auth/challenge?did={}", key.did);
    let resp = http_get(client, &challenge_url, None).await?;
    if !resp.status().is_success() {
        bail!(
            "GET /auth/challenge: HTTP {} body={}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }
    let body: Value = resp.json().await.context("challenge json")?;
    let message = body
        .get("message")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("challenge response missing `message`"))?
        .to_string();
    let nonce = body
        .get("nonce")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("challenge response missing `nonce`"))?
        .to_string();

    let signature = key.sign_challenge(&message)?;
    let session_url = format!("{base_url}/auth/session");
    let payload = json!({ "did": key.did, "nonce": nonce, "signature": signature });
    let resp = http_post(client, &session_url, None, &payload).await?;
    if !resp.status().is_success() {
        bail!(
            "POST /auth/session: HTTP {} body={}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }
    let body: Value = resp.json().await.context("session json")?;
    body.get("token")
        .and_then(Value::as_str)
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("session response missing `token`"))
}

fn random_leaf() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("0x{}", hex::encode(bytes))
}

/// EIP-55 mixed-case checksum encoding of a 20-byte address.
fn eip55(addr: &[u8; 20]) -> String {
    let hex_addr = hex::encode(addr);
    let hash = Keccak256::digest(hex_addr.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in hex_addr.chars().enumerate() {
        let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
        out.push(if c.is_ascii_alphabetic() && nibble >= 8 {
            c.to_ascii_uppercase()
        } else {
            c
        });
    }
    out
}

/// Where the reader's external facts (chain, TSA trust) come from.
pub enum ReaderConfig {
    /// Real hosts: the EVM chain over RPC (`evm_rpc_url`, else the SDK host's own default for
    /// the witness' network) and the EU trust list for TSA tokens.
    Live { evm_rpc_url: Option<String> },
    /// Injected hosts: the in-process dry run, where the aggregator's own simulated chain and
    /// TSA are also the reader's hosts. Never used against a remote.
    Injected(ReaderHosts),
}

impl ReaderConfig {
    fn hosts(&self, evm_network: &str) -> Result<ReaderHosts> {
        match self {
            Self::Injected(h) => Ok(h.clone()),
            Self::Live { evm_rpc_url } => {
                let mut chain =
                    aqua_evm_provider::EthBlockchainHost::new(tokio::runtime::Handle::current());
                if let Some(url) = evm_rpc_url {
                    let chain_id =
                        aqua_rs_sdk::core::evm_anchor::evm_chain_id_for_network(evm_network)
                            .with_context(|| {
                                format!(
                                    "witness network {evm_network:?} is not one the SDK verifies"
                                )
                            })?;
                    chain = chain.with_endpoint(chain_id, url.clone());
                }
                Ok(ReaderHosts {
                    blockchain: Arc::new(chain),
                    web: Arc::new(aqua_tsa_provider::TsaWebHost::new()),
                    tsa_facts_expected: true,
                })
            }
        }
    }
}

/// Knobs of one run.
pub struct FlowOptions {
    /// How long to wait for the epoch to seal (`/v1/schedule`).
    pub seal_wait: PollBudget,
    /// How long, after the seal, to wait for BOTH witnesses (EVM serves only at finality,
    /// about 13 minutes on Sepolia).
    pub witness_timeout: Duration,
    pub witness_interval: Duration,
    /// The foreign-DID 403 check needs a second identity: in-process runs only, never on a
    /// remote (the main path creates no random DIDs).
    pub foreign_did_negative: bool,
    pub reader: ReaderConfig,
}

/// The full M-E2E flow. Takes a pre-constructed primary [`ClientKey`] so the same flow drives
/// the standing secp256k1 identity (remote) and the ephemeral ed25519 / p256 ones (in-process).
///
/// Main path: sign in, submit the tip of a fresh one-file client tree, wait for the seal, fetch
/// BOTH witnesses (EVM and qTSA; 202 is polled to `witness_timeout`, 404, a stub or a timeout is
/// a failure), merge them into the client tree and run the SDK verifier on it.
pub async fn run_full_flow(
    base_url: &str,
    primary: &ClientKey,
    seal: SealTrigger,
    opts: &FlowOptions,
    log: StepLogger<'_>,
) -> Result<E2eOutcome> {
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("build reqwest client")?;

    // 1. Test client identity.
    log(
        1,
        &format!(
            "test client {} ({}) using method {}",
            primary.did,
            primary.display_identifier,
            primary.method.label(),
        ),
    );

    // 2. /.well-known/aqua-identity
    let identity_url = format!("{base_url}/.well-known/aqua-identity");
    let resp = http_get(&client, &identity_url, None).await?;
    if !resp.status().is_success() {
        bail!("GET /.well-known/aqua-identity: HTTP {}", resp.status());
    }
    let identity: Value = resp.json().await.context("identity json")?;
    for k in [
        "protocol",
        "version",
        "server_did",
        "ethereum_address",
        "trust_level",
        "trust_domain",
        "supported_claims",
        "auth_method",
        "endpoints",
        "identity_claim",
    ] {
        if identity.get(k).is_none() {
            bail!("identity response missing key `{k}`");
        }
    }
    if identity["auth_method"].as_str() != Some("siwe") {
        bail!(
            "identity.auth_method must be \"siwe\", got {:?}",
            identity["auth_method"]
        );
    }
    let server_did = identity["server_did"]
        .as_str()
        .ok_or_else(|| anyhow!("server_did not a string"))?
        .to_string();
    log(2, &format!("identity shape ok, server_did={server_did}"));

    // 3. SIWE handshake -> Bearer token.
    let token = mint_bearer(&client, base_url, primary).await?;
    log(
        3,
        "auth/challenge signed and POST /auth/session returned a token",
    );

    // 5. The client's own tree; its tip is the leaf.
    let client_tree = new_client_tree("openwitness_seal_e2e")?;
    let leaf_hex = client_tree.leaf_hex.clone();
    log(5, &format!("client tree built, tip (leaf) {leaf_hex}"));

    // 6. POST /v1/leaves
    let leaves_url = format!("{base_url}/v1/leaves");
    let resp = http_post(
        &client,
        &leaves_url,
        Some(&token),
        &json!({ "leaves": [leaf_hex] }),
    )
    .await?;
    let status = resp.status();
    if status != StatusCode::ACCEPTED {
        let body = resp.text().await.unwrap_or_default();
        bail!("POST /v1/leaves: expected 202, got HTTP {status} body={body}");
    }
    let body: Value = resp.json().await.context("leaves response json")?;
    let epoch_id = body
        .get("epoch_id")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("leaves response missing epoch_id"))?;
    let epoch_closes_at = body
        .get("epoch_closes_at")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("leaves response missing epoch_closes_at"))?;
    log(
        6,
        &format!("submitted leaf to epoch {epoch_id} (closes_at={epoch_closes_at})"),
    );

    // 6.5. In-process runs drive the seal now.
    if let SealTrigger::Driver(drv) = &seal {
        drv().await;
    }

    // 7. Poll /v1/schedule until the epoch is sealed. The wait is the smaller of the caller's
    // ceiling and 2 * (close - now) + 30s (success-criteria M-E2E).
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let dyn_budget = PollBudget::from_epoch_close(epoch_closes_at, now_secs, 30);
    let effective_deadline = opts.seal_wait.deadline.min(dyn_budget.deadline);
    let sched_url = format!("{base_url}/v1/schedule");
    loop {
        if Instant::now() >= effective_deadline {
            bail!("timed out waiting for epoch {epoch_id} to seal");
        }
        let resp = http_get(&client, &sched_url, None).await?;
        if !resp.status().is_success() {
            bail!("GET /v1/schedule: HTTP {}", resp.status());
        }
        let body: Value = resp.json().await.context("schedule json")?;
        let last_sealed = body
            .get("last_sealed_epoch_id")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if last_sealed >= epoch_id {
            break;
        }
        tokio::time::sleep(opts.seal_wait.interval).await;
    }
    log(7, &format!("/v1/schedule confirms epoch {epoch_id} sealed"));

    // 8. Fetch BOTH witnesses. A sealed epoch is not yet a served witness (the anchor may be
    // outstanding or not final): poll 202 to the timeout. 404, a stub, a timeout: failure.
    let deadline = Instant::now() + opts.witness_timeout;
    let fetch = |method| {
        fetch_witness(
            &client,
            base_url,
            &leaf_hex,
            &token,
            method,
            deadline,
            opts.witness_interval,
        )
    };
    let (evm, qtsa) = tokio::join!(fetch(WitnessMethod::Evm), fetch(WitnessMethod::Qtsa));
    let (evm, qtsa) = match (evm, qtsa) {
        (Ok(e), Ok(q)) => (e, q),
        (e, q) => {
            let lines: Vec<String> = [e.err(), q.err()]
                .into_iter()
                .flatten()
                .map(|x| format!("  - {x}"))
                .collect();
            bail!(
                "GET /trees/by-leaf: both anchors are required, not served:\n{}",
                lines.join("\n")
            );
        }
    };
    log(
        8,
        &format!("fetched the evm and the qtsa witness for leaf {leaf_hex}"),
    );

    // 9. The SDK verifier on the client tree with both witness pairs merged in.
    let evm_network = evm
        .payloads
        .get("network")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let hosts = opts.reader.hosts(&evm_network)?;
    let verdicts = verify_with_sdk(&client_tree, &[&evm, &qtsa], &hosts, &server_did).await?;
    for v in &verdicts {
        log(
            9,
            &format!(
                "SDK verifier: {} timestamp revision verified ({}), aggregator signature ok, root={}",
                v.method.as_str(),
                v.anchor_verdict,
                v.merkle_root_hex
            ),
        );
    }
    if verdicts[0].merkle_root_hex != verdicts[1].merkle_root_hex {
        bail!(
            "the two anchors cover different roots: evm={} qtsa={}",
            verdicts[0].merkle_root_hex,
            verdicts[1].merkle_root_hex
        );
    }

    // 10a. Negative: a *different* DID's token is 403 on this leaf (in-process only).
    let by_leaf_url = format!("{base_url}/trees/by-leaf/{leaf_hex}?method=evm");
    if opts.foreign_did_negative {
        let secondary = ClientKey::random(SignatureMethod::Secp256k1Eip191)?;
        let token_secondary = mint_bearer(&client, base_url, &secondary).await?;
        let resp = http_get(&client, &by_leaf_url, Some(&token_secondary)).await?;
        if resp.status() != StatusCode::FORBIDDEN {
            let s = resp.status();
            let b = resp.text().await.unwrap_or_default();
            bail!("negative-1: expected 403 from foreign DID on by-leaf, got {s} body={b}");
        }
        log(
            10,
            &format!(
                "negative-1 ok: foreign DID ({}) gets 403 on by-leaf",
                secondary.did
            ),
        );
    } else {
        log(
            10,
            "negative-1 skipped: needs a second (random) identity, in-process runs only",
        );
    }

    // 10b. Negative: POST /v1/leaves without a Bearer is 401.
    let resp = http_post(
        &client,
        &leaves_url,
        None,
        &json!({ "leaves": [random_leaf()] }),
    )
    .await?;
    if resp.status() != StatusCode::UNAUTHORIZED {
        let s = resp.status();
        let b = resp.text().await.unwrap_or_default();
        bail!("negative-2: expected 401 on no-bearer submit, got {s} body={b}");
    }
    log(10, "negative-2 ok: no-bearer POST /v1/leaves returns 401");

    Ok(E2eOutcome {
        base_url: base_url.to_string(),
        server_did,
        client_did: primary.did.clone(),
        leaf_hex,
        epoch_id,
        witnesses: verdicts,
    })
}
