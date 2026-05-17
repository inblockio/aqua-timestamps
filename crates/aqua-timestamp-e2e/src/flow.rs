//! End-to-end client flow for the aqua-timestamp aggregator.
//!
//! This module owns the SIWE -> submit -> wait-for-seal -> witness ->
//! signature + Merkle verification path described in
//! `docs/success-criteria.md` Section M-E2E. It is parametrised by a base
//! URL so the same logic drives both the `live` subcommand (against
//! `https://timestamp.inblock.io`) and the `selfcheck` subcommand
//! (against an in-process server bound to `http://127.0.0.1:<port>`).
//!
//! Two seams keep the flow testable without burning Sepolia time or epoch
//! clock seconds:
//!
//! * [`SealTrigger`] lets a `selfcheck` caller drive the in-process sealer
//!   between submission and polling. The `live` caller passes
//!   [`SealTrigger::None`] and waits for the production interval timer.
//! * [`PollBudget`] caps wall-clock waits so a stuck deployment fails fast.

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use aqua_rs_sdk::{
    primitives::{merkle::verify_inclusion, HashType},
    schema::{tree::Tree, AnyRevision},
    Secp256k1Signer,
};
use rand::RngCore;
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};

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

/// Outcome a successful end-to-end run produces. The `live` subcommand
/// prints these; the selfcheck test asserts on them.
#[derive(Debug)]
pub struct E2eOutcome {
    pub base_url: String,
    pub server_did: String,
    pub client_did: String,
    pub leaf_hex: String,
    pub epoch_id: u64,
    pub merkle_root_hex: String,
    pub object_hash_hex: String,
    pub signature_hash_hex: String,
    pub recovered_signer_address: String,
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
    /// Derive a secp256k1 client from a BIP39 mnemonic. This is the path
    /// the production live test takes (mnemonic from the gnome-keyring).
    pub async fn from_mnemonic(mnemonic: &str) -> Result<Self> {
        let (_addr, eip55, priv_hex) = aqua_rs_sdk::primitives::get_wallet(mnemonic)
            .await
            .map_err(|e| anyhow!("get_wallet: {e}"))?;
        let did = format!("did:pkh:eip155:1:{eip55}");
        let mut pk = [0u8; 32];
        let decoded = hex::decode(priv_hex.trim_start_matches("0x")).context("priv hex")?;
        if decoded.len() != 32 {
            bail!("private key from get_wallet is not 32 bytes");
        }
        pk.copy_from_slice(&decoded);
        Ok(Self {
            did,
            display_identifier: eip55,
            method: SignatureMethod::Secp256k1Eip191,
            secret: KeyMaterial::Secp256k1 { private_key: pk },
        })
    }

    /// Generate a fresh random client for the requested method. Used both
    /// for the negative-test foreign DID and for the multi-method live run
    /// covering `ed25519` and `p256` clients.
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
                    display_identifier: addr.to_checksum(None),
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

fn parse_hex32(s: &str) -> Result<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).context("hex")?;
    if bytes.len() != 32 {
        bail!("expected 32-byte hex, got {} bytes", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn random_leaf() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("0x{}", hex::encode(bytes))
}

/// Server address from `did:pkh:eip155:<chain>:<addr>`.
fn address_from_did(did: &str) -> Result<String> {
    let last = did
        .rsplit(':')
        .next()
        .ok_or_else(|| anyhow!("did has no `:`"))?;
    if !last.starts_with("0x") || last.len() != 42 {
        bail!("did suffix is not a 0x-prefixed eth address: {last}");
    }
    Ok(last.to_string())
}

/// Verify a Signature revision the same way `aqua-rs-sdk` does internally:
/// reconstruct the pre-signature canonical JSON, ecrecover, compare to
/// `signature_public_identifier`. Returns the recovered EIP-55 address.
fn verify_signature_revision(sig_value: &Value) -> Result<String> {
    let rev: AnyRevision =
        serde_json::from_value(sig_value.clone()).context("AnyRevision deserialise")?;
    let signature = match &rev {
        AnyRevision::Signature(s) => s,
        _ => bail!("not a Signature revision"),
    };
    let canonical = signature.pre_signature_canonical_json();
    let canonical_str = std::str::from_utf8(&canonical).context("canonical utf8")?;

    // Pull the raw 65-byte signature out of the JSON ourselves so we don't
    // depend on which SignatureValue variant the SDK exposes.
    let sig_hex = sig_value
        .pointer("/signature/signature")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Signature.signature.signature missing"))?;
    let claimed_addr = sig_value
        .pointer("/signature/signature_public_identifier")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Signature.signature.signature_public_identifier missing"))?;

    let sig_bytes = hex::decode(sig_hex.trim_start_matches("0x")).context("sig hex")?;
    if sig_bytes.len() != 65 {
        bail!("expected 65-byte signature, got {} bytes", sig_bytes.len());
    }
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig_bytes);

    let recovered = aqua_rs_sdk::core::signature::recover_wallet_address(canonical_str, &sig65)
        .map_err(|e| anyhow!("recover_wallet_address: {e}"))?;
    let recovered_eip55 = recovered.to_checksum(None);
    // The on-wire `signature_public_identifier` is also EIP-55.
    if !recovered_eip55.eq_ignore_ascii_case(claimed_addr) {
        bail!(
            "recovered signer {recovered_eip55} != claimed signature_public_identifier {claimed_addr}"
        );
    }
    Ok(recovered_eip55)
}

/// The full M-E2E flow. Takes a pre-constructed primary [`ClientKey`] so
/// the same flow drives secp256k1, ed25519, and p256 DIDs uniformly.
pub async fn run_full_flow(
    base_url: &str,
    primary: &ClientKey,
    seal: SealTrigger,
    budget: PollBudget,
    log: StepLogger<'_>,
) -> Result<E2eOutcome> {
    // Step 0: build an HTTP client with sane connect / total timeouts so a
    // stuck server does not hang the test forever.
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("build reqwest client")?;

    // ── 1. Test client identity ──────────────────────────────────────────
    log(
        1,
        &format!(
            "test client {} ({}) using method {}",
            primary.did,
            primary.display_identifier,
            primary.method.label(),
        ),
    );

    // ── 2. /.well-known/aqua-identity ────────────────────────────────────
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
    let server_addr = address_from_did(&server_did)?;
    log(2, &format!("identity shape ok, server_did={server_did}"));

    // ── 3 + 4. SIWE handshake -> Bearer token for primary client ─────────
    let token_primary = mint_bearer(&client, base_url, primary).await?;
    log(
        3,
        "auth/challenge signed and POST /auth/session returned a token",
    );

    // ── 5. Random leaf ───────────────────────────────────────────────────
    let leaf_hex = random_leaf();
    log(5, &format!("generated random leaf {leaf_hex}"));

    // ── 6. POST /v1/leaves ───────────────────────────────────────────────
    let leaves_url = format!("{base_url}/v1/leaves");
    let resp = http_post(
        &client,
        &leaves_url,
        Some(&token_primary),
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

    // ── 6.5. If in selfcheck mode, drive the seal now. ───────────────────
    if let SealTrigger::Driver(drv) = &seal {
        drv().await;
    }

    // ── 7. Poll /v1/schedule until last_sealed_epoch_id >= epoch_id ──────
    //
    // The polling budget is the minimum of two things:
    //   (a) the caller's hard ceiling (`budget.deadline`), which guards
    //       against a stuck deployment.
    //   (b) the success-criteria §M-E2E rule: `2 * (epoch_closes_at - now)
    //       + 30s` grace, computed from the server's clock at submission
    //       time so a long epoch doesn't immediately blow out a tight
    //       caller-supplied budget.
    //
    // For selfcheck the seal already fired in step 6.5, so the loop exits
    // on the first iteration; for live, the dynamic ceiling kicks in.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let dyn_budget = PollBudget::from_epoch_close(epoch_closes_at, now_secs, 30);
    let effective_deadline = budget.deadline.min(dyn_budget.deadline);

    let sched_url = format!("{base_url}/v1/schedule");
    loop {
        if Instant::now() >= effective_deadline {
            bail!(
                "timed out waiting for epoch {epoch_id} to seal (last poll: {}s past deadline)",
                Instant::now()
                    .saturating_duration_since(effective_deadline)
                    .as_secs()
            );
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
        tokio::time::sleep(budget.interval).await;
    }
    log(7, &format!("/v1/schedule confirms epoch {epoch_id} sealed"));

    // ── 8. GET /trees/by-leaf/{leaf}?method=evm ──────────────────────────
    let by_leaf_url = format!("{base_url}/trees/by-leaf/{leaf_hex}?method=evm");
    let resp = http_get(&client, &by_leaf_url, Some(&token_primary)).await?;
    if !resp.status().is_success() {
        let s = resp.status();
        let b = resp.text().await.unwrap_or_default();
        bail!("GET /trees/by-leaf: HTTP {s} body={b}");
    }
    let tree_value: Value = resp.json().await.context("tree json")?;
    let _tree: Tree =
        serde_json::from_value(tree_value.clone()).context("tree deserialises to SDK Tree")?;
    let revisions = tree_value
        .get("revisions")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("tree.revisions missing"))?;
    let file_index = tree_value
        .get("file_index")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("tree.file_index missing"))?;
    if revisions.len() != 2 {
        bail!(
            "expected 2 revisions in the witness, got {}",
            revisions.len()
        );
    }
    if file_index.len() != 2 {
        bail!("expected 2 file_index entries, got {}", file_index.len());
    }
    log(
        8,
        &format!(
            "retrieved {} witness revisions for leaf {leaf_hex}",
            revisions.len()
        ),
    );

    // ── 9a. L1: every revision JSON re-hashes to its declared link ───────
    // `Linkable::calculate_link` is implemented per-variant (Object<P>,
    // Signature, Template, Anchor) and not on `AnyRevision` directly, so we
    // match the enum and dispatch to the right impl.
    for (declared_hash, rev_value) in revisions {
        let rev: AnyRevision = serde_json::from_value(rev_value.clone())
            .with_context(|| format!("deserialise revision {declared_hash}"))?;
        let computed = match &rev {
            AnyRevision::Typed(obj) => aqua_rs_sdk::verification::Linkable::calculate_link(obj),
            AnyRevision::Signature(sig) => aqua_rs_sdk::verification::Linkable::calculate_link(sig),
            AnyRevision::Template(t) => aqua_rs_sdk::verification::Linkable::calculate_link(t),
            AnyRevision::Anchor(a) => aqua_rs_sdk::verification::Linkable::calculate_link(a),
        }
        .map_err(|e| anyhow!("calculate_link({declared_hash}): {e:?}"))?;
        let computed_hex = format!("0x{}", hex::encode(computed.as_ref()));
        if !computed_hex.eq_ignore_ascii_case(declared_hash) {
            bail!("L1: revision {declared_hash} re-hashes to {computed_hex}; map key mismatch");
        }
    }
    log(
        9,
        "L1 ok: every revision JSON re-hashes to its declared link",
    );

    // ── 9b. L2: inclusion proof verifies against the stated merkle_root ──
    let mut object_value: Option<&Value> = None;
    let mut object_hash: Option<String> = None;
    let mut signature_value: Option<&Value> = None;
    let mut signature_hash: Option<String> = None;

    for (hash, rev_value) in revisions {
        let rev: AnyRevision = serde_json::from_value(rev_value.clone())?;
        match rev {
            AnyRevision::Typed(_) => {
                object_value = Some(rev_value);
                object_hash = Some(hash.clone());
            }
            AnyRevision::Signature(_) => {
                signature_value = Some(rev_value);
                signature_hash = Some(hash.clone());
            }
            _ => {}
        }
    }
    let object_value = object_value.ok_or_else(|| anyhow!("witness missing TimestampObject"))?;
    let signature_value =
        signature_value.ok_or_else(|| anyhow!("witness missing Signature revision"))?;
    let object_hash = object_hash.unwrap();
    let signature_hash = signature_hash.unwrap();

    let payloads = object_value
        .get("payloads")
        .ok_or_else(|| anyhow!("TimestampObject.payloads missing"))?;
    let merkle_root_hex = payloads
        .get("merkle_root")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("payloads.merkle_root missing"))?
        .to_string();
    let merkle_root = parse_hex32(&merkle_root_hex)?;
    let tree_size = payloads
        .get("batch_tree_size")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("payloads.batch_tree_size missing"))? as usize;
    let leaf_index = payloads
        .get("batch_leaf_index")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("payloads.batch_leaf_index missing"))? as usize;
    let proof_arr = payloads
        .get("merkle_proof")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("payloads.merkle_proof missing"))?;
    let proof: Result<Vec<Vec<u8>>> = proof_arr
        .iter()
        .map(|v| {
            let s = v
                .as_str()
                .ok_or_else(|| anyhow!("merkle_proof entry not a string"))?;
            Ok(parse_hex32(s)?.to_vec())
        })
        .collect();
    let proof = proof?;

    let leaf_bytes = parse_hex32(&leaf_hex)?;
    let ok = verify_inclusion(
        &leaf_bytes,
        leaf_index,
        tree_size,
        &proof,
        &merkle_root,
        &HashType::Sha3_256,
    );
    if !ok {
        bail!("L2: inclusion proof failed to verify against merkle_root {merkle_root_hex}");
    }

    // Sanity: TimestampObject.previous_revision must be the client leaf.
    let prev = object_value
        .get("previous_revision")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("TimestampObject.previous_revision missing"))?;
    if !prev.eq_ignore_ascii_case(&leaf_hex) {
        bail!("L2: TimestampObject.previous_revision {prev} != submitted leaf {leaf_hex}");
    }
    log(
        9,
        &format!(
            "L2 ok: inclusion proof verifies (root={merkle_root_hex}, idx={leaf_index}, size={tree_size})"
        ),
    );

    // ── 9c. L3: Signature recovers to the service address. ───────────────
    let recovered = verify_signature_revision(signature_value)?;
    if !recovered.eq_ignore_ascii_case(&server_addr) {
        bail!("L3: signature recovered {recovered} != server address {server_addr} from identity");
    }
    // And the on-wire `signer` field should match the identity's server_did.
    let signer_did = signature_value
        .get("signer")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Signature.signer missing"))?;
    if !signer_did.eq_ignore_ascii_case(&server_did) {
        bail!("L3: Signature.signer {signer_did} != identity.server_did {server_did}");
    }
    // Signature.previous_revision should point at the TimestampObject hash.
    let sig_prev = signature_value
        .get("previous_revision")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Signature.previous_revision missing"))?;
    if !sig_prev.eq_ignore_ascii_case(&object_hash) {
        bail!("L3: Signature.previous_revision {sig_prev} != object hash {object_hash}");
    }
    log(
        9,
        &format!("L3 ok: EIP-191 signature recovers to {recovered} (== server_did address)"),
    );

    // ── 9d. qTSA witness retrieval + verification ────────────────────────
    //
    // Same shape as the EVM path: fetch `/trees/by-leaf/{leaf}?method=qtsa`,
    // assert L1 (revision rehash), L2 (Merkle proof against the same root),
    // L3 (signature recovers to the same server address). Only the
    // TimestampObject payload differs (network = sectigo-qualified-tsa,
    // tsa_provider = the TSA publisher, transaction_hash = the RFC 3161
    // TimeStampResp base64). A 404 here doesn't fail the run (qTSA may be
    // disabled in a given deployment); the fields are checked only when
    // present.
    let by_leaf_qtsa_url = format!("{base_url}/trees/by-leaf/{leaf_hex}?method=qtsa");
    let resp_q = http_get(&client, &by_leaf_qtsa_url, Some(&token_primary)).await?;
    if resp_q.status() == StatusCode::NOT_FOUND {
        log(
            9,
            "qTSA witness not present for this epoch (skipping qtsa verification)",
        );
    } else if !resp_q.status().is_success() {
        let s = resp_q.status();
        let b = resp_q.text().await.unwrap_or_default();
        bail!("GET /trees/by-leaf?method=qtsa: HTTP {s} body={b}");
    } else {
        let qtsa_tree_value: Value = resp_q.json().await.context("qtsa tree json")?;
        let _qtsa_tree: Tree = serde_json::from_value(qtsa_tree_value.clone())
            .context("qtsa tree deserialises to SDK Tree")?;
        let qtsa_revisions = qtsa_tree_value
            .get("revisions")
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow!("qtsa tree.revisions missing"))?;
        if qtsa_revisions.len() != 2 {
            bail!(
                "qtsa witness should have 2 revisions, got {}",
                qtsa_revisions.len()
            );
        }

        // L1
        for (declared_hash, rev_value) in qtsa_revisions {
            let rev: AnyRevision = serde_json::from_value(rev_value.clone())?;
            let computed = match &rev {
                AnyRevision::Typed(obj) => aqua_rs_sdk::verification::Linkable::calculate_link(obj),
                AnyRevision::Signature(sig) => {
                    aqua_rs_sdk::verification::Linkable::calculate_link(sig)
                }
                AnyRevision::Template(t) => aqua_rs_sdk::verification::Linkable::calculate_link(t),
                AnyRevision::Anchor(a) => aqua_rs_sdk::verification::Linkable::calculate_link(a),
            }
            .map_err(|e| anyhow!("calculate_link({declared_hash}): {e:?}"))?;
            let computed_hex = format!("0x{}", hex::encode(computed.as_ref()));
            if !computed_hex.eq_ignore_ascii_case(declared_hash) {
                bail!("qtsa L1: rev {declared_hash} re-hashes to {computed_hex}");
            }
        }
        log(
            9,
            "qtsa L1 ok: every revision JSON re-hashes to its declared link",
        );

        // L2 + L3
        let mut q_obj: Option<&Value> = None;
        let mut q_sig: Option<&Value> = None;
        let mut q_obj_hash: Option<String> = None;
        for (h, v) in qtsa_revisions {
            let rev: AnyRevision = serde_json::from_value(v.clone())?;
            match rev {
                AnyRevision::Typed(_) => {
                    q_obj = Some(v);
                    q_obj_hash = Some(h.clone());
                }
                AnyRevision::Signature(_) => {
                    q_sig = Some(v);
                }
                _ => {}
            }
        }
        let q_obj = q_obj.ok_or_else(|| anyhow!("qtsa witness missing TimestampObject"))?;
        let q_sig = q_sig.ok_or_else(|| anyhow!("qtsa witness missing Signature"))?;

        let q_payloads = q_obj
            .get("payloads")
            .ok_or_else(|| anyhow!("qtsa payloads missing"))?;
        let q_root_hex = q_payloads
            .get("merkle_root")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("qtsa merkle_root missing"))?
            .to_string();
        let q_root = parse_hex32(&q_root_hex)?;
        let q_size = q_payloads
            .get("batch_tree_size")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("qtsa batch_tree_size missing"))? as usize;
        let q_idx = q_payloads
            .get("batch_leaf_index")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("qtsa batch_leaf_index missing"))? as usize;
        let q_proof_arr = q_payloads
            .get("merkle_proof")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("qtsa merkle_proof missing"))?;
        let q_proof: Result<Vec<Vec<u8>>> = q_proof_arr
            .iter()
            .map(|v| {
                Ok(parse_hex32(
                    v.as_str()
                        .ok_or_else(|| anyhow!("non-string proof entry"))?,
                )?
                .to_vec())
            })
            .collect();
        let q_proof = q_proof?;
        let q_ok = verify_inclusion(
            &leaf_bytes,
            q_idx,
            q_size,
            &q_proof,
            &q_root,
            &HashType::Sha3_256,
        );
        if !q_ok {
            bail!("qtsa L2: inclusion proof failed against {q_root_hex}");
        }
        let q_prev = q_obj
            .get("previous_revision")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("qtsa previous_revision missing"))?;
        if !q_prev.eq_ignore_ascii_case(&leaf_hex) {
            bail!("qtsa L2: previous_revision {q_prev} != leaf {leaf_hex}");
        }
        log(
            9,
            &format!(
                "qtsa L2 ok: inclusion proof verifies (root={q_root_hex}, idx={q_idx}, size={q_size})"
            ),
        );

        let q_recovered = verify_signature_revision(q_sig)?;
        if !q_recovered.eq_ignore_ascii_case(&server_addr) {
            bail!("qtsa L3: recovered {q_recovered} != server addr {server_addr}");
        }
        let q_sig_prev = q_sig
            .get("previous_revision")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("qtsa sig previous_revision missing"))?;
        let q_obj_hash = q_obj_hash.unwrap();
        if !q_sig_prev.eq_ignore_ascii_case(&q_obj_hash) {
            bail!("qtsa L3: sig prev {q_sig_prev} != obj hash {q_obj_hash}");
        }
        log(
            9,
            &format!("qtsa L3 ok: EIP-191 signature recovers to {q_recovered}"),
        );

        // Surface the qTSA-specific payload fields so the transcript shows
        // the RFC 3161 evidence the operator's eIDAS-qualified provider
        // returned: who signed (publisher), what TSA URL produced it, and
        // when the qualified TSA's `genTime` stamped the root.
        let tsa_provider = q_payloads
            .get("tsa_provider")
            .and_then(Value::as_str)
            .unwrap_or("?");
        let tsa_url = q_payloads
            .get("smart_contract_address")
            .and_then(Value::as_str)
            .unwrap_or("?");
        let tsa_time = q_payloads
            .get("timestamp")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let tsa_tx_len = q_payloads
            .get("transaction_hash")
            .and_then(Value::as_str)
            .map(|s| s.len())
            .unwrap_or(0);
        log(
            9,
            &format!(
                "qtsa payload: provider={tsa_provider} url={tsa_url} gen_time={tsa_time} response_bytes={tsa_tx_len}"
            ),
        );
    }

    // ── 10a. Negative: a *different* DID's token is 403 on this leaf. ────
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

    // ── 10b. Negative: POST /v1/leaves without a Bearer is 401. ──────────
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
        merkle_root_hex,
        object_hash_hex: object_hash,
        signature_hash_hex: signature_hash,
        recovered_signer_address: recovered,
    })
}
