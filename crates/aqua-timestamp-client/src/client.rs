//! `TimestampClient`: top-level handle for the aqua-timestamp aggregator
//! protocol. Construct via `TimestampClient::builder()`, then use the
//! async methods to submit hashes, await epoch sealing, and retrieve
//! verified witness pairs.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aqua_rs_sdk::core::signature::verify_signature_sync;
use aqua_rs_sdk::schema::AnyRevision;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use tracing::debug;

use crate::auth::{AuthState, SignFn};
use crate::error::ClientError;
use crate::hex_utils::format_hash32_bare;
use crate::identity;
use crate::trust::{OnRotation, ServerRotation};
use crate::types::{AnchorMethod, EpochSchedule, ServerIdentity, SubmissionReceipt, WitnessPair};

#[derive(Clone)]
pub struct TimestampClient {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for TimestampClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TimestampClient")
            .field("base_url", &self.inner.base_url.as_str())
            .field("server_did", &self.inner.server.did)
            .field("my_did", &self.inner.auth.my_did())
            .field("rotation_detected", &self.inner.rotation.is_some())
            .finish()
    }
}

struct Inner {
    http: reqwest::Client,
    base_url: url::Url,
    auth: AuthState,
    server: ServerIdentity,
    rotation: Option<ServerRotation>,
    poll_interval: Duration,
    request_timeout: Duration,
}

impl TimestampClient {
    pub fn builder() -> TimestampClientBuilder {
        TimestampClientBuilder::default()
    }

    /// The server identity captured at `build()`. Sync, no I/O.
    pub fn server_identity(&self) -> &ServerIdentity {
        &self.inner.server
    }

    /// `Some(_)` if the discovered DID at build time differed from the
    /// `expect_server_did` prior. Useful when `OnRotation::Warn` was used.
    pub fn rotation_detected(&self) -> Option<&ServerRotation> {
        self.inner.rotation.as_ref()
    }

    /// Current epoch schedule. Public endpoint, no auth required.
    pub async fn schedule(&self) -> Result<EpochSchedule, ClientError> {
        let url = self.inner.base_url.join("/v1/schedule")?;
        let resp = self.inner.http.get(url.as_str()).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Server {
                status: status.as_u16(),
                body,
            });
        }
        Ok(resp.json::<EpochSchedule>().await?)
    }

    /// Submit a single 32-byte hash to the currently-open epoch.
    pub async fn submit(&self, hash: &[u8; 32]) -> Result<SubmissionReceipt, ClientError> {
        let mut receipts = self.submit_many(std::slice::from_ref(hash)).await?;
        receipts
            .pop()
            .ok_or_else(|| ClientError::Invalid("server returned empty receipt set".into()))
    }

    /// Submit a batch of 32-byte hashes in one request. Returns one receipt
    /// per input leaf in order; all receipts share the same epoch metadata.
    pub async fn submit_many(
        &self,
        hashes: &[[u8; 32]],
    ) -> Result<Vec<SubmissionReceipt>, ClientError> {
        if hashes.is_empty() {
            return Err(ClientError::Invalid("hashes must be non-empty".into()));
        }
        let token = self.inner.auth.ensure_token(&self.inner.http).await?;

        let leaves: Vec<String> = hashes
            .iter()
            .map(|h| format!("0x{}", format_hash32_bare(h)))
            .collect();
        let req = LeavesRequest { leaves };

        let url = self.inner.base_url.join("/v1/leaves")?;
        let resp = self
            .inner
            .http
            .post(url.as_str())
            .bearer_auth(&token)
            .json(&req)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Server {
                status: status.as_u16(),
                body,
            });
        }

        let body: LeavesResponse = resp.json().await?;

        Ok(hashes
            .iter()
            .map(|h| SubmissionReceipt {
                leaf: *h,
                epoch_id: body.epoch_id,
                epoch_closes_at: body.epoch_closes_at,
                submitter_did: body.submitter_did.clone(),
            })
            .collect())
    }

    /// Non-blocking witness lookup.
    ///
    /// - `Ok(None)` if the witness is not yet available (epoch not sealed
    ///   for this leaf yet, or sealed without a witness present).
    /// - `Ok(Some(_))` with a verified witness on success.
    /// - `Err(_)` for auth, transport, or signature-verification failures.
    pub async fn try_fetch_witness(
        &self,
        leaf: &[u8; 32],
        method: AnchorMethod,
    ) -> Result<Option<WitnessPair>, ClientError> {
        let token = self.inner.auth.ensure_token(&self.inner.http).await?;

        let leaf_hex = format_hash32_bare(leaf);
        let url = self
            .inner
            .base_url
            .join(&format!("/trees/by-leaf/{leaf_hex}"))?;

        let resp = self
            .inner
            .http
            .get(url.as_str())
            .bearer_auth(&token)
            .query(&[("method", method.as_str())])
            .send()
            .await?;

        let status = resp.status();
        if status.as_u16() == 404 {
            return Ok(None);
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Server {
                status: status.as_u16(),
                body,
            });
        }

        let tree: TreeWire = resp.json().await?;
        let pair = extract_witness_pair(&tree, method, &self.inner.server.did)?;
        Ok(Some(pair))
    }

    /// Blocking witness lookup with a caller-provided timeout.
    ///
    /// Polls `/v1/schedule` at the configured cadence until the receipt's
    /// epoch is sealed, then fetches and verifies the witness.
    pub async fn await_witness(
        &self,
        receipt: &SubmissionReceipt,
        method: AnchorMethod,
        timeout: Duration,
    ) -> Result<WitnessPair, ClientError> {
        let started = Instant::now();
        loop {
            let elapsed = started.elapsed();
            if elapsed >= timeout {
                return Err(ClientError::Timeout { elapsed });
            }

            let sched = self.schedule().await?;
            let sealed = sched
                .last_sealed_epoch_id
                .map(|id| id >= receipt.epoch_id)
                .unwrap_or(false);

            if sealed {
                if let Some(pair) = self.try_fetch_witness(&receipt.leaf, method).await? {
                    return Ok(pair);
                }
                // Epoch is sealed but the witness was not present; could be a
                // brief storage lag between seal and witness materialisation.
                // Sleep and retry rather than failing fast.
            }

            // Sleep at most until the timeout or the next poll, whichever is
            // sooner. Keeps short timeouts honest.
            let remaining = timeout.saturating_sub(started.elapsed());
            let nap = self.inner.poll_interval.min(remaining);
            if nap.is_zero() {
                return Err(ClientError::Timeout {
                    elapsed: started.elapsed(),
                });
            }
            sleep(nap).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct TimestampClientBuilder {
    base_url: Option<String>,
    my_did: Option<String>,
    signer: Option<SignFn>,
    expect_server_did: Option<(String, OnRotation)>,
    request_timeout: Option<Duration>,
    poll_interval: Option<Duration>,
}

impl TimestampClientBuilder {
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    pub fn my_did(mut self, did: impl Into<String>) -> Self {
        self.my_did = Some(did.into());
        self
    }

    /// Closure that signs a CAIP-122 message and returns its hex signature.
    pub fn signer<F>(mut self, signer: F) -> Self
    where
        F: Fn(&str) -> Result<String, Box<dyn std::error::Error + Send + Sync>>
            + Send
            + Sync
            + 'static,
    {
        self.signer = Some(Arc::new(signer));
        self
    }

    /// Cross-session rotation handling. Omit to default to pure bootstrap
    /// (no prior, accept whatever DID the server advertises). The pinned DID
    /// used for in-session signature verification is always the one
    /// discovered at `build()`.
    pub fn expect_server_did(
        mut self,
        prior: impl Into<String>,
        on_rotation: OnRotation,
    ) -> Self {
        self.expect_server_did = Some((prior.into(), on_rotation));
        self
    }

    pub fn request_timeout(mut self, dur: Duration) -> Self {
        self.request_timeout = Some(dur);
        self
    }

    pub fn poll_interval(mut self, dur: Duration) -> Self {
        self.poll_interval = Some(dur);
        self
    }

    /// Build the client. Fetches and verifies the server's identity claim,
    /// applies the rotation policy, runs one CAIP-122 handshake to seed the
    /// token cache, and returns a ready-to-use client.
    pub async fn build(self) -> Result<TimestampClient, ClientError> {
        let base_url = self
            .base_url
            .ok_or_else(|| ClientError::Invalid("base_url is required".into()))?;
        let base_url = url::Url::parse(&base_url).map_err(ClientError::Url)?;
        let my_did = self
            .my_did
            .ok_or_else(|| ClientError::Invalid("my_did is required".into()))?;
        let signer = self
            .signer
            .ok_or_else(|| ClientError::Invalid("signer is required".into()))?;

        let request_timeout = self.request_timeout.unwrap_or(Duration::from_secs(10));
        let poll_interval = self.poll_interval.unwrap_or(Duration::from_secs(5));

        let http = reqwest::Client::builder()
            .timeout(request_timeout)
            .build()
            .map_err(ClientError::Http)?;

        let (server, rotation) =
            identity::discover(&http, &base_url, self.expect_server_did.as_ref()).await?;

        let auth = AuthState::new(base_url.as_str().trim_end_matches('/').to_string(), my_did, signer);

        // Seed the token cache. If this fails, we surface the error rather
        // than handing back a client that will fail on first use.
        auth.ensure_token(&http).await?;

        debug!(did = %auth.my_did(), server = %server.did, "aqua-timestamp client ready");

        Ok(TimestampClient {
            inner: Arc::new(Inner {
                http,
                base_url,
                auth,
                server,
                rotation,
                poll_interval,
                request_timeout,
            }),
        })
    }
}

// ---------------------------------------------------------------------------
// Wire DTOs
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct LeavesRequest {
    leaves: Vec<String>,
}

#[derive(Deserialize)]
struct LeavesResponse {
    #[allow(dead_code)]
    accepted: u64,
    #[allow(dead_code)]
    duplicates: u64,
    epoch_id: u64,
    epoch_closes_at: u64,
    submitter_did: String,
}

/// Wire shape of the server's `Tree` response. Keys are hex strings; we
/// preserve raw `AnyRevision` deserialisation by way of the SDK's serde
/// impls.
#[derive(Deserialize)]
struct TreeWire {
    revisions: HashMap<String, AnyRevision>,
    #[allow(dead_code)]
    #[serde(default)]
    file_index: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// Witness extraction + verification
// ---------------------------------------------------------------------------

fn extract_witness_pair(
    tree: &TreeWire,
    method: AnchorMethod,
    pinned_server_did: &str,
) -> Result<WitnessPair, ClientError> {
    // Locate the Signature revision and its associated TimestampObject.
    let mut signature: Option<(String, &AnyRevision)> = None;
    let mut object: Option<(String, &AnyRevision)> = None;

    for (hash, rev) in &tree.revisions {
        match rev {
            AnyRevision::Signature(_) => {
                if signature.is_some() {
                    return Err(ClientError::Invalid(
                        "witness tree contains more than one Signature revision".into(),
                    ));
                }
                signature = Some((hash.clone(), rev));
            }
            AnyRevision::Typed(_) if rev.is_timestamp_object() => {
                if object.is_some() {
                    return Err(ClientError::Invalid(
                        "witness tree contains more than one timestamp object".into(),
                    ));
                }
                object = Some((hash.clone(), rev));
            }
            _ => {}
        }
    }

    let (sig_hash, sig_rev) = signature.ok_or_else(|| {
        ClientError::Invalid("witness tree has no Signature revision".into())
    })?;
    let (obj_hash, obj_rev) = object.ok_or_else(|| {
        ClientError::Invalid("witness tree has no timestamp Object revision".into())
    })?;

    // Structural: signature must chain off the object.
    let sig = sig_rev.as_signature().expect("checked above");
    if sig.previous_revision().to_string() != obj_hash {
        return Err(ClientError::Invalid(
            "witness Signature.previous_revision does not point to the timestamp Object".into(),
        ));
    }

    // Pinned-DID check: the signer string must be the server's DID.
    if sig.signer() != pinned_server_did {
        return Err(ClientError::SignatureMismatch);
    }

    // Cryptographic: signature recovers to its embedded public identifier.
    let (ok, _logs) = verify_signature_sync(sig_rev, &sig_hash, None);
    if !ok {
        return Err(ClientError::SignatureMismatch);
    }

    Ok(WitnessPair {
        object_revision: obj_rev.clone(),
        signature_revision: sig_rev.clone(),
        object_hash: obj_hash,
        signature_hash: sig_hash,
        anchor_method: method,
    })
}

// Allow Inner field access in cross-module helpers without exposing it
// publicly. Currently unused outside this module but keeps the door open.
#[allow(dead_code)]
impl Inner {
    pub(crate) fn request_timeout(&self) -> Duration {
        self.request_timeout
    }
}
