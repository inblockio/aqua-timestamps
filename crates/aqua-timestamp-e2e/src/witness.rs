//! Fetch the two witnesses of a leaf and judge them with the SDK verifier (OW1.5, audit E).
//!
//! The e2e does not re-implement a check. It fetches `GET /trees/by-leaf/{leaf}?method=evm`
//! and `?method=qtsa`, merges both witness pairs into the client's own tree and runs
//! `Aquafier::verify_tree_sync`, the verifier a reader runs. The only judgements made here are
//! the ones the verifier cannot make: a method that never arrived (404, 202 at the deadline),
//! a stub (zero transaction hash, `stub` provider) and the signer's identity.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use aqua_rs_sdk::primitives::{Method, RevisionLink};
use aqua_rs_sdk::schema::tree::Tree;
use aqua_rs_sdk::schema::{AnyRevision, AquaTreeWrapper, FileData};
use aqua_rs_sdk::{Aquafier, BlockchainHost, VerificationResult, WebHost};
use rand::RngCore;
use reqwest::{Client, StatusCode};
use serde_json::Value;

/// The two anchors every leaf must carry on the main path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessMethod {
    Evm,
    Qtsa,
}

impl WitnessMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Evm => "evm",
            Self::Qtsa => "qtsa",
        }
    }
}

/// Why a witness did not arrive as a usable witness. Every variant is a failure of the run.
#[derive(Debug)]
pub enum WitnessError {
    /// HTTP 404: the deployment has no such witness (qTSA disabled counts: both are required).
    NotFound { method: WitnessMethod, body: String },
    /// HTTP 202 until the deadline: the method is still pending.
    StillPending {
        method: WitnessMethod,
        detail: String,
    },
    /// A stub served as a witness.
    Stub {
        method: WitnessMethod,
        reason: String,
    },
    /// Any other status.
    Http {
        method: WitnessMethod,
        status: u16,
        body: String,
    },
    /// The body is not a two-revision witness of this method.
    Malformed {
        method: WitnessMethod,
        reason: String,
    },
    /// The server never answered before the deadline.
    Unreachable {
        method: WitnessMethod,
        error: String,
    },
}

impl std::fmt::Display for WitnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound { method, body } => write!(
                f,
                "{} witness: HTTP 404 (both anchors are required, a missing method is a failure) body={body}",
                method.as_str()
            ),
            Self::StillPending { method, detail } => write!(
                f,
                "{} witness still pending (HTTP 202) at the timeout: {detail}",
                method.as_str()
            ),
            Self::Stub { method, reason } => {
                write!(f, "{} witness is a stub: {reason}", method.as_str())
            }
            Self::Http {
                method,
                status,
                body,
            } => write!(f, "{} witness: HTTP {status} body={body}", method.as_str()),
            Self::Malformed { method, reason } => {
                write!(f, "{} witness is malformed: {reason}", method.as_str())
            }
            Self::Unreachable { method, error } => write!(
                f,
                "{} witness: no answer from the server before the timeout: {error}",
                method.as_str()
            ),
        }
    }
}

impl std::error::Error for WitnessError {}

/// A served witness: the two revisions and where they sit.
#[derive(Debug, Clone)]
pub struct Fetched {
    pub method: WitnessMethod,
    /// The served tree as JSON (`revisions`, `file_index`).
    pub tree: Value,
    pub object_key: String,
    pub signature_key: String,
    /// The timestamp revision's `payloads`.
    pub payloads: Value,
}

/// A stub, if the payload is one: an empty or all-zero transaction hash, or a `stub` marker in
/// the provider, network, sender or contract fields. A method/network mismatch (a qTSA witness
/// that is not on the `tsa` network, an EVM witness that is) is reported the same way.
pub fn detect_stub(method: WitnessMethod, payloads: &Value) -> Option<String> {
    let text = |k: &str| payloads.get(k).and_then(Value::as_str).unwrap_or("");
    let tx = text("transaction_hash");
    let digits = tx.strip_prefix("0x").unwrap_or(tx);
    if digits.is_empty() {
        return Some("empty transaction_hash".to_string());
    }
    if method == WitnessMethod::Evm && digits.chars().all(|c| c == '0') {
        return Some(format!("zero transaction_hash {tx}"));
    }
    for k in [
        "tsa_provider",
        "network",
        "sender_account_address",
        "smart_contract_address",
    ] {
        if text(k).to_ascii_lowercase().contains("stub") {
            return Some(format!("{k} = {:?}", text(k)));
        }
    }
    let on_tsa_network = text("network") == "tsa";
    match (method, on_tsa_network) {
        (WitnessMethod::Qtsa, false) => Some(format!(
            "qtsa witness on network {:?}, expected \"tsa\"",
            text("network")
        )),
        (WitnessMethod::Evm, true) => Some("evm witness on the \"tsa\" network".to_string()),
        _ => None,
    }
}

fn pending_detail(body: &str) -> String {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| {
            let detail = v.get("detail").and_then(Value::as_str)?.to_string();
            let epoch = v.get("epoch").map(|e| e.to_string()).unwrap_or_default();
            Some(format!("epoch {epoch}: {detail}"))
        })
        .unwrap_or_else(|| body.to_string())
}

fn parse_witness(method: WitnessMethod, body: &str) -> Result<Fetched, WitnessError> {
    let malformed = |reason: String| WitnessError::Malformed { method, reason };
    let tree: Value =
        serde_json::from_str(body).map_err(|e| malformed(format!("not JSON: {e}")))?;
    serde_json::from_value::<Tree>(tree.clone())
        .map_err(|e| malformed(format!("not an SDK tree: {e}")))?;
    let revisions = tree
        .get("revisions")
        .and_then(Value::as_object)
        .ok_or_else(|| malformed("tree.revisions missing".into()))?;
    if revisions.len() != 2 {
        return Err(malformed(format!(
            "expected 2 revisions (timestamp + signature), got {}",
            revisions.len()
        )));
    }
    let (mut object, mut signature) = (None, None);
    for (key, value) in revisions {
        match serde_json::from_value::<AnyRevision>(value.clone())
            .map_err(|e| malformed(format!("revision {key}: {e}")))?
        {
            AnyRevision::Typed(_) => object = Some((key.clone(), value)),
            AnyRevision::Signature(_) => signature = Some(key.clone()),
            _ => {}
        }
    }
    let (object_key, object_value) =
        object.ok_or_else(|| malformed("no timestamp revision".into()))?;
    let signature_key = signature.ok_or_else(|| malformed("no signature revision".into()))?;
    let payloads = object_value
        .get("payloads")
        .cloned()
        .ok_or_else(|| malformed("timestamp revision has no payloads".into()))?;
    if let Some(reason) = detect_stub(method, &payloads) {
        return Err(WitnessError::Stub { method, reason });
    }
    Ok(Fetched {
        method,
        tree,
        object_key,
        signature_key,
        payloads,
    })
}

/// Fetch the witness of `leaf_hex` for `method`, polling while the server answers 202 until
/// `deadline`. 404, a stub, another status or a malformed body end the poll at once.
pub async fn fetch_witness(
    client: &Client,
    base_url: &str,
    leaf_hex: &str,
    bearer: &str,
    method: WitnessMethod,
    deadline: Instant,
    interval: Duration,
) -> Result<Fetched, WitnessError> {
    let url = format!(
        "{base_url}/trees/by-leaf/{leaf_hex}?method={}",
        method.as_str()
    );
    let mut pending: Option<String> = None;
    let mut transport: Option<String> = None;
    loop {
        match client.get(&url).bearer_auth(bearer).send().await {
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                match status {
                    StatusCode::ACCEPTED => pending = Some(pending_detail(&body)),
                    StatusCode::NOT_FOUND => return Err(WitnessError::NotFound { method, body }),
                    s if s.is_success() => return parse_witness(method, &body),
                    s => {
                        return Err(WitnessError::Http {
                            method,
                            status: s.as_u16(),
                            body,
                        })
                    }
                }
            }
            Err(e) => transport = Some(e.to_string()),
        }
        if Instant::now() >= deadline {
            return Err(match (pending, transport) {
                (Some(detail), _) => WitnessError::StillPending { method, detail },
                (None, error) => WitnessError::Unreachable {
                    method,
                    error: error.unwrap_or_default(),
                },
            });
        }
        tokio::time::sleep(interval).await;
    }
}

// ---- the client's own tree and the SDK verifier ---------------------------------------------

/// The reader's external-fact hosts: live (EVM RPC, EU trust list) or, in the in-process dry
/// run, the simulated chain and TSA the local aggregator also uses.
#[derive(Clone)]
pub struct ReaderHosts {
    pub blockchain: Arc<dyn BlockchainHost>,
    pub web: Arc<dyn WebHost>,
    /// The real TSA host reports the token's facts (policy OID, issuer), which the SDK admits
    /// to `tsa_tokens`; the dry run's simulated TSA reports none. True demands the entry as
    /// the proof the token was admitted at Verified or QualifiedVerified.
    pub tsa_facts_expected: bool,
}

/// A one-file client tree whose tip digest is the leaf submitted to the aggregator.
pub struct ClientTree {
    tree: Value,
    file: FileData,
    pub leaf_hex: String,
}

/// A fresh client tree. The file content is unique per run, so every run submits a new leaf.
pub fn new_client_tree(tag: &str) -> Result<ClientTree> {
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let name = format!("{tag}.txt");
    let file = FileData::new(
        name.clone(),
        format!("openwitness-seal-e2e {tag} {}", hex::encode(nonce)).into_bytes(),
        std::path::PathBuf::from(&name),
    );
    let tree = Aquafier::new()
        .create_genesis_revision(file.clone(), Some(Method::Scalar))
        .map_err(|e| anyhow!("client genesis: {e:?}"))?;
    let tree = serde_json::to_value(&tree).context("client tree json")?;
    let revisions = tree["revisions"]
        .as_object()
        .ok_or_else(|| anyhow!("client tree has no revisions"))?;
    // The tip: the one revision no other revision names as its `previous_revision`.
    let previous: Vec<&str> = revisions
        .values()
        .filter_map(|r| r["previous_revision"].as_str())
        .collect();
    let tips: Vec<&String> = revisions
        .keys()
        .filter(|k| !previous.contains(&k.as_str()))
        .collect();
    if tips.len() != 1 {
        bail!("a linear client tree has one tip, found {}", tips.len());
    }
    let link: RevisionLink = tips[0].parse().map_err(|e| anyhow!("tip link: {e:?}"))?;
    let bytes: &[u8] = link.as_ref();
    let digest = bytes
        .get(bytes.len().saturating_sub(32)..)
        .filter(|d| d.len() == 32)
        .ok_or_else(|| anyhow!("tip link is shorter than 32 bytes"))?;
    Ok(ClientTree {
        tree,
        file,
        leaf_hex: format!("0x{}", hex::encode(digest)),
    })
}

fn merged(client: &ClientTree, witnesses: &[&Fetched]) -> Result<Tree> {
    let mut tree = client.tree.clone();
    for w in witnesses {
        let (Some(revs), Some(index)) = (
            w.tree.get("revisions").and_then(Value::as_object),
            w.tree.get("file_index").and_then(Value::as_object),
        ) else {
            bail!("{} witness has no revisions/file_index", w.method.as_str());
        };
        for (k, v) in revs {
            tree["revisions"][k] = v.clone();
        }
        for (k, v) in index {
            tree["file_index"][k] = v.clone();
        }
    }
    serde_json::from_value(tree).context("merged client tree parses")
}

fn errors_of(result: &VerificationResult, revision: &str) -> Vec<String> {
    result
        .errors()
        .iter()
        .filter(|e| e.revision_hash == revision)
        .map(|e| format!("{}: {}", e.code, e.message))
        .collect()
}

fn error_logs(result: &VerificationResult) -> Vec<String> {
    result
        .logs
        .iter()
        .filter(|l| format!("{:?}", l.log_type).contains("Error"))
        .map(|l| l.log.clone())
        .collect()
}

/// What the SDK verdict says about one method's witness pair.
#[derive(Debug, Clone)]
pub struct MethodVerdict {
    pub method: WitnessMethod,
    pub merkle_root_hex: String,
    pub timestamp_revision: String,
    pub signature_revision: String,
    /// Plain-text verdict of the anchor (`Verified...` for EVM, the token level for qTSA).
    pub anchor_verdict: String,
}

/// Run the SDK verifier on the client tree with every given witness pair merged in, and
/// assert, per witness: the timestamp revision carries no error, its anchor reached the
/// verified state (EVM verdict `Verified`, TSA token admitted), the aggregator's signature
/// revision carries no error and names `server_did` as signer, and the whole tree is verified.
///
/// Runs on a blocking thread: the live EVM host blocks on its own runtime handle.
pub async fn verify_with_sdk(
    client: &ClientTree,
    witnesses: &[&Fetched],
    hosts: &ReaderHosts,
    server_did: &str,
) -> Result<Vec<MethodVerdict>> {
    let tree = merged(client, witnesses)?;
    let file = client.file.clone();
    let tsa_facts_expected = hosts.tsa_facts_expected;
    let hosts = hosts.clone();
    let result = tokio::task::spawn_blocking(move || {
        Aquafier::builder()
            .blockchain_host(hosts.blockchain)
            .web_host(hosts.web)
            .build()
            .verify_tree_sync(AquaTreeWrapper::new(tree, None, None), vec![file])
    })
    .await
    .context("verifier thread")?
    .map_err(|e| anyhow!("verification did not run: {e:?}"))?;

    let mut verdicts = Vec::new();
    for w in witnesses {
        let m = w.method.as_str();
        let (obj, sig) = (&w.object_key, &w.signature_key);
        let obj_errors = errors_of(&result, obj);
        if !obj_errors.is_empty() {
            bail!(
                "{m} timestamp revision fails the SDK verifier: {obj_errors:#?}\nerror logs: {:#?}",
                error_logs(&result)
            );
        }
        let anchor_verdict = match w.method {
            WitnessMethod::Evm => {
                let v = result.evm_anchors.get(obj);
                let text = format!("{v:?}");
                if !matches!(v, Some(v) if format!("{v:?}").starts_with("Verified")) {
                    bail!("evm anchor verdict for the timestamp revision is not Verified: {text}");
                }
                text
            }
            WitnessMethod::Qtsa => match result.tsa_tokens.get(obj) {
                Some(token) => format!("token admitted: {token:?}"),
                None if tsa_facts_expected => bail!(
                    "qtsa token was not admitted as verified: tsa_tokens={:?}",
                    result.tsa_tokens
                ),
                // Simulated TSA host (dry run): it reports no facts. The token is still judged
                // by the verifier: a token that does not verify is an error on this revision
                // (TIMESTAMP_TSA_INVALID), checked above, and the whole tree must verify.
                None => {
                    "no error from the simulated TSA host (it reports no token facts)".to_string()
                }
            },
        };
        let sig_errors = errors_of(&result, sig);
        if !sig_errors.is_empty() {
            bail!("{m} aggregator signature revision fails the SDK verifier: {sig_errors:#?}");
        }
        let signer = w
            .tree
            .pointer(&format!("/revisions/{sig}/signer"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if !signer.eq_ignore_ascii_case(server_did) {
            bail!(
                "{m} signature signer {signer:?} is not the identity's server_did {server_did:?}"
            );
        }
        verdicts.push(MethodVerdict {
            method: w.method,
            merkle_root_hex: w
                .payloads
                .get("merkle_root")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            timestamp_revision: obj.clone(),
            signature_revision: sig.clone(),
            anchor_verdict,
        });
    }
    if !result.is_verified() {
        bail!(
            "client tree with both witnesses does not verify: {:?}\nerror logs: {:#?}",
            result.outcome,
            error_logs(&result)
        );
    }
    Ok(verdicts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{http::StatusCode as AxStatus, Router};
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn good_evm() -> Value {
        json!({"transaction_hash": format!("0x{}", "ab".repeat(32)), "network": "sepolia",
               "tsa_provider": "", "sender_account_address": "0xCAFE", "smart_contract_address": "0xDEAD"})
    }

    fn good_qtsa() -> Value {
        json!({"transaction_hash": "AAAA", "network": "tsa", "tsa_provider": "Some TSA",
               "sender_account_address": "", "smart_contract_address": "http://tsa.test/"})
    }

    #[test]
    fn a_real_looking_pair_is_not_a_stub() {
        assert_eq!(detect_stub(WitnessMethod::Evm, &good_evm()), None);
        assert_eq!(detect_stub(WitnessMethod::Qtsa, &good_qtsa()), None);
    }

    #[test]
    fn stubs_are_detected() {
        let mut p = good_evm();
        p["transaction_hash"] = json!(format!("0x{}", "00".repeat(32)));
        assert!(detect_stub(WitnessMethod::Evm, &p)
            .unwrap()
            .contains("zero transaction_hash"));
        p["transaction_hash"] = json!("");
        assert!(detect_stub(WitnessMethod::Evm, &p)
            .unwrap()
            .contains("empty"));
        let mut q = good_qtsa();
        q["tsa_provider"] = json!("stub");
        assert!(detect_stub(WitnessMethod::Qtsa, &q)
            .unwrap()
            .contains("tsa_provider"));
        let mut q = good_qtsa();
        q["transaction_hash"] = json!("");
        assert!(detect_stub(WitnessMethod::Qtsa, &q).is_some());
        let mut e = good_evm();
        e["network"] = json!("STUB-chain");
        assert!(detect_stub(WitnessMethod::Evm, &e).is_some());
    }

    #[test]
    fn method_and_network_must_agree() {
        assert!(detect_stub(WitnessMethod::Qtsa, &good_evm()).is_some());
        assert!(detect_stub(WitnessMethod::Evm, &good_qtsa()).is_some());
    }

    async fn serve(app: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{addr}")
    }

    async fn fetch(base: &str, method: WitnessMethod, ms: u64) -> Result<Fetched, WitnessError> {
        fetch_witness(
            &Client::new(),
            base,
            "0x00",
            "t",
            method,
            Instant::now() + Duration::from_millis(ms),
            Duration::from_millis(10),
        )
        .await
    }

    #[tokio::test]
    async fn a_404_is_a_failure_naming_the_method() {
        let base =
            serve(Router::new().fallback(|| async { (AxStatus::NOT_FOUND, "no qtsa") })).await;
        let err = fetch(&base, WitnessMethod::Qtsa, 2_000).await.unwrap_err();
        assert!(matches!(err, WitnessError::NotFound { .. }), "{err}");
        let text = err.to_string();
        assert!(text.contains("qtsa") && text.contains("404"), "{text}");
    }

    #[tokio::test]
    async fn pending_is_polled_until_the_timeout_and_names_the_method() {
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let base = serve(Router::new().fallback(move || {
            let h = h.clone();
            async move {
                h.fetch_add(1, Ordering::SeqCst);
                (
                    AxStatus::ACCEPTED,
                    r#"{"status":"pending","method":"evm","epoch":7,"leaf":"0x00","detail":"waiting for finality"}"#,
                )
            }
        }))
        .await;
        let err = fetch(&base, WitnessMethod::Evm, 300).await.unwrap_err();
        assert!(matches!(err, WitnessError::StillPending { .. }), "{err}");
        let text = err.to_string();
        assert!(
            text.contains("evm")
                && text.contains("pending")
                && text.contains("waiting for finality"),
            "{text}"
        );
        assert!(hits.load(Ordering::SeqCst) >= 3, "it kept polling");
    }

    #[tokio::test]
    async fn pending_then_an_answer_stops_the_poll() {
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let base = serve(Router::new().fallback(move || {
            let h = h.clone();
            async move {
                if h.fetch_add(1, Ordering::SeqCst) < 3 {
                    (AxStatus::ACCEPTED, r#"{"status":"pending"}"#.to_string())
                } else {
                    (AxStatus::OK, r#"{"revisions":{}}"#.to_string())
                }
            }
        }))
        .await;
        let err = fetch(&base, WitnessMethod::Evm, 5_000).await.unwrap_err();
        // The 200 body is not a witness, which proves the poll got through the 202s.
        assert!(matches!(err, WitnessError::Malformed { .. }), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn other_statuses_end_the_poll_at_once() {
        let base = serve(Router::new().fallback(|| async { (AxStatus::FORBIDDEN, "no") })).await;
        let err = fetch(&base, WitnessMethod::Evm, 5_000).await.unwrap_err();
        assert!(
            matches!(err, WitnessError::Http { status: 403, .. }),
            "{err}"
        );
    }

    #[tokio::test]
    async fn an_unreachable_server_times_out_as_unreachable() {
        let err = fetch("http://127.0.0.1:1", WitnessMethod::Evm, 200)
            .await
            .unwrap_err();
        assert!(matches!(err, WitnessError::Unreachable { .. }), "{err}");
    }

    #[test]
    fn client_trees_carry_a_fresh_leaf_each() {
        let a = new_client_tree("t").unwrap();
        let b = new_client_tree("t").unwrap();
        assert_ne!(a.leaf_hex, b.leaf_hex);
        assert_eq!(a.leaf_hex.len(), 66);
    }
}
