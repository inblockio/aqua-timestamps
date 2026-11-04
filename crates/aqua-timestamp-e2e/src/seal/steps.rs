//! Steps 1 to 7 of a seal run, on persisted data alone. A live run calls [`run`] after its pull,
//! a replay after [`super::run_dir::verify_complete`]: this module holds no HTTP client and no
//! signing key of the run, so the steps cannot reach the aggregator. Their only network is the
//! EVM host inside the reader.
//!
//! No trust logic: each assertion compares SDK outputs. Step 5 flips bytes and step 7 compares
//! what the epoch listing reports with what the served witnesses carry, parsed by the SDK.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use aqua_rs_sdk::core::seal::{
    build_seal_container, complete_seal, evaluate_seal_witnesses, finish_seal, full_set_check,
    handover_check_seal, read_seal_attestations, verify_seal_container, AcceptedWitnesses,
    AnchorKind, AttestationBasis, AttestationRule, AttestationVerdict, DimensionState,
    FullSetPackage, FullSetVerdict, Headline, MemberTree, PreparedSeal, SealAttestationsReading,
    SealError, SealHead, SealReading, SealReceipt, SealStatus, SealTime, SealWitness, VerifiedSeal,
    WitnessAdmission, WitnessInput, WitnessRefusal, WitnessRequirement,
};
use aqua_rs_sdk::primitives::merkle::{
    parse_batch_digest, parse_batch_root, shielded_leaf, BatchDigest,
};
use aqua_rs_sdk::primitives::{HashType, Method, RevisionLink};
use aqua_rs_sdk::schema::link::Anchor;
use aqua_rs_sdk::schema::tree::Tree;
use aqua_rs_sdk::schema::{AnyRevision, SigningCredentials};
use aqua_rs_sdk::verification::Linkable;
use rand::RngCore;
use serde_json::{json, Value};

use super::log::{utc, StepLog};
use super::policy::Reader;
use super::run_dir::{
    admit_members, blocking, epoch_file, epochs_file, hex_digest, prepared_file, RunState, Store,
    ATTESTATIONS_1, CONTAINER_1, FETCH_STATUS,
};
use super::tamper::{
    alter_p_key_kept, flip_tsa_token, link_of, only_p, rekey_bad_signature, remove_p,
};
use crate::witness::{detect_stub, parse_served, parse_witness, Fetched, WitnessMethod};

/// The SDK test that is gate 6a: one-shot and two-step builds byte-identical over a
/// deterministic provider. This crate names it and does not copy it; step 6 here is 6b.
pub const GATE_6A_SDK_TEST: &str = "sp2_e8_one_shot_and_two_step_byte_identical";

/// A run submits two leaves, S1 and S2.
pub const OWN_LEAVES: u64 = 2;

/// Everything the steps need. Deliberately no HTTP client and no identity.
pub struct Ctx {
    pub store: Store,
    pub reader: Reader,
    pub state: RunState,
    pub header: Vec<String>,
    pub expect_server_did: Option<String>,
    /// How long step 1 retries the documented retryable refusal (EVM not final yet).
    pub finality_budget: Duration,
}

/// Which steps a [`run`] covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Steps {
    /// 1 to 7: a live run.
    All,
    /// 2 to 7: step 1 built what a replay re-reads.
    FromPersisted,
}

/// Run the steps in order, writing each step's log as it ends (with `closing` as its last line).
pub async fn run(ctx: &Ctx, which: Steps, closing: &str) -> Result<Vec<StepLog>> {
    let mut logs = Vec::new();
    let keep = |log: StepLog, logs: &mut Vec<StepLog>| -> Result<()> {
        if let Some(dir) = ctx.store.write_dir() {
            log.write(dir, closing)?;
        }
        logs.push(log);
        Ok(())
    };
    if which == Steps::All {
        keep(step1(ctx).await, &mut logs)?;
    }
    let (l2, s2) = step2(ctx).await;
    keep(l2, &mut logs)?;
    keep(step3(ctx).await, &mut logs)?;
    keep(step4(ctx).await, &mut logs)?;
    keep(step5(ctx, s2.as_ref()).await, &mut logs)?;
    keep(step6(ctx).await, &mut logs)?;
    keep(step7(ctx).await, &mut logs)?;
    Ok(logs)
}

// ---- helpers ---------------------------------------------------------------------------------

/// A served witness split into T and P, with their served keys.
pub struct ServedPair {
    pub fetched: Fetched,
    pub object: AnyRevision,
    pub signature: AnyRevision,
}

fn pair_of(fetched: Fetched) -> Result<ServedPair> {
    let revision = |key: &str| -> Result<AnyRevision> {
        serde_json::from_value(fetched.tree["revisions"][key].clone())
            .map_err(|e| anyhow!("served revision {key}: {e}"))
    };
    let object = revision(&fetched.object_key)?;
    let signature = revision(&fetched.signature_key)?;
    Ok(ServedPair {
        fetched,
        object,
        signature,
    })
}

fn load_pair(store: &Store, file: &str, method: WitnessMethod) -> Result<ServedPair> {
    let body = store.read(file)?;
    pair_of(parse_witness(method, &body).map_err(|e| anyhow!("{file}: {e}"))?)
}

/// One served witness body as step 1 reads it: the pair, the stub check on its payload, its
/// served keys against the SDK's links. `None` when the body cannot be used; every reason is a
/// failed assertion in `log`.
pub fn served_witness(
    log: &mut StepLog,
    key: &str,
    method: WitnessMethod,
    body: &str,
) -> Result<Option<SealWitness>> {
    let fetched = match parse_served(method, body) {
        Ok(f) => f,
        Err(e) => {
            log.check(false, format!("{key}: {e}"), "anchor missing");
            return Ok(None);
        }
    };
    let stub = detect_stub(method, &fetched.payloads);
    if !log.check(
        stub.is_none(),
        format!("{key}: detect_stub on the served payload = {stub:?}"),
        "stub",
    ) {
        return Ok(None);
    }
    let pair = pair_of(fetched)?;
    log.l(format!(
        "{key}: T {} payloads {}",
        pair.fetched.object_key,
        shorten_token(&pair.fetched.payloads)
    ));
    log.l(format!(
        "{key}: P {} {}",
        pair.fetched.signature_key,
        serde_json::to_string(&pair.signature)?
    ));
    const NOT_THE_LINK: &str = "anchor missing (served key is not the SDK link)";
    let t_link = link_of(&pair.object)?;
    let p_link = link_of(&pair.signature)?;
    let t_ok = log.check(
        t_link.to_string() == pair.fetched.object_key,
        format!("{key}: served key of T equals SDK link {t_link}"),
        NOT_THE_LINK,
    );
    let p_ok = log.check(
        p_link.to_string() == pair.fetched.signature_key,
        format!("{key}: served key of P equals SDK link {p_link}"),
        NOT_THE_LINK,
    );
    Ok((t_ok && p_ok).then(|| SealWitness::new(pair.object, Some(pair.signature))))
}

/// Payloads for the log, with a long TSA token shortened.
fn shorten_token(payloads: &Value) -> Value {
    let mut p = payloads.clone();
    if let Some(tx) = p["transaction_hash"].as_str().map(str::to_string) {
        if tx.len() > 100 {
            p["transaction_hash"] = json!(format!("{}... ({} chars)", &tx[..60], tx.len()));
        }
    }
    p
}

fn fetch_status(ctx: &Ctx, key: &str) -> Value {
    ctx.store
        .read(FETCH_STATUS)
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .map(|v| v[key].clone())
        .unwrap_or(Value::Null)
}

fn load_prepared(ctx: &Ctx, seal: usize) -> Result<PreparedSeal> {
    Ok(serde_json::from_str(
        &ctx.store.read(&prepared_file(seal))?,
    )?)
}

fn load_container(ctx: &Ctx) -> Result<Tree> {
    Ok(serde_json::from_str(&ctx.store.read(CONTAINER_1)?)?)
}

fn receipts_for(
    anchor: &RevisionLink,
    head: &SealHead,
    leaves: &[BatchDigest],
    tips: &[RevisionLink],
    nonces: &[BatchDigest],
) -> Result<Vec<SealReceipt>> {
    tips.iter()
        .zip(nonces)
        .enumerate()
        .map(|(i, (t, n))| {
            SealReceipt::issue(anchor, head, leaves, i as u64, t.clone(), *n)
                .map_err(|e| anyhow!("receipt {i}: {e}"))
        })
        .collect()
}

async fn verify(reader: &Reader, container: &Tree, input: WitnessInput) -> Result<SealReading> {
    let aq = reader.aq.clone();
    let catalogue = reader.policy.catalogue();
    let c = container.clone();
    blocking(move || verify_seal_container(&aq, &c, &input, &catalogue)).await
}

async fn members(ctx: &Ctx) -> Result<Vec<MemberTree>> {
    admit_members(&ctx.reader.aq, &ctx.state.members).await
}

/// An EVM witness's provenance without its confirmation count, the one thing in it that follows
/// the chain head. Any other text passes through, so a new form compares in full.
pub fn without_chain_head(provenance: &str) -> &str {
    match provenance.rfind(" confirmations ") {
        Some(i)
            if provenance[i + " confirmations ".len()..]
                .bytes()
                .all(|b| b.is_ascii_digit()) =>
        {
            &provenance[..i]
        }
        _ => provenance,
    }
}

/// Every part of a seal reading two reads of one container share. The chain head moves between
/// two reads (about every 12 s on Sepolia), so the EVM witness's confirmation count stays out.
fn stable(v: &VerifiedSeal) -> String {
    let mut acceptance = v.witness_acceptance().clone();
    for w in &mut acceptance.witnesses {
        w.provenance = w
            .provenance
            .as_deref()
            .map(|p| without_chain_head(p).to_string());
    }
    format!(
        "{:?} {:?} {} {} {} {} {:?} {} {:?} {:?} {:?} {:?} {:?} {}",
        v.status(),
        v.signed_head(),
        v.genesis(),
        v.head_link(),
        v.signature(),
        v.signer(),
        v.witnesses(),
        v.anchor(),
        v.sdk().outcome,
        acceptance,
        v.sealer_signature(),
        v.time(),
        v.sdk().errors(),
        v.identity_verified(),
    )
}

fn log_seal(log: &mut StepLog, ctx: &Ctx, label: &str, v: &VerifiedSeal) {
    log.l(format!("[{label}] SDK status = {:?}", v.status()));
    log.l(format!(
        "[{label}] anchor A = {}, head H = {}, signature S = {}, genesis G = {}",
        v.anchor(),
        v.head_link(),
        v.signature(),
        v.genesis()
    ));
    log.l(format!("[{label}] signer = {}", v.signer()));
    log.l(format!("[{label}] signed_head = {:?}", v.signed_head()));
    log.l(format!(
        "[{label}] witnesses (T links) = {:?}",
        v.witnesses()
    ));
    log.l(format!(
        "[{label}] sealer_signature = {:?}",
        v.sealer_signature()
    ));
    log.l(format!(
        "[{label}] witness_acceptance = {:?}",
        v.witness_acceptance()
    ));
    log.l(format!(
        "[{label}] witness findings = {:?}",
        v.witness_acceptance().findings()
    ));
    log.l(format!("[{label}] time = {:?}", v.time()));
    log.l(format!(
        "[{label}] sdk outcome = {:?}; sdk errors = {:?}",
        v.sdk().outcome,
        v.sdk().errors()
    ));
    log.l(format!(
        "[{label}] sdk tsa_tokens = {:?}",
        v.sdk().tsa_tokens
    ));
    log.l(format!(
        "[{label}] sdk evm_anchors = {:?}",
        v.sdk().evm_anchors
    ));
    log.l(format!(
        "[{label}] identity_verified = {}",
        v.identity_verified()
    ));
    if let Err(e) = ctx
        .store
        .artifact(&format!("debug/{label}-seal.txt"), format!("{v:#?}\n"))
    {
        log.l(format!("[{label}] debug form not written: {e:#}"));
    }
}

fn log_verdict(log: &mut StepLog, label: &str, v: &FullSetVerdict) {
    log.l(format!(
        "[{label}] full_set_check: set_headline = {}, completeness = {}, integrity = {}, non_suppression = {}",
        v.set_headline.as_str(),
        v.completeness.as_str(),
        v.integrity.as_str(),
        v.non_suppression.as_str()
    ));
    for f in &v.findings {
        log.l(format!("[{label}] finding {} {:?}", f.code, f.args));
    }
    if v.findings.is_empty() {
        log.l(format!("[{label}] findings: none"));
    }
}

fn log_attestations(log: &mut StepLog, label: &str, r: &SealAttestationsReading) {
    log.l(format!("[{label}] read_seal_attestations = {r:?}"));
}

/// The package of one seal and its members and receipts; a rejected container goes to `rejected`.
fn package_of(
    reading: SealReading,
    members: Vec<MemberTree>,
    receipts: Vec<SealReceipt>,
) -> FullSetPackage {
    match reading.into_seal() {
        Ok(seal) => FullSetPackage {
            root: Some(seal.anchor().clone()),
            seals: vec![seal],
            members,
            receipts,
            ..Default::default()
        },
        Err(rej) => FullSetPackage {
            root: rej.id().cloned(),
            rejected: vec![rej],
            members,
            receipts,
            ..Default::default()
        },
    }
}

fn reading_of(r: &SealAttestationsReading, t: &RevisionLink) -> Option<Vec<AttestationVerdict>> {
    r.witnesses
        .iter()
        .find(|w| &w.witness == t)
        .map(|w| w.attestations.iter().map(|a| a.verdict.clone()).collect())
}

fn admission_of<'a>(v: &'a VerifiedSeal, t: &RevisionLink) -> Option<&'a WitnessAdmission> {
    v.witness_acceptance()
        .witnesses
        .iter()
        .find(|w| &w.witness == t)
        .map(|w| &w.admission)
}

/// One call of the evaluator, its inputs together.
struct Evaluation<'a> {
    prepared: &'a PreparedSeal,
    head: &'a SealHead,
    did: &'a str,
    witnesses: &'a [SealWitness],
    requirement: &'a WitnessRequirement,
    /// How long the retryable "EVM not final" refusal is retried; zero never retries.
    budget: Duration,
}

/// The evaluator, retried only on the documented retryable refusal; every attempt is logged.
async fn evaluate_with_retry(
    log: &mut StepLog,
    reader: &Reader,
    e: Evaluation<'_>,
) -> Result<std::result::Result<AcceptedWitnesses, WitnessRefusal>> {
    let deadline = Instant::now() + e.budget;
    let mut attempt = 0;
    loop {
        attempt += 1;
        let (aq, p, h, d, w, r) = (
            reader.aq.clone(),
            e.prepared.clone(),
            e.head.clone(),
            e.did.to_string(),
            e.witnesses.to_vec(),
            e.requirement.clone(),
        );
        let res = blocking(move || evaluate_seal_witnesses(&aq, &p, &h, &d, &w, &r)).await?;
        match &res {
            Err(refusal @ WitnessRefusal::EvmAnchorNotFinal { .. })
                if Instant::now() < deadline =>
            {
                log.l(format!(
                    "evaluate attempt {attempt} at {}: {refusal} (retryable); retry in 60 s",
                    utc()
                ));
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
            _ => {
                let outcome = match &res {
                    Ok(_) => "Ok".to_string(),
                    Err(refusal) => format!("Err({refusal:?})"),
                };
                log.l(format!(
                    "evaluate attempt {attempt} at {}: {outcome}",
                    utc()
                ));
                return Ok(res);
            }
        }
    }
}

// ---- step 1 ----------------------------------------------------------------------------------

async fn step1(ctx: &Ctx) -> StepLog {
    let mut log = StepLog::new(
        1,
        "seal a Folder of three members through the aggregator (prepare, submit S, pull both witnesses, evaluate, finish)",
        &ctx.header,
    );
    if let Err(e) = step1_inner(ctx, &mut log).await {
        log.check(false, format!("harness error: {e:#}"), "harness error");
    }
    log
}

async fn step1_inner(ctx: &Ctx, log: &mut StepLog) -> Result<()> {
    let st = &ctx.state;
    log.l(format!("run.json = {}", st.meta));
    log.l(format!("set (Folder genesis) = {}", st.set));
    for (i, t) in st.tips.iter().enumerate() {
        log.l(format!(
            "member m{} tip (spine().last()) = {t}; seal-1 leaf = {}",
            i + 1,
            hex_digest(&st.leaves[0][i])
        ));
    }
    log.l(format!(
        "head1 = {:?} root {}",
        st.heads[0],
        hex_digest(st.heads[0].root())
    ));
    let req = WitnessRequirement::open_witness();
    log.l(format!(
        "requirement (serde) = {}",
        serde_json::to_string(&req)?
    ));
    let mut witnesses = Vec::new();
    for (file, key, method) in [
        ("s1-evm.json", "s1_evm", WitnessMethod::Evm),
        ("s1-qtsa.json", "s1_qtsa", WitnessMethod::Qtsa),
    ] {
        let fetch = fetch_status(ctx, key);
        log.l(format!("fetch {key}: {fetch}"));
        if !log.check(
            fetch["status"] == 200,
            format!("{key} served with HTTP 200"),
            "anchor missing",
        ) {
            continue;
        }
        if let Some(w) = served_witness(log, key, method, &ctx.store.read(file)?)? {
            witnesses.push(w);
        }
    }
    if witnesses.len() != 2 {
        log.l("not evaluated: a witness is missing");
        return Ok(());
    }
    let prepared = load_prepared(ctx, 1)?;
    log.l("prepared seal 1 re-read from prepared-seal-1.json (the stored two-step)");
    let prepared_head = prepared.head().map_err(|e| anyhow!("{e}"))?;
    log.check(
        prepared_head == st.heads[0],
        "prepared-seal-1 head equals SealHead::from_leaves(set, leaves1)",
        "refusal (prepared state)",
    );
    let submitter = st.meta["post_body"]["submitter_did"].as_str().unwrap_or("");
    log.check(
        submitter == st.did,
        format!(
            "the server's submitter_did {submitter:?} is S's signer {}",
            st.did
        ),
        "refusal (prepared state)",
    );
    let res = evaluate_with_retry(
        log,
        &ctx.reader,
        Evaluation {
            prepared: &prepared,
            head: &st.heads[0],
            did: &st.did,
            witnesses: &witnesses,
            requirement: &req,
            budget: ctx.finality_budget,
        },
    )
    .await?;
    let accepted = match res {
        Ok(a) => a,
        Err(r) => {
            let debug = format!("{r:?}");
            let variant = debug.split([' ', '{', '(']).next().unwrap_or("");
            log.check(
                false,
                format!("evaluate_seal_witnesses refused: {r} ({r:?})"),
                &format!("refusal {variant}"),
            );
            return Ok(());
        }
    };
    log.check(true, "evaluate_seal_witnesses returned Ok", "refusal");
    log.l(format!(
        "accepted anchor = {}; witnesses = {:?}",
        accepted.anchor(),
        accepted.witnesses()
    ));
    let n_accepted = accepted.witnesses().len();
    log.check(
        n_accepted == 2,
        format!("accepted.witnesses().len() == 2 (got {n_accepted})"),
        "anchor missing",
    );
    let kinds: BTreeSet<AnchorKind> = accepted.witnesses().iter().map(|w| w.kind()).collect();
    log.check(
        kinds == BTreeSet::from([AnchorKind::Evm, AnchorKind::Tsa]),
        format!("kinds = {kinds:?}"),
        "anchor missing",
    );
    for w in accepted.witnesses() {
        log.check(
            w.attester() == Some(st.server_did.as_str()),
            format!(
                "{:?} witness {} attester = {:?} (server_did {})",
                w.kind(),
                w.timestamp(),
                w.attester(),
                st.server_did
            ),
            "refusal (attester)",
        );
    }
    let out = finish_seal(prepared, accepted).map_err(|e| anyhow!("finish_seal: {e}"))?;
    let n = out.container.revisions.len();
    log.check(
        n == 6,
        format!("container has {n} revisions (G, H, S, T x2, A expected 6)"),
        "refusal (container shape)",
    );
    let container = serde_json::to_string(&out.container)?;
    let attestations = out.attestations.to_canonical_json()?;
    ctx.store.artifact(CONTAINER_1, &container)?;
    ctx.store.artifact(ATTESTATIONS_1, &attestations)?;
    log.l(format!(
        "persisted {CONTAINER_1} ({} bytes) and {ATTESTATIONS_1} ({} bytes)",
        container.len(),
        attestations.len()
    ));
    for (k, r) in &out.container.revisions {
        log.l(format!(
            "container-1 revision {k} {}",
            serde_json::to_value(r)?
                .get("revision_type")
                .cloned()
                .unwrap_or(Value::Null)
        ));
    }
    Ok(())
}

// ---- step 2 ----------------------------------------------------------------------------------

/// Step 2's reading, for step 5's fresh-read compare.
pub struct Step2Out {
    seal: VerifiedSeal,
    stable: String,
}

async fn step2(ctx: &Ctx) -> (StepLog, Option<Step2Out>) {
    let mut log = StepLog::new(
        2,
        "verify the container and the full-set check under the pinned reader policy P2",
        &ctx.header,
    );
    match step2_inner(ctx, &mut log).await {
        Ok(out) => (log, out),
        Err(e) => {
            log.check(false, format!("harness error: {e:#}"), "harness error");
            (log, None)
        }
    }
}

async fn step2_inner(ctx: &Ctx, log: &mut StepLog) -> Result<Option<Step2Out>> {
    let st = &ctx.state;
    let policy = &ctx.reader.policy;
    log.l(format!(
        "reader policy = {}",
        policy.describe("P2", true, &st.server_did)
    ));
    log.l(format!(
        "catalogue kind = {:?}, source = {}",
        policy.catalogue().kind(),
        policy.catalogue().source()
    ));
    let container = match load_container(ctx) {
        Ok(c) => c,
        Err(e) => {
            log.check(
                false,
                format!("{CONTAINER_1} exists (from step 1): {e:#}"),
                "partially_verified (no container from step 1)",
            );
            return Ok(None);
        }
    };
    let reading = verify(&ctx.reader, &container, policy.dual()).await?;
    let admitted_members = members(ctx).await?;
    let seal = match &reading {
        SealReading::Seal(s) => s.clone(),
        SealReading::Rejected(r) => {
            log.check(
                false,
                format!("container read as a seal (rejected: {r})"),
                "partially_verified",
            );
            let v = full_set_check(&package_of(reading, admitted_members, Vec::new()));
            log_verdict(log, "P2", &v);
            return Ok(None);
        }
        _ => bail!("unknown SealReading variant"),
    };
    log_seal(log, ctx, "step2-P2", &seal);
    let receipts = receipts_for(
        seal.anchor(),
        &st.heads[0],
        &st.leaves[0],
        &st.tips,
        &st.nonces[0],
    )?;
    for (i, r) in receipts.iter().enumerate() {
        ctx.store.derived(
            log,
            &format!("receipts-1/m{}.json", i + 1),
            r.to_json_string() + "\n",
            "partially_verified (receipt differs)",
        )?;
    }
    let v = full_set_check(&package_of(reading, admitted_members, receipts));
    log_verdict(log, "P2", &v);

    log.check(
        seal.status() == SealStatus::Verified,
        format!("seal.status() == Verified (got {:?})", seal.status()),
        "partially_verified",
    );
    log.check(
        seal.sealer_signature().is_admitted(),
        format!(
            "sealer_signature().is_admitted() (catalogue kind {:?})",
            policy.catalogue().kind()
        ),
        "partially_verified",
    );
    let wa = seal.witness_acceptance();
    let admitted = wa
        .witnesses
        .iter()
        .filter(|w| w.admission == WitnessAdmission::Admitted)
        .count();
    log.check(
        wa.witnesses.len() == 2 && admitted == 2,
        format!(
            "witness_acceptance().witnesses: {} readings, {admitted} Admitted (want 2 and 2)",
            wa.witnesses.len()
        ),
        "partially_verified",
    );
    for w in &wa.witnesses {
        log.l(format!(
            "witness {} descriptor {} admission {:?} timestamp {} provenance {:?}",
            w.witness, w.descriptor, w.admission, w.timestamp, w.provenance
        ));
    }
    let time_ok =
        matches!(seal.time(), SealTime::Accepted { witnesses, .. } if witnesses.len() == 2);
    log.check(
        time_ok,
        format!(
            "time is SealTime::Accepted with 2 witnesses ({:?})",
            seal.time()
        ),
        "partially_verified",
    );
    log.check(
        v.set_headline == Headline::Verified,
        format!("set_headline == verified (got {})", v.set_headline.as_str()),
        "partially_verified",
    );
    log.check(
        v.completeness == DimensionState::Pass
            && v.integrity == DimensionState::Pass
            && v.non_suppression == DimensionState::Pass,
        "completeness, integrity, non_suppression all pass",
        "partially_verified",
    );
    let extra = v.findings.iter().any(|f| f.code == "seal_extra_revisions");
    log.check(
        !extra,
        "no seal_extra_revisions finding",
        "seal_extra_revisions",
    );

    let doc = ctx.store.read(ATTESTATIONS_1)?;
    for (basis, pins) in [
        (AttestationBasis::Unpinned, BTreeSet::new()),
        (
            AttestationBasis::Pinned,
            BTreeSet::from([st.server_did.clone()]),
        ),
    ] {
        let r = read_seal_attestations(&seal, Some(&doc), &pins);
        log_attestations(log, &format!("P2 pins {pins:?}"), &r);
        log.check(
            r.witnesses.len() == 2,
            format!("attestation reading has 2 witnesses (pins {pins:?})"),
            "no attester",
        );
        for w in &r.witnesses {
            let ok = w.attestations.len() == 1
                && w.attestations[0].verdict
                    == AttestationVerdict::Verified {
                        attester: st.server_did.clone(),
                        signature_type: policy.sealer_signature_type.clone(),
                        basis,
                    };
            log.check(
                ok,
                format!(
                    "witness {}: one attestation Verified{{attester {}, {}, basis {basis:?}}}",
                    w.witness, st.server_did, policy.sealer_signature_type
                ),
                "no attester",
            );
        }
        log.check(
            r.unmatched.is_empty() && r.findings.is_empty() && r.rejected.is_none(),
            "unmatched empty, findings empty, rejected None",
            "no attester",
        );
    }
    match &ctx.expect_server_did {
        Some(want) => {
            log.check(
                st.server_did == *want,
                format!(
                    "server_did from /.well-known/aqua-identity = {} equals --expect-server-did {want}",
                    st.server_did
                ),
                "no attester",
            );
        }
        None => log.l(format!(
            "server_did from /.well-known/aqua-identity = {}, no --expect-server-did given",
            st.server_did
        )),
    }
    let stable = stable(&seal);
    Ok(Some(Step2Out { seal, stable }))
}

// ---- step 3 ----------------------------------------------------------------------------------

async fn step3(ctx: &Ctx) -> StepLog {
    let mut log = StepLog::new(
        3,
        "the same container under a reader policy that admits qTSA only (P3)",
        &ctx.header,
    );
    if let Err(e) = step3_inner(ctx, &mut log).await {
        log.check(false, format!("harness error: {e:#}"), "harness error");
    }
    log
}

async fn step3_inner(ctx: &Ctx, log: &mut StepLog) -> Result<()> {
    let st = &ctx.state;
    let policy = &ctx.reader.policy;
    log.l(format!(
        "reader policy = {}",
        policy.describe("P3", false, &st.server_did)
    ));
    let container = match load_container(ctx) {
        Ok(c) => c,
        Err(e) => {
            log.check(
                false,
                format!("{CONTAINER_1} exists (from step 1): {e:#}"),
                "below verified (no container from step 1)",
            );
            return Ok(());
        }
    };
    let t_qtsa = load_pair(&ctx.store, "s1-qtsa.json", WitnessMethod::Qtsa)?;
    let t_evm = load_pair(&ctx.store, "s1-evm.json", WitnessMethod::Evm)?;
    let reading = verify(&ctx.reader, &container, policy.tsa_only()).await?;
    let admitted_members = members(ctx).await?;
    let SealReading::Seal(seal) = &reading else {
        log.check(false, "container read as a seal", "below verified");
        return Ok(());
    };
    let seal = seal.clone();
    log_seal(log, ctx, "step3-P3", &seal);
    let receipts = receipts_for(
        seal.anchor(),
        &st.heads[0],
        &st.leaves[0],
        &st.tips,
        &st.nonces[0],
    )?;
    let v = full_set_check(&package_of(reading, admitted_members, receipts));
    log_verdict(log, "P3", &v);
    log.check(
        seal.status() == SealStatus::Verified,
        format!("seal.status() == Verified (got {:?})", seal.status()),
        "below verified",
    );
    let tq: RevisionLink = t_qtsa
        .fetched
        .object_key
        .parse()
        .map_err(|e| anyhow!("{e:?}"))?;
    let te: RevisionLink = t_evm
        .fetched
        .object_key
        .parse()
        .map_err(|e| anyhow!("{e:?}"))?;
    let adm_q = admission_of(&seal, &tq).cloned();
    let adm_e = admission_of(&seal, &te).cloned();
    log.check(
        adm_q == Some(WitnessAdmission::Admitted),
        format!("TSA witness {tq} Admitted (got {adm_q:?})"),
        "below verified",
    );
    log.check(
        matches!(adm_e, Some(WitnessAdmission::NotAdmitted(_))),
        format!("EVM witness {te} NotAdmitted (got {adm_e:?})"),
        "below verified",
    );
    let findings = seal.witness_acceptance().findings();
    let listed = findings
        .iter()
        .any(|x| x.first().map(String::as_str) == Some("trust_input_not_admitted"));
    log.check(
        listed,
        format!("finding trust_input_not_admitted listed in the witness findings {findings:?}"),
        "below verified",
    );
    let in_set = v
        .findings
        .iter()
        .any(|x| x.code == "trust_input_not_admitted");
    log.l(format!(
        "trust_input_not_admitted also in full_set findings: {in_set}"
    ));
    log.check(
        v.set_headline == Headline::Verified,
        format!("set_headline == verified (got {})", v.set_headline.as_str()),
        "below verified",
    );
    Ok(())
}

// ---- step 4 ----------------------------------------------------------------------------------

async fn step4(ctx: &Ctx) -> StepLog {
    let mut log = StepLog::new(
        4,
        "seal the Folder with EVM opted out (qTSA only); a build with no timestamp is refused",
        &ctx.header,
    );
    if let Err(e) = step4a(ctx, &mut log).await {
        log.check(false, format!("harness error (4a): {e:#}"), "harness error");
    }
    if let Err(e) = step4b(ctx, &mut log).await {
        log.check(false, format!("harness error (4b): {e:#}"), "harness error");
    }
    log
}

async fn step4a(ctx: &Ctx, log: &mut StepLog) -> Result<()> {
    let st = &ctx.state;
    let policy = &ctx.reader.policy;
    log.l("--- 4a: seal 2, qTSA only");
    let req = WitnessRequirement::open_witness().without_evm();
    log.l(format!(
        "requirement (serde) = {}",
        serde_json::to_string(&req)?
    ));
    log.l(format!(
        "reader policy = {}",
        policy.describe("P3", false, &st.server_did)
    ));
    let fetch = fetch_status(ctx, "s2_qtsa");
    log.l(format!("fetch s2_qtsa: {fetch}"));
    let pair = match load_pair(&ctx.store, "s2-qtsa.json", WitnessMethod::Qtsa) {
        Ok(p) => p,
        Err(e) => {
            log.check(
                false,
                format!("s2 qTSA witness: {e:#}"),
                "seal 2 not built (witness missing)",
            );
            return Ok(());
        }
    };
    log.l(format!(
        "s2_qtsa: T {} P {}",
        pair.fetched.object_key, pair.fetched.signature_key
    ));
    let prepared = load_prepared(ctx, 2)?;
    let witnesses = [SealWitness::new(pair.object, Some(pair.signature))];
    let res = evaluate_with_retry(
        log,
        &ctx.reader,
        Evaluation {
            prepared: &prepared,
            head: &st.heads[1],
            did: &st.did,
            witnesses: &witnesses,
            requirement: &req,
            budget: Duration::ZERO,
        },
    )
    .await?;
    let accepted = match res {
        Ok(a) => a,
        Err(r) => {
            log.check(
                false,
                format!("seal 2 evaluate refused: {r} ({r:?})"),
                "seal 2 not built (refusal)",
            );
            return Ok(());
        }
    };
    let kinds: Vec<AnchorKind> = accepted.witnesses().iter().map(|w| w.kind()).collect();
    log.l(format!(
        "seal 2 accepted witnesses = {:?}",
        accepted.witnesses()
    ));
    const NOT_ONE: &str = "seal 2 not exactly one qTSA T";
    log.check(
        kinds == vec![AnchorKind::Tsa],
        format!("seal 2 accepted kinds = {kinds:?} (exactly one, Tsa)"),
        NOT_ONE,
    );
    let out = finish_seal(prepared, accepted).map_err(|e| anyhow!("finish_seal: {e}"))?;
    let n = out.container.revisions.len();
    log.check(
        n == 5,
        format!("container 2 has {n} revisions (G, H, S, T, A expected 5)"),
        NOT_ONE,
    );
    const DIFFERS: &str = "seal 2 differs from the persisted run";
    ctx.store.derived(
        log,
        "container-2.json",
        serde_json::to_string(&out.container)?,
        DIFFERS,
    )?;
    ctx.store.derived(
        log,
        "attestations-2.json",
        out.attestations.to_canonical_json()?,
        DIFFERS,
    )?;
    let reading = verify(&ctx.reader, &out.container, policy.tsa_only()).await?;
    let admitted_members = members(ctx).await?;
    let SealReading::Seal(seal) = &reading else {
        log.check(false, "container 2 read as a seal", "seal 2 below verified");
        return Ok(());
    };
    let seal = seal.clone();
    log_seal(log, ctx, "step4a-P3", &seal);
    log.check(
        seal.witnesses().len() == 1,
        format!("seal 2 links exactly one T ({:?})", seal.witnesses()),
        NOT_ONE,
    );
    let receipts = receipts_for(
        seal.anchor(),
        &st.heads[1],
        &st.leaves[1],
        &st.tips,
        &st.nonces[1],
    )?;
    for (i, r) in receipts.iter().enumerate() {
        ctx.store.derived(
            log,
            &format!("receipts-2/m{}.json", i + 1),
            r.to_json_string() + "\n",
            DIFFERS,
        )?;
    }
    let v = full_set_check(&package_of(reading, admitted_members, receipts));
    log_verdict(log, "seal2 P3", &v);
    log.check(
        seal.status() == SealStatus::Verified,
        format!("seal 2 status == Verified (got {:?})", seal.status()),
        "seal 2 below verified",
    );
    log.check(
        v.set_headline == Headline::Verified,
        format!(
            "seal 2 set_headline == verified (got {})",
            v.set_headline.as_str()
        ),
        "seal 2 below verified",
    );
    Ok(())
}

async fn step4b(ctx: &Ctx, log: &mut StepLog) -> Result<()> {
    let st = &ctx.state;
    log.l("--- 4b: refusal probes (a container file is written under step4b/ only on Ok)");
    ctx.store.ensure_dir("step4b")?;
    const FALS: &str = "a seal without T is written";
    let p1 = WitnessRequirement::kinds([], AttestationRule::IfPresent);
    log.l(format!(
        "probe 1 WitnessRequirement::kinds([], IfPresent) = {p1:?}"
    ));
    log.check(
        matches!(p1, Err(SealError::NoWitness)),
        "probe 1 is Err(SealError::NoWitness)",
        FALS,
    );
    let p2 = serde_json::from_str::<WitnessRequirement>(
        r#"{"kinds":[],"tsa_minimum":"none","attestation":"if_present"}"#,
    );
    log.l(format!(
        "probe 2 serde {{\"kinds\":[],\"tsa_minimum\":\"none\",\"attestation\":\"if_present\"}} = {p2:?}"
    ));
    log.check(p2.is_err(), "probe 2 serde form refused", FALS);
    let prepared = load_prepared(ctx, 2)?;
    let (aq, h, d) = (ctx.reader.aq.clone(), st.heads[1].clone(), st.did.clone());
    let p3 = blocking(move || {
        evaluate_seal_witnesses(
            &aq,
            &prepared,
            &h,
            &d,
            &[],
            &WitnessRequirement::open_witness().without_evm(),
        )
    })
    .await?;
    let shown = match &p3 {
        Ok(_) => "Ok(..)".to_string(),
        Err(e) => format!("Err({e:?})"),
    };
    log.l(format!(
        "probe 3 evaluate_seal_witnesses(.., &[], open_witness().without_evm()) = {shown}"
    ));
    log.check(
        matches!(p3, Err(WitnessRefusal::NoWitness)),
        "probe 3 is Err(WitnessRefusal::NoWitness)",
        FALS,
    );
    // Probe 4: the one-shot with no provider over a fresh head. The refusal has nothing to do
    // with who signs, so a throwaway in-memory key signs: the steps hold no key of the run.
    let mut leaves = Vec::new();
    for t in &st.tips {
        let mut n = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut n);
        leaves.push(shielded_leaf(t, &n).map_err(|e| anyhow!("{e}"))?);
    }
    let head2b = SealHead::from_leaves(st.set.clone(), &leaves).map_err(|e| anyhow!("{e}"))?;
    let mut throwaway = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut throwaway);
    let signer = SigningCredentials::Secp256k1 {
        secp256k1_key: throwaway.to_vec(),
    };
    let p4 = build_seal_container(
        &ctx.reader.aq,
        &head2b,
        &signer,
        &[],
        &WitnessRequirement::open_witness().without_evm(),
    )
    .await;
    match &p4 {
        Ok(out) => {
            ctx.store.artifact(
                "step4b/container-probe4.json",
                serde_json::to_string(&out.container)?,
            )?;
            log.l("probe 4 build_seal_container returned Ok: container written to step4b/container-probe4.json");
        }
        Err(e) => log.l(format!(
            "probe 4 build_seal_container(.., providers [], open_witness().without_evm()) = Err({e:?})"
        )),
    }
    log.check(
        matches!(p4, Err(SealError::Refused(WitnessRefusal::NoWitness))),
        "probe 4 is Err(SealError::Refused(NoWitness))",
        FALS,
    );
    let files = ctx.store.list("step4b")?;
    log.check(
        files.is_empty(),
        format!("step4b/ holds no container ({files:?})"),
        FALS,
    );
    Ok(())
}

// ---- step 5 ----------------------------------------------------------------------------------

async fn step5(ctx: &Ctx, s2: Option<&Step2Out>) -> StepLog {
    let mut log = StepLog::new(
        5,
        "tamper: one byte of the qTSA token changed (relinked); the attestation P removed or altered (Q16 default)",
        &ctx.header,
    );
    if let Err(e) = step5a(ctx, &mut log).await {
        log.check(false, format!("harness error (5a): {e:#}"), "harness error");
    }
    if let Err(e) = step5b(ctx, &mut log, s2).await {
        log.check(false, format!("harness error (5b): {e:#}"), "harness error");
    }
    log
}

async fn step5a(ctx: &Ctx, log: &mut StepLog) -> Result<()> {
    let st = &ctx.state;
    let policy = &ctx.reader.policy;
    log.l("--- 5a: relinked qTSA tamper, read with P2");
    log.l(format!(
        "reader policy = {}",
        policy.describe("P2", true, &st.server_did)
    ));
    let c1 = match load_container(ctx) {
        Ok(c) => c,
        Err(e) => {
            log.check(
                false,
                format!("{CONTAINER_1} exists (from step 1): {e:#}"),
                "verified (no container from step 1)",
            );
            return Ok(());
        }
    };
    let tq: RevisionLink = load_pair(&ctx.store, "s1-qtsa.json", WitnessMethod::Qtsa)?
        .fetched
        .object_key
        .parse()
        .map_err(|e| anyhow!("{e:?}"))?;
    let te: RevisionLink = load_pair(&ctx.store, "s1-evm.json", WitnessMethod::Evm)?
        .fetched
        .object_key
        .parse()
        .map_err(|e| anyhow!("{e:?}"))?;
    let (a_key, a_rev) = c1
        .revisions
        .iter()
        .find(|(_, r)| matches!(r, AnyRevision::Anchor(_)))
        .map(|(k, r)| (k.clone(), r.clone()))
        .ok_or_else(|| anyhow!("no A in container 1"))?;
    let a_json = serde_json::to_value(&a_rev)?;
    let method: Method = serde_json::from_value(a_json["method"].clone())?;
    let head_link: RevisionLink = serde_json::from_value(a_json["previous_revision"].clone())?;
    let t = c1
        .revisions
        .get(&tq)
        .ok_or_else(|| anyhow!("qTSA T not in container 1"))?;
    let (t2, note) = flip_tsa_token(t)?;
    log.l(format!("flip: {note}"));
    let t2_link = link_of(&t2)?;
    log.l(format!(
        "T {tq} -> T' {t2_link} (SDK global_calculate_hash)"
    ));
    let mut links = vec![te.clone(), t2_link.clone()];
    links.sort();
    let mut a2 = Anchor::new(head_link.clone(), method, links.clone());
    let a2_link = a2
        .calculate_link(HashType::Sha3_256)
        .map_err(|e| anyhow!("{e:?}"))?;
    a2.populate_leaves(HashType::Sha3_256)
        .map_err(|e| anyhow!("{e:?}"))?;
    log.l(format!(
        "A {a_key} -> A' {a2_link} = Anchor::new(H {head_link}, method {method:?}, sorted {links:?}), calculate_link then populate_leaves"
    ));
    let mut c5 = c1.clone();
    c5.revisions.remove(&tq);
    c5.revisions.remove(&a_key);
    c5.revisions.insert(t2_link.clone(), t2.clone());
    c5.revisions
        .insert(a2_link.clone(), AnyRevision::Anchor(a2));
    ctx.store
        .artifact("container-5a.json", serde_json::to_string(&c5)?)?;
    log.l(format!(
        "container' = G, H, S, T_evm, T', A' ({} revisions), written as container-5a.json",
        c5.revisions.len()
    ));

    let reading = verify(&ctx.reader, &c5, policy.dual()).await?;
    let admitted_members = members(ctx).await?;
    const FALS: &str = "Q16 default: a reading is verified or pass, or a dimension is fail";
    let seal = match &reading {
        SealReading::Seal(s) => Some(s.clone()),
        SealReading::Rejected(r) => {
            log.l(format!("container' rejected: {r}"));
            None
        }
        _ => None,
    };
    let receipts = receipts_for(
        &a2_link,
        &st.heads[0],
        &st.leaves[0],
        &st.tips,
        &st.nonces[0],
    )?;
    let v = full_set_check(&package_of(reading, admitted_members, receipts));
    log_verdict(log, "5a P2", &v);
    let Some(seal) = seal else {
        log.check(
            false,
            "container' read as a seal (needed for the witness reading)",
            FALS,
        );
        return Ok(());
    };
    log_seal(log, ctx, "step5a-P2", &seal);
    let adm = admission_of(&seal, &t2_link).cloned();
    let failed_ok = matches!(&adm, Some(WitnessAdmission::Failed(r)) if !r.is_empty());
    log.check(
        failed_ok,
        format!("TSA witness T' reads WitnessAdmission::Failed(reason) with a non-empty reason (got {adm:?})"),
        "witness not Failed with a reason",
    );
    log.check(
        seal.status() == SealStatus::NotChecked,
        format!("per-seal status NotChecked (got {:?})", seal.status()),
        FALS,
    );
    log.check(
        v.integrity == DimensionState::NotChecked,
        format!("set integrity not_checked (got {})", v.integrity.as_str()),
        FALS,
    );
    let want_args = vec![a2_link.to_string(), t2_link.to_string()];
    let swf = v
        .findings
        .iter()
        .any(|f| f.code == "seal_witness_failed" && f.args == want_args);
    log.check(
        swf,
        format!("finding seal_witness_failed({a2_link}, {t2_link})"),
        FALS,
    );
    let ho = handover_check_seal(&seal, &st.did);
    log.l(format!(
        "handover_check_seal(seal', {}) = {:?}",
        st.did, ho.verdict
    ));
    log.check(!ho.verdict.is_pass(), "hand-over not pass", FALS);
    log.check(
        v.set_headline == Headline::PartiallyVerified,
        format!(
            "set_headline == partially_verified (got {})",
            v.set_headline.as_str()
        ),
        FALS,
    );
    log.check(
        v.completeness != DimensionState::Fail && v.non_suppression != DimensionState::Fail,
        format!(
            "completeness ({}) and non_suppression ({}) not fail",
            v.completeness.as_str(),
            v.non_suppression.as_str()
        ),
        FALS,
    );
    log.check(
        seal.status() != SealStatus::Verified && v.set_headline != Headline::Verified,
        "not verified",
        "verified",
    );

    log.l("--- 5a2 (record): in-place flip under the old key, A unchanged");
    let mut c5b = c1.clone();
    c5b.revisions.insert(tq.clone(), t2);
    ctx.store
        .artifact("container-5a2.json", serde_json::to_string(&c5b)?)?;
    let r2 = verify(&ctx.reader, &c5b, policy.dual()).await?;
    let admitted_members = members(ctx).await?;
    let st2 = r2.status();
    let shown = match &r2 {
        SealReading::Seal(s) => format!(
            "seal, status {:?}, acceptance {:?}",
            s.status(),
            s.witness_acceptance()
        ),
        SealReading::Rejected(r) => format!("rejected: {r}"),
        _ => "unknown SealReading variant".to_string(),
    };
    log.l(format!("5a2 reading: {shown}"));
    let receipts = receipts_for(&a_key, &st.heads[0], &st.leaves[0], &st.tips, &st.nonces[0])?;
    let v2 = full_set_check(&package_of(r2, admitted_members, receipts));
    log_verdict(log, "5a2 P2", &v2);
    log.check(
        st2 != SealStatus::Verified && v2.set_headline != Headline::Verified,
        format!(
            "5a2 not verified (status {st2:?}, headline {})",
            v2.set_headline.as_str()
        ),
        "verified",
    );
    Ok(())
}

/// The re-keyed variant's reading of the tampered witness: it reached the signature check and
/// named nobody. `Err` carries the reason for the assertion line.
pub fn rekeyed_reading_ok(
    r: &SealAttestationsReading,
    t: &RevisionLink,
    new_key: &RevisionLink,
) -> std::result::Result<String, String> {
    let Some(witness) = r.witnesses.iter().find(|w| &w.witness == t) else {
        return Err(format!("no reading for witness {t}"));
    };
    let [one] = witness.attestations.as_slice() else {
        return Err(format!(
            "expected one attestation over {t}, got {:?}",
            witness.attestations
        ));
    };
    if &one.attestation != new_key {
        return Err(format!(
            "read P {} is not the re-keyed {new_key}",
            one.attestation
        ));
    }
    match &one.verdict {
        AttestationVerdict::Verified { attester, .. } => {
            Err(format!("Verified with attester {attester}"))
        }
        AttestationVerdict::Unverifiable { cause } if cause == "not_addressed" => {
            Err("stopped at addressing: the signature check did not run".to_string())
        }
        AttestationVerdict::Unverifiable { cause } if cause.contains("did:") => {
            Err(format!("a DID in the cause: {cause}"))
        }
        AttestationVerdict::Unverifiable { cause } => {
            if format!("{witness:?}").contains("did:") {
                return Err(format!("a DID in the witness reading: {witness:?}"));
            }
            Ok(cause.clone())
        }
    }
}

async fn step5b(ctx: &Ctx, log: &mut StepLog, s2: Option<&Step2Out>) -> Result<()> {
    let st = &ctx.state;
    log.l("--- 5b: attestation document of seal 1, qTSA P removed / altered (Q16 default)");
    const FALS: &str =
        "an attester DID is reported for a removed or altered P, or the seal reading changes";
    let Some(s2) = s2 else {
        log.check(false, "step 2 seal reading available", FALS);
        return Ok(());
    };
    let seal = &s2.seal;
    let doc: Value = serde_json::from_str(&ctx.store.read(ATTESTATIONS_1)?)?;
    let qtsa = load_pair(&ctx.store, "s1-qtsa.json", WitnessMethod::Qtsa)?;
    let tq: RevisionLink = qtsa
        .fetched
        .object_key
        .parse()
        .map_err(|e| anyhow!("{e:?}"))?;
    let pq = qtsa.fetched.signature_key.clone();
    if doc["revisions"].get(&pq).is_none() {
        log.check(false, format!("qTSA P {pq} is in {ATTESTATIONS_1}"), FALS);
        return Ok(());
    }

    let removed_s = remove_p(&doc, &pq)?.to_string();
    ctx.store
        .artifact("attestations-5b-removed.json", &removed_s)?;
    let (altered, note) = alter_p_key_kept(&doc, &pq)?;
    let altered_s = altered.to_string();
    ctx.store
        .artifact("attestations-5b-altered.json", &altered_s)?;
    let alone_s = only_p(&altered, &pq)?.to_string();
    ctx.store
        .artifact("attestations-5b-altered-alone.json", &alone_s)?;
    log.l(format!("qTSA T {tq}, its P {pq}; {note}"));

    let rekeyed = rekey_bad_signature(&doc, &pq)?;
    let rekeyed_s = rekeyed.doc.to_string();
    ctx.store
        .artifact("attestations-5b-rekeyed.json", &rekeyed_s)?;
    let rekeyed_key = rekeyed.key.to_string();
    let rekeyed_alone_s = only_p(&rekeyed.doc, &rekeyed_key)?.to_string();
    ctx.store
        .artifact("attestations-5b-rekeyed-alone.json", &rekeyed_alone_s)?;
    log.l(format!(
        "re-keyed variant: {}, P {pq} -> P' {rekeyed_key} (SDK link of the altered P)",
        rekeyed.note
    ));

    for pins in [BTreeSet::new(), BTreeSet::from([st.server_did.clone()])] {
        let r = read_seal_attestations(seal, Some(&removed_s), &pins);
        log_attestations(log, &format!("removed, pins {pins:?}"), &r);
        let q = reading_of(&r, &tq);
        let ok = q.as_ref().map(|v| v.is_empty()).unwrap_or(true);
        log.check(
            ok,
            format!("removed: qTSA witness has no attestation and no attester (got {q:?})"),
            FALS,
        );

        let r = read_seal_attestations(seal, Some(&altered_s), &pins);
        log_attestations(log, &format!("altered, pins {pins:?}"), &r);
        let q = reading_of(&r, &tq).unwrap_or_default();
        let wq = r
            .witnesses
            .iter()
            .find(|w| w.witness == tq)
            .map(|w| format!("{w:?}"))
            .unwrap_or_default();
        let ok = q.len() == 1
            && matches!(&q[0], AttestationVerdict::Unverifiable { cause } if !cause.contains("did:"))
            && !wq.contains("did:");
        log.check(
            ok,
            format!("altered: qTSA witness reads Unverifiable{{cause}} with no did: in the cause or its reading (got {q:?})"),
            FALS,
        );
        let elsewhere = format!("{:?} {:?}", r.unmatched, r.findings);
        log.check(
            !elsewhere.contains("did:"),
            "altered: no did: in unmatched or findings",
            FALS,
        );

        let r = read_seal_attestations(seal, Some(&alone_s), &pins);
        log_attestations(log, &format!("altered alone, pins {pins:?}"), &r);
        let q = reading_of(&r, &tq).unwrap_or_default();
        let ok = q.len() == 1
            && matches!(&q[0], AttestationVerdict::Unverifiable { .. })
            && !format!("{r:?}").contains("did:");
        log.check(
            ok,
            "altered alone: Unverifiable and no did: anywhere in the reading",
            FALS,
        );

        let r = read_seal_attestations(seal, Some(&rekeyed_s), &pins);
        log_attestations(log, &format!("re-keyed, pins {pins:?}"), &r);
        let verdict = rekeyed_reading_ok(&r, &tq, &rekeyed.key);
        log.check(
            verdict.is_ok(),
            format!("re-keyed: addressed P with a bad signature is not Verified, the SDK ran the signature check, no attester ({verdict:?})"),
            FALS,
        );
        let r = read_seal_attestations(seal, Some(&rekeyed_alone_s), &pins);
        log_attestations(log, &format!("re-keyed alone, pins {pins:?}"), &r);
        let verdict = rekeyed_reading_ok(&r, &tq, &rekeyed.key);
        log.check(
            verdict.is_ok() && !format!("{r:?}").contains("did:"),
            format!("re-keyed alone: no did: anywhere in the reading ({verdict:?})"),
            FALS,
        );
    }
    let c1 = load_container(ctx)?;
    match verify(&ctx.reader, &c1, ctx.reader.policy.dual())
        .await?
        .into_seal()
    {
        Ok(again) => {
            let eq = stable(&again) == s2.stable;
            log.check(
                eq,
                "a fresh P2 read of container 1 is byte-equal to step 2 (stable form): the seal reading did not change",
                FALS,
            );
            if !eq {
                log.l(format!("step 2 stable: {}", s2.stable));
                log.l(format!("fresh stable : {}", stable(&again)));
            }
        }
        Err(r) => {
            log.check(
                false,
                format!("fresh P2 read of container 1 is a seal (rejected: {r})"),
                FALS,
            );
        }
    }
    Ok(())
}

// ---- step 6 ----------------------------------------------------------------------------------

async fn step6(ctx: &Ctx) -> StepLog {
    let mut log = StepLog::new(
        6,
        "one-shot and two-step builds give byte-identical containers for the same inputs",
        &ctx.header,
    );
    if let Err(e) = step6_inner(ctx, &mut log).await {
        log.check(false, format!("harness error: {e:#}"), "harness error");
    }
    log
}

async fn step6_inner(ctx: &Ctx, log: &mut StepLog) -> Result<()> {
    let st = &ctx.state;
    const FALS: &str = "any byte differs";
    log.l(format!(
        "--- 6a: gate 6a is the SDK's own test {GATE_6A_SDK_TEST}, run once at the pinned SDK tag; this crate does not copy it"
    ));
    log.l("--- 6b: complete_seal (the one-shot tail) on the persisted prepared state and witnesses vs step 1's stored two-step output");
    let (Ok(c1), Ok(a1)) = (
        ctx.store.read_bytes(CONTAINER_1),
        ctx.store.read_bytes(ATTESTATIONS_1),
    ) else {
        log.check(false, "step 1 output present", FALS);
        return Ok(());
    };
    let mut witnesses = Vec::new();
    for (file, method) in [
        ("s1-evm.json", WitnessMethod::Evm),
        ("s1-qtsa.json", WitnessMethod::Qtsa),
    ] {
        let pair = load_pair(&ctx.store, file, method)?;
        witnesses.push(SealWitness::new(pair.object, Some(pair.signature)));
    }
    let prepared = load_prepared(ctx, 1)?;
    let (aq, h, d) = (ctx.reader.aq.clone(), st.heads[0].clone(), st.did.clone());
    let out = blocking(move || {
        complete_seal(
            &aq,
            prepared,
            &h,
            &d,
            &witnesses,
            &WitnessRequirement::open_witness(),
        )
    })
    .await?;
    let out = match out {
        Ok(o) => o,
        Err(e) => {
            log.check(
                false,
                format!("complete_seal returned Ok (got {e:?})"),
                FALS,
            );
            return Ok(());
        }
    };
    let c6 = serde_json::to_string(&out.container)?;
    let a6 = out.attestations.to_canonical_json()?;
    ctx.store.artifact("container-6b.json", &c6)?;
    ctx.store.artifact("attestations-6b.json", &a6)?;
    log.check(
        c6.as_bytes() == c1.as_slice(),
        format!("container bytes equal ({} vs {} bytes)", c6.len(), c1.len()),
        FALS,
    );
    log.check(
        a6.as_bytes() == a1.as_slice(),
        format!(
            "attestation document bytes equal ({} vs {} bytes)",
            a6.len(),
            a1.len()
        ),
        FALS,
    );
    Ok(())
}

// ---- step 7 ----------------------------------------------------------------------------------

/// How much of an epoch the identity's witnesses cover: an identity reads only its own witnesses
/// of an epoch, so busier epochs are partially visible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairCoverage {
    /// The epoch holds only this identity's leaves: every pair of the epoch was read.
    Full { pairs: u64 },
    /// The epoch holds more leaves than this identity's: logged with both numbers, no failure.
    Partial { pairs: u64, leaf_count: u64 },
}

/// Step 7's pair logic, per witness method two (EVM and qTSA) per own leaf. Always: visible pairs
/// equal 2 x own leaves, and the epoch holds at least the own leaves. `Err` is the failure text.
pub fn pair_coverage(
    visible_pairs: u64,
    own_leaves: u64,
    leaf_count: u64,
) -> std::result::Result<PairCoverage, String> {
    let want = 2 * own_leaves;
    if visible_pairs != want {
        return Err(format!(
            "{visible_pairs} witness pairs visible, 2 x {own_leaves} own leaves = {want} expected"
        ));
    }
    if leaf_count < own_leaves {
        return Err(format!(
            "epoch lists leaf_count {leaf_count}, fewer than the {own_leaves} own leaves"
        ));
    }
    if leaf_count == own_leaves {
        return Ok(PairCoverage::Full {
            pairs: visible_pairs,
        });
    }
    Ok(PairCoverage::Partial {
        pairs: visible_pairs,
        leaf_count,
    })
}

async fn step7(ctx: &Ctx) -> StepLog {
    let mut log = StepLog::new(
        7,
        "no stub witness in the test leaf's epoch on the aggregator",
        &ctx.header,
    );
    if let Err(e) = step7_inner(ctx, &mut log) {
        log.check(false, format!("harness error: {e:#}"), "harness error");
    }
    log
}

fn step7_inner(ctx: &Ctx, log: &mut StepLog) -> Result<()> {
    const FALS: &str = "a stub served";
    let meta = &ctx.state.meta;
    let epoch = meta["epoch_id"]
        .as_u64()
        .ok_or_else(|| anyhow!("no epoch_id"))?;
    log.l(format!("epoch N = {epoch}"));
    log.l("The identity reads only its own witnesses of epoch N (other DIDs get 403 by design). All leaves of an epoch share one anchor outcome per method, so the own pairs show the epoch's EVM tx and TSA token; reading other DIDs' witnesses needs operator access.");
    let accepted = meta["post_body"]["accepted"].as_u64();
    log.check(
        accepted == Some(OWN_LEAVES),
        format!("the server accepted {accepted:?} leaves of this run ({OWN_LEAVES} submitted)"),
        FALS,
    );
    log.l(format!(
        "GET /v1/epochs?from={epoch}&limit=1: {}",
        fetch_status(ctx, "epochs")
    ));
    let epochs: Value = serde_json::from_str(&ctx.store.read(&epochs_file(epoch))?)?;
    log.l(format!("body: {epochs}"));
    let item = epochs["epochs"]
        .as_array()
        .and_then(|a| a.iter().find(|e| e["id"].as_u64() == Some(epoch)).cloned());
    let Some(item) = item else {
        log.check(false, format!("/v1/epochs lists epoch {epoch}"), FALS);
        return Ok(());
    };
    let root_txt = item["merkle_root"].as_str().unwrap_or("").to_string();
    let epoch_root =
        parse_batch_digest(&root_txt).map_err(|e| anyhow!("epoch merkle_root {root_txt}: {e}"))?;
    log.l(format!(
        "epoch {epoch} merkle_root = {root_txt} (leaf_count {})",
        item["leaf_count"]
    ));
    let mut pairs = 0u64;
    for m in [WitnessMethod::Evm, WitnessMethod::Qtsa] {
        let key = format!("epoch_{}", m.as_str());
        let fetch = fetch_status(ctx, &key);
        log.l(format!(
            "GET /trees?epoch={epoch}&method={}: {fetch}",
            m.as_str()
        ));
        log.check(
            fetch["status"] == 200,
            format!("{key}: HTTP 200 (not 410 / not verifiable)"),
            FALS,
        );
        let body: Value = serde_json::from_str(&ctx.store.read(&epoch_file(epoch, m))?)?;
        let revisions = body["revisions"].as_object().cloned().unwrap_or_default();
        for (k, r) in &revisions {
            let Some(p) = r.get("payloads") else { continue };
            pairs += 1;
            log.l(format!("{} T {k}: {}", m.as_str(), shorten_token(p)));
            let stub = detect_stub(m, p);
            log.check(
                stub.is_none(),
                format!("{} T {k}: detect_stub = {stub:?}", m.as_str()),
                FALS,
            );
            let mr = p["merkle_root"].as_str().unwrap_or("");
            let root = parse_batch_root(mr).map_err(|e| anyhow!("payload merkle_root {mr}: {e}"));
            let ok = matches!(&root, Ok(r) if *r == epoch_root);
            log.check(
                ok,
                format!(
                    "{} T {k}: payload merkle_root {mr} names epoch {epoch}'s root {root_txt} (SDK parse_batch_root vs parse_batch_digest, bytes compared)",
                    m.as_str()
                ),
                FALS,
            );
        }
    }
    let Some(leaf_count) = item["leaf_count"].as_u64() else {
        log.check(false, format!("epoch {epoch} lists a leaf_count"), FALS);
        return Ok(());
    };
    match pair_coverage(pairs, OWN_LEAVES, leaf_count) {
        Ok(PairCoverage::Full { pairs }) => {
            log.check(
                true,
                format!("{pairs} witness pairs read = 2 x leaf_count {leaf_count}: full coverage of epoch {epoch}"),
                FALS,
            );
        }
        Ok(PairCoverage::Partial { pairs, leaf_count }) => {
            log.check(
                true,
                format!("{pairs} witness pairs read = 2 x {OWN_LEAVES} own leaves"),
                FALS,
            );
            log.l(format!(
                "partial coverage of epoch {epoch}: {pairs} own pairs visible, leaf_count {leaf_count}; other DIDs' witnesses are not readable by this identity"
            ));
        }
        Err(why) => {
            log.check(false, why, FALS);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step7_equal_pairs_are_full_coverage() {
        assert_eq!(pair_coverage(4, 2, 2), Ok(PairCoverage::Full { pairs: 4 }));
    }

    #[test]
    fn step7_busier_epoch_is_partial_coverage_with_both_numbers_and_no_failure() {
        assert_eq!(
            pair_coverage(4, 2, 7),
            Ok(PairCoverage::Partial {
                pairs: 4,
                leaf_count: 7
            })
        );
    }

    #[test]
    fn step7_short_pairs_are_a_failure() {
        for (pairs, leaf_count) in [(3, 2), (3, 7), (0, 2), (5, 2), (8, 4)] {
            let err = pair_coverage(pairs, 2, leaf_count).expect_err("short or long is a failure");
            assert!(err.contains("expected"), "{err}");
        }
    }

    #[test]
    fn step7_an_epoch_with_fewer_leaves_than_ours_is_a_failure() {
        assert!(pair_coverage(4, 2, 1).is_err());
        assert!(pair_coverage(4, 2, 0).is_err());
    }

    #[test]
    fn only_the_confirmation_count_is_left_out_of_a_provenance() {
        assert_eq!(
            without_chain_head("sdk evm anchor verdict: chain 1 block 2 0xab confirmations 44463"),
            "sdk evm anchor verdict: chain 1 block 2 0xab"
        );
        for kept in [
            "sdk tsa token facts: policy 1.2 issuer CN=x",
            "confirmations 3",
            "x confirmations 3 and more",
            "",
        ] {
            assert_eq!(without_chain_head(kept), kept);
        }
    }

    #[test]
    fn step1_a_body_that_is_no_witness_fails_named_not_quietly() {
        let mut log = StepLog::new(1, "t", &[]);
        let got = served_witness(
            &mut log,
            "s1_evm",
            WitnessMethod::Evm,
            r#"{"revisions":{}}"#,
        )
        .expect("no harness error");
        assert!(got.is_none());
        assert!(!log.passed());
        assert!(
            log.verdict().contains("anchor missing"),
            "{}",
            log.verdict()
        );
    }
}
