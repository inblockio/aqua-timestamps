//! `seal` and `seal-replay` end to end, offline: the whole live part against an in-process
//! aggregator on localhost (sign-in, both leaves, seal, pull, persist), the seven steps over the
//! offline doubles, and the replay of what that run persisted. Nothing here leaves this machine.
//!
//! One run per test binary: the tests share it read-only.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aqua_rs_sdk::core::seal::{
    read_seal_attestations, verify_seal_container, AttestationVerdict, SealReading,
};
use aqua_rs_sdk::primitives::RevisionLink;
use aqua_rs_sdk::schema::tree::Tree;
use aqua_rs_sdk::schema::AnyRevision;
use aqua_timestamp_e2e::flow::{wait_for_seal, PollBudget, SealTrigger};
use aqua_timestamp_e2e::identity::for_base_url;
use aqua_timestamp_e2e::seal::live::{read_epoch_bodies, run_seal, SealConfig, SealReport};
use aqua_timestamp_e2e::seal::log::{all_passed, StepLog};
use aqua_timestamp_e2e::seal::policy::Reader;
use aqua_timestamp_e2e::seal::replay::{run_replay, ReplayConfig};
use aqua_timestamp_e2e::seal::run_dir::{verify_complete, RunState, Store, StoreMode};
use aqua_timestamp_e2e::seal::steps::{self, rekeyed_reading_ok, served_witness, Ctx, Steps};
use aqua_timestamp_e2e::seal::tamper::{
    alter_p_key_kept, link_of, rekey_bad_signature, relink_flipped_token,
};
use aqua_timestamp_e2e::selfcheck::run_seal_in_process;
use aqua_timestamp_e2e::witness::{ReaderHosts, WitnessMethod};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::OnceCell;

struct Run {
    /// Keeps the directories alive for the whole test binary.
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    identity: PathBuf,
    reader: Reader,
    hosts: ReaderHosts,
    logs: Vec<(u8, bool, String)>,
    version_before: String,
    version_after: String,
}

static RUN: OnceCell<Run> = OnceCell::const_new();

async fn run() -> &'static Run {
    RUN.get_or_init(|| async {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("run");
        let identity = tmp.path().join("identity");
        let done = run_seal_in_process(&dir, &identity)
            .await
            .expect("live part");
        for log in &done.report.logs {
            if !log.passed() {
                let fails: Vec<_> = log
                    .lines()
                    .iter()
                    .filter(|l| l.starts_with("ASSERT FAIL"))
                    .collect();
                eprintln!("{}: {fails:#?}", log.verdict());
            }
        }
        Run {
            dir,
            identity,
            logs: done
                .report
                .logs
                .iter()
                .map(|l| (l.number(), l.passed(), l.verdict()))
                .collect(),
            version_before: done.report.version_before.clone(),
            version_after: done.report.version_after.clone(),
            reader: done.reader,
            hosts: done.hosts,
            _tmp: tmp,
        }
    })
    .await
}

/// The server DID the in-process run persisted: the pin a replay of it takes.
fn pin(run: &Run) -> String {
    let identity: Value = serde_json::from_str(&read(&run.dir, "aqua-identity.json")).unwrap();
    identity["server_did"].as_str().unwrap().to_string()
}

fn read(dir: &Path, file: &str) -> String {
    std::fs::read_to_string(dir.join(file)).unwrap()
}

/// Every file under `dir`, relative path to bytes.
fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        for entry in std::fs::read_dir(&d).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                todo.push(path);
            } else {
                let rel = path.strip_prefix(dir).unwrap().to_path_buf();
                out.insert(rel, std::fs::read(&path).unwrap());
            }
        }
    }
    out
}

fn copy_tree(from: &Path, to: &Path) {
    for (rel, bytes) in snapshot(from) {
        let target = to.join(rel);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(target, bytes).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_seven_steps_pass_against_the_in_process_aggregator() {
    let run = run().await;
    let numbers: Vec<u8> = run.logs.iter().map(|l| l.0).collect();
    assert_eq!(numbers, vec![1, 2, 3, 4, 5, 6, 7]);
    for (_, passed, verdict) in &run.logs {
        assert!(*passed, "{verdict}");
    }
    assert_eq!(run.version_before, run.version_after);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_run_persists_its_whole_client_state_under_the_known_names() {
    let run = run().await;
    verify_complete(&run.dir).expect("a finished run is complete");
    let meta: Value = serde_json::from_str(&read(&run.dir, "run.json")).unwrap();
    let epoch = meta["epoch_id"].as_u64().unwrap();
    for file in [
        "aqua-identity.json",
        "attestations-1.json",
        "attestations-2.json",
        "attestations-5b-rekeyed.json",
        "attestations-5b-rekeyed-alone.json",
        "attestations-6b.json",
        "container-1.json",
        "container-2.json",
        "container-5a.json",
        "container-6b.json",
        "fetch-status.json",
        "leaves.json",
        "members/m1/files/m1.txt",
        "members/m3/tree.json",
        "nonces-1.json",
        "nonces-2.json",
        "prepared-seal-1.json",
        "prepared-seal-2.json",
        "receipts-1/m1.json",
        "receipts-2/m3.json",
        "run.json",
        "s1-evm.json",
        "s1-qtsa.json",
        "s2-qtsa.json",
        "set-folder.json",
        "step-1.log",
        "step-7.log",
        &format!("epochs-{epoch}.json"),
        &format!("epoch-{epoch}-evm.json"),
        &format!("epoch-{epoch}-qtsa.json"),
    ] {
        assert!(run.dir.join(file).is_file(), "{file}");
    }
    assert!(meta["server_version_after"].is_string());
    assert_eq!(meta["post_body"]["accepted"], 2);
    // No identity material beside the run: the key stays where it lives.
    let key = std::fs::read_to_string(run.identity.join("secp256k1.key")).unwrap();
    for (rel, bytes) in snapshot(&run.dir) {
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains(key.trim()), "{rel:?} holds the key");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn step_logs_hold_assertion_lines_a_verdict_and_step_6_names_the_sdk_gate() {
    let run = run().await;
    for n in 1..=7 {
        let log = read(&run.dir, &format!("step-{n}.log"));
        assert!(log.contains("ASSERT ok"), "step {n}");
        assert!(!log.contains("ASSERT FAIL"), "step {n}: {log}");
        assert!(
            log.trim_end().ends_with(&format!("STEP {n} PASS")),
            "step {n}"
        );
        assert!(log.contains("server /version after the run"), "step {n}");
        assert!(
            !log.contains("pending"),
            "step {n}: the closing line was rewritten"
        );
    }
    let six = read(&run.dir, "step-6.log");
    assert!(six.contains("sp2_e8_one_shot_and_two_step_byte_identical"));
    let seven = read(&run.dir, "step-7.log");
    assert!(seven.contains("full coverage"), "{seven}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_replay_passes_with_the_server_gone_and_leaves_the_run_untouched() {
    let run = run().await;
    let before = snapshot(&run.dir);
    let report = run_replay(ReplayConfig {
        run_dir: run.dir.clone(),
        out: None,
        reader: run.reader.clone(),
        expect_server_did: pin(run),
    })
    .await
    .expect("replay");
    let numbers: Vec<u8> = report.logs.iter().map(StepLog::number).collect();
    assert_eq!(numbers, vec![2, 3, 4, 5, 6, 7]);
    for log in &report.logs {
        assert!(log.passed(), "{}", log.verdict());
    }
    assert!(all_passed(&report.logs));
    assert_eq!(snapshot(&run.dir), before, "the replay wrote into the run");
    // It really compared what the run derived.
    let four = report.logs.iter().find(|l| l.number() == 4).unwrap();
    assert!(
        four.lines()
            .iter()
            .any(|l| l.contains("replay reproduces container-2.json byte for byte")),
        "{:?}",
        four.lines()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn replay_out_gets_the_logs_and_may_not_sit_in_the_run() {
    let run = run().await;
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out");
    let report = run_replay(ReplayConfig {
        run_dir: run.dir.clone(),
        out: Some(out.clone()),
        reader: run.reader.clone(),
        expect_server_did: pin(run),
    })
    .await
    .expect("replay");
    assert!(report.passed());
    assert!(out.join("step-2.log").is_file());
    assert!(!out.join("step-1.log").exists(), "step 1 is not replayed");
    assert!(out.join("container-5a.json").is_file());

    let inside = run_replay(ReplayConfig {
        run_dir: run.dir.clone(),
        out: Some(run.dir.join("x")),
        reader: run.reader.clone(),
        expect_server_did: pin(run),
    })
    .await;
    assert!(inside.is_err());
    assert!(!run.dir.join("x").exists());
}

/// A chain whose head moves with every read, as a live one does between two reads.
struct MovingHead {
    inner: Arc<dyn aqua_rs_sdk::BlockchainHost>,
    moved: AtomicU64,
}

impl aqua_rs_sdk::BlockchainHost for MovingHead {
    fn transaction_facts(
        &self,
        chain_id: u64,
        tx_hash: &str,
    ) -> Result<Option<aqua_rs_sdk::EvmTransactionFacts>, aqua_rs_sdk::HostError> {
        let by = self.moved.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .inner
            .transaction_facts(chain_id, tx_hash)?
            .map(|mut facts| {
                facts.head.latest += by;
                facts
            }))
    }
}

/// The rehearsal over a real chain found this: the confirmation count in an EVM witness's
/// provenance grows between two reads, and the fresh-read compare of step 5 must not fail on it.
#[tokio::test(flavor = "multi_thread")]
async fn the_fresh_read_compare_survives_a_moving_chain_head() {
    let run = run().await;
    let hosts = ReaderHosts {
        blockchain: Arc::new(MovingHead {
            inner: run.hosts.blockchain.clone(),
            moved: AtomicU64::new(1),
        }),
        ..run.hosts.clone()
    };
    let report = run_replay(ReplayConfig {
        run_dir: run.dir.clone(),
        out: None,
        reader: Reader::new(hosts, run.reader.policy.clone()),
        expect_server_did: pin(run),
    })
    .await
    .expect("replay");
    for log in &report.logs {
        assert!(log.passed(), "{}", log.verdict());
    }
    let five = report.logs.iter().find(|l| l.number() == 5).unwrap();
    assert!(
        five.lines()
            .iter()
            .any(|l| l.starts_with("ASSERT ok") && l.contains("a fresh P2 read")),
        "{:?}",
        five.lines()
    );
}

/// Every file a replay needs, removed or broken in turn: a named error, never a pass.
#[tokio::test(flavor = "multi_thread")]
async fn replay_refuses_a_missing_or_malformed_file_by_name() {
    let run = run().await;
    let meta: Value = serde_json::from_str(&read(&run.dir, "run.json")).unwrap();
    let epoch = meta["epoch_id"].as_u64().unwrap();
    let required = [
        "run.json".to_string(),
        "aqua-identity.json".into(),
        "set-folder.json".into(),
        "members/m1/tree.json".into(),
        "members/m2/tree.json".into(),
        "members/m3/tree.json".into(),
        "nonces-1.json".into(),
        "nonces-2.json".into(),
        "prepared-seal-1.json".into(),
        "prepared-seal-2.json".into(),
        "s1-evm.json".into(),
        "s1-qtsa.json".into(),
        "s2-qtsa.json".into(),
        "container-1.json".into(),
        "attestations-1.json".into(),
        "container-2.json".into(),
        "attestations-2.json".into(),
        "receipts-1/m1.json".into(),
        "receipts-1/m2.json".into(),
        "receipts-1/m3.json".into(),
        "receipts-2/m1.json".into(),
        "receipts-2/m2.json".into(),
        "receipts-2/m3.json".into(),
        "fetch-status.json".into(),
        format!("epochs-{epoch}.json"),
        format!("epoch-{epoch}-evm.json"),
        format!("epoch-{epoch}-qtsa.json"),
    ];
    for file in required
        .iter()
        .map(String::as_str)
        .chain(["members/m2/files/m2.txt"])
    {
        let tmp = tempfile::tempdir().unwrap();
        copy_tree(&run.dir, tmp.path());
        std::fs::remove_file(tmp.path().join(file)).unwrap();
        let err = verify_complete(tmp.path()).expect_err(file);
        assert_eq!(err.file, file);
        assert_eq!(err.problem, "missing", "{file}");
        let err = run_replay(ReplayConfig {
            run_dir: tmp.path().to_path_buf(),
            out: None,
            reader: run.reader.clone(),
            expect_server_did: pin(run),
        })
        .await
        .err()
        .expect(file);
        assert!(err.to_string().contains(file), "{file}: {err}");
    }
    for file in &required {
        let tmp = tempfile::tempdir().unwrap();
        copy_tree(&run.dir, tmp.path());
        std::fs::write(tmp.path().join(file), "{ not json").unwrap();
        let err = verify_complete(tmp.path()).expect_err(file);
        assert_eq!(&err.file, file);
        assert!(
            err.problem.starts_with("malformed"),
            "{file}: {}",
            err.problem
        );
    }
}

/// A read failure other than "not found" is no gap to step over: a directory in place of a file
/// the replay byte-compares is refused by name.
#[tokio::test(flavor = "multi_thread")]
async fn replay_refuses_an_unreadable_compared_file_by_name() {
    let run = run().await;
    for file in [
        "container-2.json",
        "attestations-2.json",
        "receipts-1/m2.json",
        "receipts-2/m3.json",
    ] {
        let tmp = tempfile::tempdir().unwrap();
        copy_tree(&run.dir, tmp.path());
        std::fs::remove_file(tmp.path().join(file)).unwrap();
        std::fs::create_dir(tmp.path().join(file)).unwrap();
        let err = verify_complete(tmp.path()).expect_err(file);
        assert_eq!(err.file, file);
        assert!(err.problem.starts_with("unreadable"), "{}", err.problem);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn replay_refuses_a_run_json_that_names_another_leaf() {
    let run = run().await;
    let tmp = tempfile::tempdir().unwrap();
    copy_tree(&run.dir, tmp.path());
    let mut meta: Value = serde_json::from_str(&read(tmp.path(), "run.json")).unwrap();
    meta["s1"] = json!(format!("0x{}", "11".repeat(32)));
    std::fs::write(tmp.path().join("run.json"), meta.to_string()).unwrap();
    let err = run_replay(ReplayConfig {
        run_dir: tmp.path().to_path_buf(),
        out: None,
        reader: run.reader.clone(),
        expect_server_did: pin(run),
    })
    .await
    .err()
    .expect("refused");
    assert!(err.to_string().contains("run.json"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_replay_with_another_expected_server_did_fails_step_2() {
    let run = run().await;
    let report = run_replay(ReplayConfig {
        run_dir: run.dir.clone(),
        out: None,
        reader: run.reader.clone(),
        expect_server_did: "did:pkh:eip155:1:0x0000000000000000000000000000000000000001".into(),
    })
    .await
    .expect("replay ran");
    assert!(!report.passed());
    let two = report.logs.iter().find(|l| l.number() == 2).unwrap();
    assert!(two.verdict().contains("no attester"), "{}", two.verdict());
}

/// L1: step 1's stub check is a real one. The same body with a zero transaction hash is a stub,
/// and fails the step by that name; the body as served passes.
#[tokio::test(flavor = "multi_thread")]
async fn step1_flags_a_stub_body_and_passes_a_real_one() {
    let run = run().await;
    for (file, method) in [
        ("s1-evm.json", WitnessMethod::Evm),
        ("s1-qtsa.json", WitnessMethod::Qtsa),
    ] {
        let real = read(&run.dir, file);
        let mut log = StepLog::new(1, "t", &[]);
        let got = served_witness(&mut log, file, method, &real).unwrap();
        assert!(got.is_some(), "{file}: {:?}", log.lines());
        assert!(log.passed(), "{file}: {}", log.verdict());
        assert!(
            log.lines()
                .iter()
                .any(|l| l.starts_with("ASSERT ok") && l.contains("detect_stub")),
            "{file}: {:?}",
            log.lines()
        );

        let mut stub: Value = serde_json::from_str(&real).unwrap();
        for revision in stub["revisions"].as_object_mut().unwrap().values_mut() {
            if revision.get("payloads").is_some() {
                revision["payloads"]["transaction_hash"] = json!("");
            }
        }
        let mut log = StepLog::new(1, "t", &[]);
        let got = served_witness(&mut log, file, method, &stub.to_string()).unwrap();
        assert!(got.is_none(), "{file}");
        assert_eq!(log.verdict(), "STEP 1 FAIL stub", "{file}");
    }
}

/// Attempt 1 of the clean-checkout suite found this: the seal's genesis G is an anchor revision
/// too, so picking "the" anchor by searching the container depends on which link sorts first.
/// A comes from the SDK's reading instead, and G is refused in its place.
#[tokio::test(flavor = "multi_thread")]
async fn the_tamper_takes_a_from_the_sdk_reading_never_from_the_link_order() {
    let run = run().await;
    let container: Tree = serde_json::from_str(&read(&run.dir, "container-1.json")).unwrap();
    let anchors: Vec<_> = container
        .revisions
        .iter()
        .filter(|(_, r)| matches!(r, AnyRevision::Anchor(_)))
        .map(|(k, _)| k.clone())
        .collect();
    assert_eq!(anchors.len(), 2, "G and A are both anchor revisions");

    let reader = run.reader.clone();
    let (input, catalogue, aq, c) = (
        reader.policy.dual(),
        reader.policy.catalogue(),
        reader.aq.clone(),
        container.clone(),
    );
    let reading =
        tokio::task::spawn_blocking(move || verify_seal_container(&aq, &c, &input, &catalogue))
            .await
            .unwrap();
    let SealReading::Seal(seal) = reading else {
        panic!("container 1 reads as a seal");
    };
    let key_of = |file: &str| -> RevisionLink {
        let served: Value = serde_json::from_str(&read(&run.dir, file)).unwrap();
        served["revisions"]
            .as_object()
            .unwrap()
            .iter()
            .find(|(_, r)| r.get("payloads").is_some())
            .map(|(k, _)| k.parse().unwrap())
            .unwrap()
    };
    let (tq, te) = (key_of("s1-qtsa.json"), key_of("s1-evm.json"));

    let done = relink_flipped_token(&container, seal.anchor(), seal.head_link(), &tq, &te).unwrap();
    assert_eq!(done.container.revisions.len(), 6);
    assert!(!done.container.revisions.contains_key(seal.anchor()));
    assert!(!done.container.revisions.contains_key(&tq));
    assert!(done.container.revisions.contains_key(&done.anchor_link));
    assert!(done.container.revisions.contains_key(&done.flipped_link));
    assert!(done.links.contains(&done.flipped_link) && done.links.contains(&te));

    let err = relink_flipped_token(&container, seal.genesis(), seal.head_link(), &tq, &te)
        .expect_err("G is not the seal's A");
    assert!(
        err.to_string().contains("does not follow the head"),
        "{err}"
    );
    let err = relink_flipped_token(&container, seal.head_link(), seal.head_link(), &tq, &te)
        .expect_err("H is no anchor");
    assert!(err.to_string().contains("not an anchor"), "{err}");
}

/// M1: a P with an altered signature, re-keyed under the link the SDK computes for it. It is
/// addressed, so the SDK reader runs the signature check: not Verified, no attester named. The
/// key-kept variant stops earlier, which is why it alone does not cover the check.
#[tokio::test(flavor = "multi_thread")]
async fn m1_an_addressed_p_with_a_bad_signature_runs_the_signature_check() {
    let run = run().await;
    let container: Tree = serde_json::from_str(&read(&run.dir, "container-1.json")).unwrap();
    let doc_text = read(&run.dir, "attestations-1.json");
    let doc: Value = serde_json::from_str(&doc_text).unwrap();
    let served: Value = serde_json::from_str(&read(&run.dir, "s1-qtsa.json")).unwrap();
    let (mut t_key, mut p_key) = (None, None);
    for (key, revision) in served["revisions"].as_object().unwrap() {
        if revision.get("payloads").is_some() {
            t_key = Some(key.clone());
        } else {
            p_key = Some(key.clone());
        }
    }
    let (t_key, p_key) = (t_key.unwrap(), p_key.unwrap());
    let t: RevisionLink = t_key.parse().unwrap();

    let reader = run.reader.clone();
    let input = reader.policy.dual();
    let catalogue = reader.policy.catalogue();
    let aq = reader.aq.clone();
    let reading = tokio::task::spawn_blocking(move || {
        verify_seal_container(&aq, &container, &input, &catalogue)
    })
    .await
    .unwrap();
    let SealReading::Seal(seal) = reading else {
        panic!("container 1 reads as a seal");
    };
    let pins = Default::default();

    // The document as built names the attester.
    let honest = read_seal_attestations(&seal, Some(&doc_text), &pins);
    assert!(format!("{honest:?}").contains("did:"));

    let rekeyed = rekey_bad_signature(&doc, &p_key).unwrap();
    assert_ne!(
        rekeyed.key.to_string(),
        p_key,
        "the altered P has a new link"
    );
    let revision: AnyRevision =
        serde_json::from_value(rekeyed.doc["revisions"][rekeyed.key.to_string()].clone()).unwrap();
    assert_eq!(link_of(&revision).unwrap(), rekeyed.key, "addressed");
    assert!(rekeyed.doc["revisions"].get(&p_key).is_none());

    let r = read_seal_attestations(&seal, Some(&rekeyed.doc.to_string()), &pins);
    let cause = rekeyed_reading_ok(&r, &t, &rekeyed.key).expect("the signature check ran");
    assert!(cause.starts_with("signature_invalid"), "{cause}");
    let witness = r.witnesses.iter().find(|w| w.witness == t).unwrap();
    assert!(matches!(
        witness.attestations[0].verdict,
        AttestationVerdict::Unverifiable { .. }
    ));
    assert!(!format!("{witness:?}").contains("did:"));

    // The key-kept variant never gets there.
    let (kept, _) = alter_p_key_kept(&doc, &p_key).unwrap();
    let r = read_seal_attestations(&seal, Some(&kept.to_string()), &pins);
    let p_link: RevisionLink = p_key.parse().unwrap();
    let why = rekeyed_reading_ok(&r, &t, &p_link).expect_err("stops at addressing");
    assert!(why.contains("addressing"), "{why}");

    // The check itself refuses a verified P: it is no always-pass.
    let why = rekeyed_reading_ok(&honest, &t, &p_link).expect_err("a verified P is a failure");
    assert!(why.contains("Verified"), "{why}");
}

// ---- a scripted server: the faults the in-process aggregator cannot show ------------------------

#[derive(Clone)]
enum Answer {
    /// Read the request, then close the connection: a transport error at the client.
    Hangup,
    /// A 200 that promises more body than it sends: the body read fails at the client.
    Truncated,
    Http(u16, String),
}

fn http(status: u16, body: &str) -> Answer {
    Answer::Http(status, body.to_string())
}

struct Scripted {
    url: String,
    requests: Arc<Mutex<Vec<String>>>,
}

impl Scripted {
    fn hits(&self, line: &str) -> usize {
        let requests = self.requests.lock().unwrap();
        requests.iter().filter(|r| r.as_str() == line).count()
    }
}

/// Serve on localhost until the test ends. `answer` gets the request line's method and path, and
/// how many times that same request came before.
async fn scripted(answer: impl Fn(&str, usize) -> Answer + Send + Sync + 'static) -> Scripted {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::<String>::new()));
    let seen = requests.clone();
    let answer = Arc::new(answer);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let (seen, answer) = (seen.clone(), answer.clone());
            tokio::spawn(async move {
                let Some(line) = read_request(&mut stream).await else {
                    return;
                };
                let before = {
                    let mut seen = seen.lock().unwrap();
                    let before = seen.iter().filter(|r| **r == line).count();
                    seen.push(line.clone());
                    before
                };
                let reply = match answer(&line, before) {
                    Answer::Hangup => return,
                    Answer::Truncated => http_reply(200, 1000, "{"),
                    Answer::Http(status, body) => http_reply(status, body.len(), &body),
                };
                let _ = stream.write_all(reply.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    Scripted { url, requests }
}

/// The request line's method and path, with the request read to its end.
async fn read_request(stream: &mut tokio::net::TcpStream) -> Option<String> {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        raw.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&raw[..end]).to_string();
    let length: usize = head
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0);
    while raw.len() < end + length {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        raw.extend_from_slice(&chunk[..n]);
    }
    let mut parts = head.lines().next()?.split(' ');
    Some(format!("{} {}", parts.next()?, parts.next()?))
}

fn http_reply(status: u16, length: usize, body: &str) -> String {
    let date = chrono::Utc::now().to_rfc2822();
    format!(
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {length}\r\nDate: {date}\r\nConnection: close\r\n\r\n{body}"
    )
}

// ---- F3: live-run reads survive what a proxy does, 4xx stays final ------------------------------

const SCHEDULE: &str = "GET /v1/schedule";

fn budget(millis: u64) -> PollBudget {
    PollBudget {
        deadline: Instant::now() + Duration::from_millis(millis),
        interval: Duration::from_millis(5),
    }
}

async fn wait(server: &Scripted, millis: u64) -> (anyhow::Result<()>, Vec<String>) {
    let mut lines = Vec::new();
    let b = budget(millis);
    let result = wait_for_seal(
        &reqwest::Client::new(),
        &server.url,
        7,
        b.deadline,
        b.interval,
        &mut |line| lines.push(line),
    )
    .await;
    (result, lines)
}

#[tokio::test(flavor = "multi_thread")]
async fn wait_for_seal_retries_a_transport_error_and_a_5xx_logging_each_attempt() {
    let server = scripted(|_, n| match n {
        0 => http(502, "<html>bad gateway</html>"),
        1 => Answer::Hangup,
        2 => Answer::Truncated,
        3 => http(503, ""),
        4 => http(200, r#"{"last_sealed_epoch_id":6}"#),
        _ => http(200, r#"{"last_sealed_epoch_id":7}"#),
    })
    .await;
    let (result, lines) = wait(&server, 30_000).await;
    result.expect("the epoch sealed");
    assert_eq!(server.hits(SCHEDULE), 6);
    assert_eq!(lines.len(), 4, "one line per failed attempt: {lines:?}");
    assert!(lines[0].contains("502"), "{lines:?}");
    assert!(lines[3].contains("503"), "{lines:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn wait_for_seal_takes_a_4xx_as_final() {
    for status in [400, 403, 404, 410] {
        let server = scripted(move |_, _| http(status, "no")).await;
        let (result, _) = wait(&server, 30_000).await;
        let err = result.expect_err("a 4xx is final");
        assert!(err.to_string().contains(&status.to_string()), "{err}");
        assert_eq!(server.hits(SCHEDULE), 1, "{status} was not retried");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn wait_for_seal_gives_up_at_the_deadline_with_the_last_answer() {
    let server = scripted(|_, _| http(503, "still down")).await;
    let (result, lines) = wait(&server, 1_000).await;
    let err = result.expect_err("no seal, no pass").to_string();
    assert!(err.contains("timed out"), "{err}");
    assert!(err.contains("503"), "{err}");
    assert!(lines.len() >= 2, "{lines:?}");
}

const EVM: &str = "GET /trees?epoch=7&method=evm";
const QTSA: &str = "GET /trees?epoch=7&method=qtsa";
const EPOCHS: &str = "GET /v1/epochs?from=7&limit=1";

async fn epoch_reads(
    server: &Scripted,
    millis: u64,
) -> (
    serde_json::Map<String, Value>,
    tempfile::TempDir,
    Vec<String>,
) {
    let run = tempfile::tempdir().unwrap();
    let mut lines = Vec::new();
    let reads = read_epoch_bodies(
        &reqwest::Client::new(),
        &server.url,
        "token",
        7,
        run.path(),
        budget(millis),
        &mut |line| lines.push(line),
    )
    .await
    .expect("a failed read is recorded, it does not discard the run");
    (reads, run, lines)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_epoch_reads_retry_a_transport_error_and_a_5xx_and_keep_the_served_bytes() {
    let server = scripted(|line, n| match (line, n) {
        (EVM, 0) => http(502, "<html>"),
        (QTSA, 0) => Answer::Hangup,
        (EPOCHS, 0) => Answer::Truncated,
        (EVM, _) => http(200, r#"{"revisions":{"evm":1}}"#),
        (QTSA, _) => http(200, r#"{"revisions":{"qtsa":1}}"#),
        _ => http(200, r#"{"epochs":[]}"#),
    })
    .await;
    let (reads, run, lines) = epoch_reads(&server, 30_000).await;
    for key in ["epoch_evm", "epoch_qtsa", "epochs"] {
        assert_eq!(reads[key]["status"], 200, "{key}");
    }
    assert_eq!(lines.len(), 3, "one line per failed attempt: {lines:?}");
    assert_eq!(
        read(run.path(), "epoch-7-evm.json"),
        r#"{"revisions":{"evm":1}}"#
    );
    assert_eq!(
        read(run.path(), "epoch-7-qtsa.json"),
        r#"{"revisions":{"qtsa":1}}"#
    );
    assert_eq!(read(run.path(), "epochs-7.json"), r#"{"epochs":[]}"#);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_epoch_read_takes_a_4xx_as_final_and_records_it() {
    let server = scripted(|line, _| match line {
        EVM => http(410, r#"{"error":"gone"}"#),
        _ => http(200, "{}"),
    })
    .await;
    let (reads, run, lines) = epoch_reads(&server, 30_000).await;
    assert_eq!(server.hits(EVM), 1);
    assert_eq!(reads["epoch_evm"]["status"], 410);
    assert_eq!(read(run.path(), "epoch-7-evm.json"), r#"{"error":"gone"}"#);
    assert!(lines.is_empty(), "{lines:?}");
}

/// A run that already holds its witnesses is not discarded by an epoch read that stays down: the
/// failure is on record and no body is invented for it.
#[tokio::test(flavor = "multi_thread")]
async fn an_epoch_read_that_stays_down_is_recorded_with_no_body_and_the_rest_still_read() {
    let server = scripted(|line, _| match line {
        EVM => http(503, "down"),
        _ => http(200, "{}"),
    })
    .await;
    let (reads, run, _) = epoch_reads(&server, 150).await;
    assert_eq!(reads["epoch_evm"]["status"], Value::Null);
    assert!(
        reads["epoch_evm"]["error"]
            .as_str()
            .unwrap()
            .contains("503"),
        "{reads:?}"
    );
    assert!(!run.path().join("epoch-7-evm.json").exists());
    assert_eq!(reads["epoch_qtsa"]["status"], 200);
    assert_eq!(reads["epochs"]["status"], 200);
}

/// The steps over a copy of the finished run, as a live run reads it: the copy takes what they
/// write.
async fn steps_over_copy(
    copy: &tempfile::TempDir,
    which: Steps,
    reader: Reader,
    finality_budget: Duration,
) -> Vec<StepLog> {
    let state = RunState::load(copy.path(), &reader.aq).await.unwrap();
    let ctx = Ctx {
        store: Store::new(copy.path(), StoreMode::Persist),
        reader,
        state,
        header: Vec::new(),
        expect_server_did: None,
        finality_budget,
    };
    steps::run(&ctx, which, "test").await.unwrap()
}

/// The recorded failure of an epoch read ends in a failed step 7, not a pass.
#[tokio::test(flavor = "multi_thread")]
async fn an_epoch_read_that_stayed_down_fails_step_7() {
    let run = run().await;
    let copy = tempfile::tempdir().unwrap();
    copy_tree(&run.dir, copy.path());
    let meta: Value = serde_json::from_str(&read(copy.path(), "run.json")).unwrap();
    let epoch = meta["epoch_id"].as_u64().unwrap();
    std::fs::remove_file(copy.path().join(format!("epoch-{epoch}-evm.json"))).unwrap();
    let mut status: Value = serde_json::from_str(&read(copy.path(), "fetch-status.json")).unwrap();
    status["epoch_evm"] = json!({"status": null, "error": "HTTP 503", "at": "t"});
    std::fs::write(copy.path().join("fetch-status.json"), status.to_string()).unwrap();
    let logs = steps_over_copy(
        &copy,
        Steps::FromPersisted,
        run.reader.clone(),
        Duration::ZERO,
    )
    .await;
    let seven = logs.iter().find(|l| l.number() == 7).unwrap();
    assert!(!seven.passed(), "{:?}", seven.lines());
    assert!(!all_passed(&logs));
}

// ---- F4: step 1 repeats a read of an unavailable host, a verdict stays final --------------------

/// A chain host whose answer the test chooses: down for the first `down` reads, reverted always
/// when `revert`.
struct Chain {
    inner: Arc<dyn aqua_rs_sdk::BlockchainHost>,
    down: AtomicU64,
    revert: bool,
}

impl aqua_rs_sdk::BlockchainHost for Chain {
    fn transaction_facts(
        &self,
        chain_id: u64,
        tx_hash: &str,
    ) -> Result<Option<aqua_rs_sdk::EvmTransactionFacts>, aqua_rs_sdk::HostError> {
        let left = self.down.load(Ordering::SeqCst);
        if left > 0 {
            self.down.store(left - 1, Ordering::SeqCst);
            return Err(aqua_rs_sdk::HostError::NetworkError("down".to_string()));
        }
        let mut facts = self.inner.transaction_facts(chain_id, tx_hash)?;
        if self.revert {
            if let Some(inclusion) = facts.as_mut().and_then(|f| f.inclusion.as_mut()) {
                inclusion.succeeded = false;
            }
        }
        Ok(facts)
    }
}

async fn step_1_over(run: &Run, down: u64, revert: bool, budget: Duration) -> StepLog {
    let hosts = ReaderHosts {
        blockchain: Arc::new(Chain {
            inner: run.hosts.blockchain.clone(),
            down: AtomicU64::new(down),
            revert,
        }),
        ..run.hosts.clone()
    };
    let copy = tempfile::tempdir().unwrap();
    copy_tree(&run.dir, copy.path());
    let reader = Reader::new(hosts, run.reader.policy.clone());
    let logs = steps_over_copy(&copy, Steps::All, reader, budget).await;
    logs.into_iter().find(|l| l.number() == 1).unwrap()
}

fn attempts(log: &StepLog) -> Vec<String> {
    log.lines()
        .iter()
        .filter(|l| l.starts_with("evaluate attempt"))
        .cloned()
        .collect()
}

/// One failed read at evaluate time does not end the run: the read is repeated, logged per
/// attempt, and the verdict is the SDK's on the repeated read.
#[tokio::test(flavor = "multi_thread")]
async fn step_1_repeats_a_read_of_an_unavailable_host_within_the_budget() {
    let run = run().await;
    let log = step_1_over(run, 1, false, Duration::from_secs(5)).await;
    let tried = attempts(&log);
    assert_eq!(tried.len(), 2, "{tried:?}");
    assert!(tried[0].contains("host_unavailable"), "{tried:?}");
    assert!(tried[1].contains(": Ok"), "{tried:?}");
    assert!(log.passed(), "{:?}", log.lines());
}

/// A retry never turns a verdict into a pass: a host that stays down ends in a failed step.
#[tokio::test(flavor = "multi_thread")]
async fn step_1_with_a_host_that_stays_unavailable_ends_in_a_failed_step() {
    let run = run().await;
    let log = step_1_over(run, u64::MAX, false, Duration::from_secs(5)).await;
    let tried = attempts(&log);
    assert!(tried.len() >= 2, "{tried:?}");
    assert!(
        tried.iter().all(|t| t.contains("host_unavailable")),
        "{tried:?}"
    );
    assert!(!log.passed());
    assert!(
        log.verdict().contains("EvmAnchorNotVerified"),
        "{}",
        log.verdict()
    );
}

/// A refusal on what the chain says stays final, however much budget is left.
#[tokio::test(flavor = "multi_thread")]
async fn step_1_takes_a_final_refusal_as_final_with_budget_left() {
    let run = run().await;
    let started = Instant::now();
    let log = step_1_over(run, 0, true, Duration::from_secs(3_600)).await;
    let tried = attempts(&log);
    assert_eq!(tried.len(), 1, "{tried:?}");
    assert!(tried[0].contains("EvmAnchorNotVerified"), "{tried:?}");
    assert!(tried[0].contains("invalid"), "{tried:?}");
    assert!(!log.passed());
    assert!(started.elapsed() < Duration::from_secs(60), "it waited");
}

// ---- F5: the server DID pin holds before anything is posted --------------------------------------

const SERVER_DID: &str = "did:pkh:eip155:1:0x0000000000000000000000000000000000000abc";
const OTHER_DID: &str = "did:pkh:eip155:1:0x0000000000000000000000000000000000000def";
const LEAVES: &str = "POST /v1/leaves";
const SESSION: &str = "POST /auth/session";

/// The aggregator as the run's preflight and sign-in see it; `leaves` answers the POST.
async fn aggregator(leaves: Answer) -> Scripted {
    scripted(move |line, _| match line.split('?').next().unwrap() {
        "GET /version" => http(200, r#"{"service":"aqua-timestamp","revision":"abc"}"#),
        "GET /health" => http(200, "ok"),
        "GET /.well-known/aqua-identity" => {
            http(200, &json!({ "server_did": SERVER_DID }).to_string())
        }
        "GET /auth/challenge" => http(200, r#"{"message":"m","nonce":"n"}"#),
        SESSION => http(200, r#"{"token":"t"}"#),
        LEAVES => leaves.clone(),
        other => http(404, other),
    })
    .await
}

fn seal_config(base_url: &str, dir: &Path, reader: &Reader, pin: Option<&str>) -> SealConfig {
    SealConfig {
        base_url: base_url.to_string(),
        run_dir: dir.join("run"),
        identity_dir: dir.join("identity"),
        reader: reader.clone(),
        seal_trigger: SealTrigger::None,
        expect_version: None,
        expect_server_did: pin.map(str::to_string),
        seal_grace: Duration::from_secs(1),
        witness_grace: Duration::from_secs(1),
        poll_interval: Duration::from_millis(5),
        finality_budget: Duration::ZERO,
    }
}

/// The run against the scripted aggregator, under a throwaway loopback identity.
async fn seal_against(
    server: &Scripted,
    dir: &Path,
    reader: &Reader,
    pin: Option<&str>,
) -> anyhow::Result<SealReport> {
    let cfg = seal_config(&server.url, dir, reader, pin);
    let id = for_base_url(&server.url, &cfg.identity_dir).unwrap();
    run_seal(cfg, &id).await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_did_other_than_the_pin_stops_the_run_before_anything_is_posted() {
    let run = run().await;
    let server = aggregator(http(500, "must not be reached")).await;
    let tmp = tempfile::tempdir().unwrap();
    let err = seal_against(&server, tmp.path(), &run.reader, Some(OTHER_DID))
        .await
        .err()
        .expect("refused")
        .to_string();
    assert!(err.contains("--expect-server-did"), "{err}");
    assert!(err.contains("nothing was posted"), "{err}");
    assert_eq!(server.hits(LEAVES), 0);
    assert_eq!(server.hits(SESSION), 0);
    assert!(!tmp.path().join("run").exists(), "no run directory");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_served_server_did_equal_to_the_pin_goes_on_to_the_post() {
    let run = run().await;
    let server = aggregator(http(500, "refused")).await;
    let tmp = tempfile::tempdir().unwrap();
    let err = seal_against(&server, tmp.path(), &run.reader, Some(SERVER_DID))
        .await
        .err()
        .expect("the POST was refused")
        .to_string();
    assert!(err.contains("/v1/leaves"), "{err}");
    assert_eq!(server.hits(LEAVES), 1);
}

/// The library holds ruling 10 too, not only the command line.
#[tokio::test(flavor = "multi_thread")]
async fn run_seal_on_a_remote_with_no_pin_is_refused_before_any_read() {
    let run = run().await;
    let tmp = tempfile::tempdir().unwrap();
    let loopback = aggregator(http(500, "unused")).await;
    let id = for_base_url(&loopback.url, &tmp.path().join("identity")).unwrap();
    let cfg = seal_config("https://e2e.example.invalid", tmp.path(), &run.reader, None);
    let err = run_seal(cfg, &id).await.err().expect("refused").to_string();
    assert!(err.contains("--expect-server-did"), "{err}");
    assert!(!tmp.path().join("run").exists());
}

// ---- F7: step 7 counts per method, not only the sum ----------------------------------------------

async fn step_7_over(run: &Run, copy: &tempfile::TempDir) -> StepLog {
    let logs = steps_over_copy(
        copy,
        Steps::FromPersisted,
        run.reader.clone(),
        Duration::ZERO,
    )
    .await;
    logs.into_iter().find(|l| l.number() == 7).unwrap()
}

/// Three EVM pairs and one qTSA pair sum to the same four as two of each.
#[tokio::test(flavor = "multi_thread")]
async fn step_7_fails_a_listing_that_only_sums_right() {
    let run = run().await;
    let copy = tempfile::tempdir().unwrap();
    copy_tree(&run.dir, copy.path());
    let meta: Value = serde_json::from_str(&read(copy.path(), "run.json")).unwrap();
    let epoch = meta["epoch_id"].as_u64().unwrap();
    let edit = |method: &str, change: &dyn Fn(&mut serde_json::Map<String, Value>)| {
        let file = format!("epoch-{epoch}-{method}.json");
        let mut body: Value = serde_json::from_str(&read(copy.path(), &file)).unwrap();
        change(body["revisions"].as_object_mut().unwrap());
        std::fs::write(copy.path().join(file), body.to_string()).unwrap();
    };
    let is_t = |r: &Value| r.get("payloads").is_some();
    edit("evm", &|revisions| {
        let t = revisions.values().find(|r| is_t(r)).unwrap().clone();
        revisions.insert("0xextra".to_string(), t);
    });
    edit("qtsa", &|revisions| {
        let key = revisions.iter().find(|(_, r)| is_t(r)).unwrap().0.clone();
        revisions.remove(&key);
    });
    let seven = step_7_over(run, &copy).await;
    assert!(!seven.passed(), "{:?}", seven.lines());
    let failed: Vec<_> = seven
        .lines()
        .iter()
        .filter(|l| l.starts_with("ASSERT FAIL"))
        .collect();
    assert_eq!(failed.len(), 2, "one per method: {failed:?}");
}

/// Ruling 2 stands: more leaves in the epoch than this run's is partial coverage with both
/// numbers, no failure.
#[tokio::test(flavor = "multi_thread")]
async fn step_7_logs_a_busier_epoch_as_partial_coverage_and_passes() {
    let run = run().await;
    let copy = tempfile::tempdir().unwrap();
    copy_tree(&run.dir, copy.path());
    let meta: Value = serde_json::from_str(&read(copy.path(), "run.json")).unwrap();
    let file = format!("epochs-{}.json", meta["epoch_id"].as_u64().unwrap());
    let mut body: Value = serde_json::from_str(&read(copy.path(), &file)).unwrap();
    for item in body["epochs"].as_array_mut().unwrap() {
        item["leaf_count"] = json!(7);
    }
    std::fs::write(copy.path().join(file), body.to_string()).unwrap();
    let seven = step_7_over(run, &copy).await;
    assert!(seven.passed(), "{:?}", seven.lines());
    assert!(
        seven
            .lines()
            .iter()
            .any(|l| l.contains("partial coverage") && l.contains("leaf_count 7")),
        "{:?}",
        seven.lines()
    );
}
