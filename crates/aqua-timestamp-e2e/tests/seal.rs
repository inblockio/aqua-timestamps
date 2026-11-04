//! `seal` and `seal-replay` end to end, offline: the whole live part against an in-process
//! aggregator on localhost (sign-in, both leaves, seal, pull, persist), the seven steps over the
//! offline doubles, and the replay of what that run persisted. Nothing here leaves this machine.
//!
//! One run per test binary: the tests share it read-only.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use aqua_rs_sdk::core::seal::{
    read_seal_attestations, verify_seal_container, AttestationVerdict, SealReading,
};
use aqua_rs_sdk::primitives::RevisionLink;
use aqua_rs_sdk::schema::tree::Tree;
use aqua_rs_sdk::schema::AnyRevision;
use aqua_timestamp_e2e::seal::log::{all_passed, StepLog};
use aqua_timestamp_e2e::seal::policy::Reader;
use aqua_timestamp_e2e::seal::replay::{run_replay, ReplayConfig};
use aqua_timestamp_e2e::seal::run_dir::verify_complete;
use aqua_timestamp_e2e::seal::steps::{rekeyed_reading_ok, served_witness};
use aqua_timestamp_e2e::seal::tamper::{
    alter_p_key_kept, link_of, rekey_bad_signature, relink_flipped_token,
};
use aqua_timestamp_e2e::selfcheck::run_seal_in_process;
use aqua_timestamp_e2e::witness::{ReaderHosts, WitnessMethod};
use serde_json::{json, Value};
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
        expect_server_did: None,
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
        expect_server_did: None,
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
        expect_server_did: None,
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
        expect_server_did: None,
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
            expect_server_did: None,
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
        expect_server_did: None,
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
        expect_server_did: Some(
            "did:pkh:eip155:1:0x0000000000000000000000000000000000000001".into(),
        ),
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
