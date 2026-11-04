//! Command-line contract of the e2e binary (OW1.5): the standing identity layout, no default
//! base URL, the production guard.

use std::os::unix::fs::PermissionsExt;
use std::process::Command;

fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_aqua-timestamp-e2e"));
    c.env_remove("OPENWITNESS_E2E_BASE_URL")
        .env_remove("OPENWITNESS_E2E_IDENTITY_DIR");
    c
}

#[test]
fn live_without_a_base_url_does_not_run() {
    let out = bin().arg("live").output().unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--base-url"), "{err}");
}

#[test]
fn live_refuses_production_without_the_flag_before_touching_the_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("id");
    let out = bin()
        .args([
            "live",
            "--base-url",
            "https://openwitness.org",
            "--identity-dir",
        ])
        .arg(&dir)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("production"), "{err}");
    assert!(!dir.exists(), "refused before creating any identity");
}

#[test]
fn selfcheck_on_a_named_dir_creates_the_standing_identity_once() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("id");
    let run = || {
        let out = bin()
            .args(["selfcheck", "--identity-dir"])
            .arg(&dir)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).to_string()
    };
    let first = run();
    let key = std::fs::read(dir.join("secp256k1.key")).unwrap();
    let record = std::fs::read_to_string(dir.join("identity.json")).unwrap();
    assert!(record.contains("openwitness-seal-e2e"));
    assert_eq!(
        std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(dir.join("secp256k1.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    // Both anchors were judged by the SDK verifier.
    for m in ["evm", "qtsa"] {
        assert!(
            first.contains(&format!("SDK verifier: {m} timestamp revision verified")),
            "{first}"
        );
    }
    let did = record
        .split("\"did\": \"")
        .nth(1)
        .and_then(|r| r.split('"').next())
        .unwrap()
        .to_string();
    assert!(first.contains(&did), "the run signed in as the stored DID");

    // Second run: same identity, key and record untouched.
    let second = run();
    assert!(second.contains(&did));
    assert_eq!(std::fs::read(dir.join("secp256k1.key")).unwrap(), key);
    assert_eq!(
        std::fs::read_to_string(dir.join("identity.json")).unwrap(),
        record
    );
}

/// A remote `--base-url` with no identity stops before any network and writes nothing. The host
/// is reserved and never resolves, so a regression fails this test instead of reaching a server.
#[test]
fn a_remote_with_a_missing_identity_is_refused_on_live_and_on_seal() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("id");
    let run = tmp.path().join("run");
    for cmd in ["live", "seal"] {
        let mut c = bin();
        c.arg(cmd)
            .args(["--base-url", "https://e2e.example.invalid"])
            .arg("--identity-dir")
            .arg(&dir);
        if cmd == "seal" {
            c.arg("--run-dir").arg(&run);
            c.args(["--expect-server-did", "did:pkh:eip155:1:0x01"]);
        }
        let out = c.output().unwrap();
        assert!(!out.status.success(), "{cmd}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("no standing identity"), "{cmd}: {err}");
        assert!(err.contains("Nothing was written"), "{cmd}: {err}");
        assert!(!dir.exists(), "{cmd}: no identity directory");
        assert!(!run.exists(), "{cmd}: no run directory");
    }
}

#[test]
fn seal_refuses_production_without_the_flag_before_touching_the_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("id");
    let out = bin()
        .args(["seal", "--base-url", "https://openwitness.org"])
        .arg("--identity-dir")
        .arg(&dir)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("production"), "{err}");
    assert!(!dir.exists());
}

/// Ruling 10: no default in code. A remote `seal` with no pin stops at the start, before the
/// identity and before any network; the host is reserved and never resolves.
#[test]
fn seal_on_a_remote_without_the_server_did_pin_is_refused_at_the_start() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("id");
    let run = tmp.path().join("run");
    let out = bin()
        .args(["seal", "--base-url", "https://e2e.example.invalid"])
        .arg("--identity-dir")
        .arg(&dir)
        .arg("--run-dir")
        .arg(&run)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--expect-server-did"), "{err}");
    assert!(!dir.exists(), "no identity directory");
    assert!(!run.exists(), "no run directory");
}

#[test]
fn seal_replay_without_the_server_did_pin_does_not_run() {
    let tmp = tempfile::tempdir().unwrap();
    let out = bin().arg("seal-replay").arg(tmp.path()).output().unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--expect-server-did"), "{err}");
}

#[test]
fn seal_without_a_base_url_does_not_run() {
    let out = bin().arg("seal").output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--base-url"));
}

#[test]
fn seal_replay_of_an_incomplete_directory_names_the_file_and_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let out = bin()
        .arg("seal-replay")
        .arg(tmp.path())
        .args(["--expect-server-did", "did:pkh:eip155:1:0x01"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("run.json"), "{err}");
    assert!(err.contains("missing"), "{err}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("PASS"), "{stdout}");
    assert_eq!(
        std::fs::read_dir(tmp.path()).unwrap().count(),
        0,
        "the replay writes nothing into the directory"
    );
}
