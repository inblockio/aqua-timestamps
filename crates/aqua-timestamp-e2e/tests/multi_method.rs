//! `cargo test --workspace -p aqua-timestamp-e2e --test multi_method`
//!
//! Runs the full end-to-end flow against an in-process server three
//! times: once with a secp256k1+EIP-191 client (the production
//! happy-path), once with an Ed25519 client, and once with a P-256
//! client. All three DID methods the deployed `aqua-rs-auth` accepts
//! get exercised under the same verifier code.
//!
//! Implementation: invoke the binary as a subprocess with
//! `selfcheck-all`. Mirrors the pattern in `tests/selfcheck.rs` so
//! arg parsing, runtime spin-up, and process exit code are all in scope
//! and any regression in either binary wiring or flow surfaces here.

use std::process::Command;

#[test]
fn flow_works_for_all_three_did_methods() {
    let bin = env!("CARGO_BIN_EXE_aqua-timestamp-e2e");
    let output = Command::new(bin)
        .arg("selfcheck-all")
        .output()
        .expect("spawn selfcheck-all binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "selfcheck-all failed (status={:?})\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        output.status.code()
    );

    for method in ["secp256k1+eip191", "ed25519", "p256"] {
        let needle = format!("[{method}] STATUS=OK");
        assert!(
            stdout.contains(&needle),
            "missing per-method OK line `{needle}` in stdout:\n{stdout}"
        );
    }
    assert!(stdout.contains("OVERALL = OK (3 methods)"));
}
