//! `cargo test --workspace -p aqua-timestamp-e2e` entry point.
//!
//! Asserts the same M-E2E flow that runs against the live deployment also
//! runs to completion against an in-process server. This guarantees the
//! verifier code (Merkle proof, EIP-191 recovery, isolation 403, no-bearer
//! 401) keeps working independent of the live deployment, so the live
//! script is solely a "the server is reachable + correct" check.

use std::process::Command;

#[test]
fn selfcheck_runs_to_completion() {
    // Invoke the binary as a subprocess. This mirrors what `cargo run --bin
    // aqua-timestamp-e2e -- selfcheck` does end-to-end, including
    // argument parsing, runtime spin-up, and process exit code, so any
    // regression in either the binary wiring or the flow surfaces here.
    let bin = env!("CARGO_BIN_EXE_aqua-timestamp-e2e");
    let output = Command::new(bin)
        .arg("selfcheck")
        .output()
        .expect("spawn selfcheck binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "selfcheck failed (status={:?})\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        output.status.code()
    );

    // Sanity: every step should have logged an `OK` line.
    for step in [1, 2, 3, 5, 6, 7, 8, 9, 10] {
        let needle = format!("[step {step}] OK");
        assert!(
            stdout.contains(&needle),
            "missing step marker `{needle}` in stdout:\n{stdout}"
        );
    }
    assert!(stdout.contains("STATUS         = OK"));
}
