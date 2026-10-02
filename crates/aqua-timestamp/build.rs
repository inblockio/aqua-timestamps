//! Stamp the source commit into the binary so a running service can say what it is
//! (`GET /version`), which is how aqua-ops derives the deployed dependency pins.
//!
//! GIT_SHA   full 40-hex commit that was built, or "unknown"
//! GIT_DIRTY "1" when tracked files differ from that commit, else "0"
//!
//! A Docker build has no `.git`, so `GIT_SHA` / `GIT_DIRTY` from the environment
//! win over git (the Dockerfile passes them as build args). Never fails the build:
//! with neither available both fall back to "unknown"/"0" and consumers treat
//! "unknown" as not observable.
use std::path::Path;
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn is_full_sha(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn main() {
    let sha = std::env::var("GIT_SHA")
        .ok()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| is_full_sha(s))
        .or_else(|| git(&["rev-parse", "HEAD"]).filter(|s| is_full_sha(s)))
        .unwrap_or_else(|| "unknown".into());
    let dirty = match std::env::var("GIT_DIRTY") {
        Ok(v) => v.trim() == "1",
        Err(_) => git(&["status", "--porcelain", "--untracked-files=no"])
            .map(|s| !s.is_empty())
            .unwrap_or(false),
    };
    println!("cargo:rustc-env=GIT_SHA={sha}");
    println!(
        "cargo:rustc-env=GIT_DIRTY={}",
        if dirty { "1" } else { "0" }
    );
    println!("cargo:rerun-if-env-changed=GIT_SHA");
    println!("cargo:rerun-if-env-changed=GIT_DIRTY");

    // Rebuild when HEAD moves. A dirty-state change alone does not retrigger cargo;
    // the deploy builds from a clean checkout, which is the supported path.
    if let Some(gd) = git(&["rev-parse", "--git-dir"]) {
        let gd = Path::new(&gd);
        println!("cargo:rerun-if-changed={}", gd.join("HEAD").display());
        if let Some(r) = git(&["symbolic-ref", "-q", "HEAD"]) {
            println!("cargo:rerun-if-changed={}", gd.join(r).display());
        }
    }
}
