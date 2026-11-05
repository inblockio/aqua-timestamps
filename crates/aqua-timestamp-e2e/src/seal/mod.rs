//! The Set Seal v1 reference e2e: seven steps against a deployed aggregator, and a replay of a
//! finished run from its persisted client state.
//!
//! * [`live`]: the only part that holds the standing identity, a bearer token and an HTTP client.
//!   It prepares two seals, signs in, submits their signatures S as one `POST /v1/leaves`, waits
//!   for the epoch, pulls the witnesses and persists every body byte for byte.
//! * [`steps`]: steps 1 to 7 on the persisted data, under reader policies pinned in [`policy`].
//! * [`replay`]: steps 2 to 7 on a persisted run. No key, no session, nothing sent to the
//!   aggregator.
//!
//! No trust logic (hash, signature, verdict) lives here: [`steps`] compares SDK outputs,
//! [`tamper`] flips bytes.

pub mod live;
pub mod log;
pub mod policy;
pub mod replay;
pub mod run_dir;
pub mod steps;
pub mod tamper;

use anyhow::{bail, Result};

/// The workspace lockfile this binary was built from.
const CARGO_LOCK: &str = include_str!("../../../../Cargo.lock");

/// The git revision of `aqua-rs-sdk` in `lock`. More or fewer than one is an error: the workspace
/// holds one SDK, and a second copy would split its types.
pub fn sdk_rev_in(lock: &str) -> Result<String> {
    let mut in_pkg = false;
    let mut revs = Vec::new();
    for line in lock.lines() {
        if line.starts_with("name = ") {
            in_pkg = line == "name = \"aqua-rs-sdk\"";
        }
        if in_pkg && line.starts_with("source = ") {
            if let Some(i) = line.rfind('#') {
                revs.push(line[i + 1..].trim_end_matches('"').to_string());
            }
        }
    }
    match revs.as_slice() {
        [one] => Ok(one.clone()),
        _ => bail!("expected exactly one aqua-rs-sdk in Cargo.lock, found {revs:?}"),
    }
}

/// The SDK revision of this binary.
pub fn sdk_rev() -> Result<String> {
    sdk_rev_in(CARGO_LOCK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_workspace_holds_one_sdk_at_a_full_revision() {
        let rev = sdk_rev().unwrap();
        assert_eq!(rev.len(), 40, "{rev}");
        assert!(rev.chars().all(|c| c.is_ascii_hexdigit()), "{rev}");
    }

    #[test]
    fn two_sdks_in_a_lockfile_are_refused() {
        let one = "name = \"aqua-rs-sdk\"\nsource = \"git+https://x?tag=a#aaa\"\n";
        assert_eq!(sdk_rev_in(one).unwrap(), "aaa");
        let two = format!("{one}{}", one.replace("aaa", "bbb"));
        assert!(sdk_rev_in(&two).is_err());
        assert!(sdk_rev_in("").is_err());
    }

    /// Ruling 3: an assertion line that cannot fail is no evidence. Line breaks do not hide one.
    #[test]
    fn no_assertion_line_is_hardwired_to_pass() {
        let needle = concat!("check(", "true");
        for (name, src) in [
            ("live.rs", include_str!("live.rs")),
            ("log.rs", include_str!("log.rs")),
            ("replay.rs", include_str!("replay.rs")),
            ("run_dir.rs", include_str!("run_dir.rs")),
            ("steps.rs", include_str!("steps.rs")),
            ("tamper.rs", include_str!("tamper.rs")),
        ] {
            let flat: String = src.chars().filter(|c| !c.is_whitespace()).collect();
            assert!(!flat.contains(needle), "{name} holds a {needle}");
        }
    }

    /// The replay guarantee, held by the source: the replay path and everything it reads cannot
    /// name an HTTP client, a session or the identity. A new use of one fails here at once.
    #[test]
    fn the_replay_path_holds_no_session_no_post_and_no_identity() {
        let sources = [
            ("replay.rs", include_str!("replay.rs")),
            ("steps.rs", include_str!("steps.rs")),
            ("run_dir.rs", include_str!("run_dir.rs")),
            ("tamper.rs", include_str!("tamper.rs")),
            ("log.rs", include_str!("log.rs")),
            ("policy.rs", include_str!("policy.rs")),
        ];
        for (name, src) in sources {
            for banned in [
                "reqwest",
                "http_get",
                "http_post",
                "mint_bearer",
                "bearer",
                ".post(",
                "/auth/session",
                "/v1/leaves\"",
                "identity::",
                "StandingIdentity",
                "load_or_create",
                "load_existing",
                "for_base_url",
                "live::",
                "fetch_witness",
                "fetch_served",
            ] {
                assert!(!src.contains(banned), "{name} must not name {banned}");
            }
        }
    }
}
