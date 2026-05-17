//! aqua-timestamp-core: shared types and primitives for the aggregator.
//!
//! M0 carries only the marker module so the workspace resolves; epoch,
//! accumulator, witness-minter, and store modules land in M2/M3.

pub mod version {
    pub const PROTOCOL: &str = "aqua";
    pub const PROTOCOL_VERSION: &str = "4.0";
    pub const SCHEMA_URL: &str = "https://aqua-protocol.org/docs/v4/schema";
}

/// Smoke check that all path-dep crates are wired correctly. Compile-only;
/// the body never runs.
#[allow(dead_code)]
fn _link_check() {
    let _ = aqua_rs_sdk::primitives::merkle::merkle_root;
    let _ = aqua_auth::verify_caip122;
}
