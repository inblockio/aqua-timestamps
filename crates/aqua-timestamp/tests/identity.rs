//! M1 identity tests: golden mnemonic vector, SDK round-trip on the
//! identity tree, JSON snapshot of the well-known response.

use aqua_rs_sdk::{schema::AquaTreeWrapper, Aquafier};
use aqua_timestamp::{
    config::IdentityConfig,
    identity::{
        build_identity_tree, build_response, normalise_for_snapshot, IdentityClaimOverrides,
        ServiceIdentity,
    },
};

/// Well-known Hardhat test mnemonic; the production mnemonic never
/// appears in this repo. Address at `m/44'/60'/0'/0/0` is
/// `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`.
const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";
const TEST_ADDRESS_EIP55: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

fn fixed_overrides() -> IdentityClaimOverrides {
    IdentityClaimOverrides {
        valid_from: Some(1_747_526_400),
    }
}

fn test_config() -> IdentityConfig {
    IdentityConfig {
        chain_id: 1,
        trust_domain: "timestamp".into(),
        dns: "timestamp.inblock.io".into(),
        ip: "139.59.144.60".into(),
    }
}

#[tokio::test]
async fn mnemonic_to_address_matches_known_vector() {
    let identity = ServiceIdentity::from_mnemonic(TEST_MNEMONIC, &test_config())
        .await
        .expect("derive identity");
    assert_eq!(identity.address_eip55, TEST_ADDRESS_EIP55);
    assert_eq!(
        identity.server_did,
        format!("did:pkh:eip155:1:{TEST_ADDRESS_EIP55}")
    );
}

#[tokio::test]
async fn identity_tree_verifies_via_sdk() {
    let identity = ServiceIdentity::from_mnemonic(TEST_MNEMONIC, &test_config())
        .await
        .expect("derive identity");
    let tree = build_identity_tree(&identity, &fixed_overrides())
        .await
        .expect("build tree");

    let wrapper = AquaTreeWrapper::new(tree, None, None);
    let result = Aquafier::new()
        .verify_tree_sync(wrapper, vec![])
        .expect("sync verify");
    assert!(
        result.is_valid,
        "identity tree must verify cleanly through the SDK; status={} logs={:#?}",
        result.status, result.logs
    );
}

/// Golden JSON snapshot, normalised. If this test fails because the
/// expected shape changed deliberately, re-generate the fixture by
/// running `cargo test -p aqua-timestamp identity_snapshot_matches --
/// --nocapture` and copying the `actual` printout into the fixture.
#[tokio::test]
async fn identity_snapshot_matches_fixture() {
    let identity = ServiceIdentity::from_mnemonic(TEST_MNEMONIC, &test_config())
        .await
        .expect("derive identity");
    let tree = build_identity_tree(&identity, &fixed_overrides())
        .await
        .expect("build tree");
    let response = build_response(&identity, &tree).expect("build response");
    let normalised = normalise_for_snapshot(response);

    let golden_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/identity_golden.json");

    if std::env::var("AQUA_TIMESTAMP_BLESS").is_ok() {
        let pretty = serde_json::to_string_pretty(&normalised).unwrap();
        std::fs::write(&golden_path, format!("{pretty}\n")).expect("write golden");
        return;
    }

    let golden: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&golden_path).expect("read golden fixture"))
            .expect("parse golden fixture");

    if normalised != golden {
        let actual = serde_json::to_string_pretty(&normalised).unwrap();
        let expected = serde_json::to_string_pretty(&golden).unwrap();
        panic!(
            "identity snapshot mismatch.\n--- expected ---\n{expected}\n--- actual ---\n{actual}\n"
        );
    }
}
