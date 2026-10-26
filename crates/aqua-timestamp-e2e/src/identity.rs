//! The one standing test identity of the OpenWitness e2e (OW1.5, audit E).
//!
//! A remote run signs in with ONE secp256k1 identity that persists across runs, so the
//! operator can find that user in the aggregator's records and see that the test ran. The
//! key lives in a state directory (default `~/.local/state/openwitness-seal-e2e/`):
//!
//! ```text
//! <dir>/            0700
//!   secp256k1.key   0600   64 hex chars (the 32-byte private key) + newline
//!   identity.json   0600   {"alias","did","key_type","created_at"}
//! ```
//!
//! Rules enforced by [`load_or_create`]:
//!
//! * created once: the key and the record are written only when the key file is absent, with
//!   `create_new` (an existing file is never truncated or replaced);
//! * never rotated: an existing key is loaded as it is; a record that names another DID than
//!   the key derives, or a key without a record, is an error, not a repair;
//! * never loose: a state directory or key file readable by group or others is refused.
//!
//! Other key types (ed25519, p256) have no standing identity: those cases run only in-process
//! (`selfcheck-all`) with ephemeral keys against a throwaway server, never against a remote.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::flow::ClientKey;

/// The alias that names this test, recorded beside the key.
pub const ALIAS: &str = "openwitness-seal-e2e";
/// Private key file (hex), 0600.
pub const KEY_FILE: &str = "secp256k1.key";
/// Identity record, 0600.
pub const RECORD_FILE: &str = "identity.json";
/// The one key type with a standing identity.
pub const KEY_TYPE: &str = "secp256k1";

/// What `identity.json` holds. No secret.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityRecord {
    pub alias: String,
    pub did: String,
    pub key_type: String,
    /// RFC 3339 UTC time the identity was created.
    pub created_at: String,
}

/// The loaded standing identity.
pub struct StandingIdentity {
    pub record: IdentityRecord,
    /// True only on the run that created the identity.
    pub created: bool,
    key: [u8; 32],
}

impl StandingIdentity {
    /// The sign-in key for the flow.
    pub fn client_key(&self) -> Result<ClientKey> {
        ClientKey::from_secp256k1_bytes(self.key)
    }
}

/// `~/.local/state/openwitness-seal-e2e`.
pub fn default_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?;
    Ok(PathBuf::from(home).join(".local/state/openwitness-seal-e2e"))
}

fn require_private(path: &Path, what: &str) -> Result<()> {
    let meta = fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "{what} {} has mode {mode:o}: readable or writable by group or others; refusing to use it \
             (fix with chmod, the key is never rotated or rewritten by the test)",
            path.display()
        );
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create {} (create_new, never overwrites)", path.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("write {}", path.display()))?;
    f.sync_all().ok();
    Ok(())
}

fn read_key(path: &Path) -> Result<[u8; 32]> {
    let meta = fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if !meta.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    require_private(path, "key file")?;
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let bytes = hex::decode(text.trim()).context("key file is not hex")?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| anyhow!("key file holds {} bytes, expected 32", bytes.len()))
}

/// Load the standing identity from `dir`, creating it once if the key file is absent.
pub fn load_or_create(dir: &Path) -> Result<StandingIdentity> {
    if !dir.exists() {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("create {}", dir.display()))?;
    }
    let dmeta = fs::symlink_metadata(dir).with_context(|| format!("stat {}", dir.display()))?;
    if !dmeta.is_dir() {
        bail!("{} is not a directory", dir.display());
    }
    require_private(dir, "state directory")?;

    let key_path = dir.join(KEY_FILE);
    let record_path = dir.join(RECORD_FILE);

    if !key_path.exists() {
        if record_path.exists() {
            bail!(
                "{} exists but {} does not: refusing to create a second identity beside an existing record",
                record_path.display(),
                key_path.display()
            );
        }
        // Create once. A key the curve rejects (probability about 2^-128) is retried.
        let (key, client) = loop {
            let mut key = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut key);
            if let Ok(c) = ClientKey::from_secp256k1_bytes(key) {
                break (key, c);
            }
        };
        let record = IdentityRecord {
            alias: ALIAS.to_string(),
            did: client.did.clone(),
            key_type: KEY_TYPE.to_string(),
            created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        };
        // Key first: if the record write then fails, the next run refuses (key without record)
        // instead of silently minting another identity.
        write_new(&key_path, format!("{}\n", hex::encode(key)).as_bytes())?;
        write_new(
            &record_path,
            serde_json::to_string_pretty(&record)?.as_bytes(),
        )?;
        return Ok(StandingIdentity {
            record,
            created: true,
            key,
        });
    }

    let key = read_key(&key_path)?;
    let client = ClientKey::from_secp256k1_bytes(key).context("derive DID from the key file")?;
    if !record_path.exists() {
        bail!(
            "{} exists but {} does not: refusing to guess the record (restore it or move the key aside by hand)",
            key_path.display(),
            record_path.display()
        );
    }
    require_private(&record_path, "identity record")?;
    let record: IdentityRecord = serde_json::from_str(
        &fs::read_to_string(&record_path)
            .with_context(|| format!("read {}", record_path.display()))?,
    )
    .with_context(|| format!("parse {}", record_path.display()))?;
    if record.did != client.did {
        bail!(
            "{} names {} but the key derives {}: refusing to continue",
            record_path.display(),
            record.did,
            client.did
        );
    }
    if record.alias != ALIAS {
        bail!(
            "{} has alias {:?}, expected {ALIAS:?}: this is not the e2e's identity directory",
            record_path.display(),
            record.alias
        );
    }
    Ok(StandingIdentity {
        record,
        created: false,
        key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn created_once_with_private_modes_and_alias() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("state");
        let a = load_or_create(&dir).unwrap();
        assert!(a.created);
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join(KEY_FILE)), 0o600);
        assert_eq!(mode(&dir.join(RECORD_FILE)), 0o600);
        assert_eq!(a.record.alias, "openwitness-seal-e2e");
        assert!(a.record.did.starts_with("did:pkh:eip155:1:0x"));
        assert_eq!(a.record.key_type, "secp256k1");
        assert!(a.record.created_at.ends_with('Z'));
        // The record on disk is the record in memory and holds no secret.
        let on_disk = fs::read_to_string(dir.join(RECORD_FILE)).unwrap();
        assert!(!on_disk.contains(&hex::encode(a.key)));
        let parsed: IdentityRecord = serde_json::from_str(&on_disk).unwrap();
        assert_eq!(parsed, a.record);
    }

    #[test]
    fn second_load_reuses_and_never_overwrites() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("state");
        let a = load_or_create(&dir).unwrap();
        let key_before = fs::read(dir.join(KEY_FILE)).unwrap();
        let rec_before = fs::read(dir.join(RECORD_FILE)).unwrap();
        for _ in 0..3 {
            let b = load_or_create(&dir).unwrap();
            assert!(!b.created);
            assert_eq!(b.record, a.record);
            assert_eq!(b.client_key().unwrap().did, a.record.did);
        }
        assert_eq!(fs::read(dir.join(KEY_FILE)).unwrap(), key_before);
        assert_eq!(fs::read(dir.join(RECORD_FILE)).unwrap(), rec_before);
    }

    #[test]
    fn refuses_a_world_readable_key_and_leaves_it_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("state");
        load_or_create(&dir).unwrap();
        let key_path = dir.join(KEY_FILE);
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).unwrap();
        let before = fs::read(&key_path).unwrap();
        let err = load_or_create(&dir).err().expect("must refuse").to_string();
        assert!(err.contains("key file") && err.contains("644"), "{err}");
        assert_eq!(fs::read(&key_path).unwrap(), before);
        assert_eq!(mode(&key_path), 0o644, "the test must not chmod the key");
    }

    #[test]
    fn refuses_a_group_readable_key_and_a_loose_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("state");
        load_or_create(&dir).unwrap();
        fs::set_permissions(dir.join(KEY_FILE), fs::Permissions::from_mode(0o640)).unwrap();
        assert!(load_or_create(&dir).is_err());
        fs::set_permissions(dir.join(KEY_FILE), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let err = load_or_create(&dir).err().expect("must refuse").to_string();
        assert!(err.contains("state directory"), "{err}");
    }

    #[test]
    fn refuses_a_record_that_names_another_did() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("state");
        let a = load_or_create(&dir).unwrap();
        let mut rec = a.record.clone();
        rec.did = "did:pkh:eip155:1:0x0000000000000000000000000000000000000001".into();
        fs::write(dir.join(RECORD_FILE), serde_json::to_string(&rec).unwrap()).unwrap();
        let key_before = fs::read(dir.join(KEY_FILE)).unwrap();
        assert!(load_or_create(&dir).is_err());
        assert_eq!(fs::read(dir.join(KEY_FILE)).unwrap(), key_before);
    }

    #[test]
    fn key_without_record_or_record_without_key_is_not_repaired() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("state");
        load_or_create(&dir).unwrap();
        fs::remove_file(dir.join(RECORD_FILE)).unwrap();
        assert!(load_or_create(&dir).is_err());
        assert!(!dir.join(RECORD_FILE).exists(), "no record is invented");

        let dir2 = tmp.path().join("state2");
        load_or_create(&dir2).unwrap();
        fs::remove_file(dir2.join(KEY_FILE)).unwrap();
        assert!(load_or_create(&dir2).is_err());
        assert!(!dir2.join(KEY_FILE).exists(), "no second key is minted");
    }

    #[test]
    fn a_garbage_key_file_is_an_error_not_a_reset() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("state");
        load_or_create(&dir).unwrap();
        fs::write(dir.join(KEY_FILE), "not hex\n").unwrap();
        assert!(load_or_create(&dir).is_err());
        assert_eq!(fs::read_to_string(dir.join(KEY_FILE)).unwrap(), "not hex\n");
    }

    #[test]
    fn distinct_directories_get_distinct_identities() {
        let tmp = tempfile::tempdir().unwrap();
        let a = load_or_create(&tmp.path().join("a")).unwrap();
        let b = load_or_create(&tmp.path().join("b")).unwrap();
        assert_ne!(a.record.did, b.record.did);
    }
}
