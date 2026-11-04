//! The run directory of a `seal` run: everything a replay needs to re-verify, byte for byte as
//! the server served it. [`verify_complete`] names any missing or malformed file; [`Store`] is
//! the one way steps write, and in replay mode it never writes into the run directory.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use aqua_rs_sdk::core::seal::{MemberTree, PreparedSeal, SealAttestations, SealHead};
use aqua_rs_sdk::primitives::merkle::{shielded_leaf, BatchDigest};
use aqua_rs_sdk::primitives::RevisionLink;
use aqua_rs_sdk::schema::tree::Tree;
use aqua_rs_sdk::schema::FileData;
use aqua_rs_sdk::Aquafier;
use serde_json::Value;

use super::log::StepLog;
use crate::witness::{parse_witness, WitnessMethod};

pub const RUN_JSON: &str = "run.json";
pub const AQUA_IDENTITY: &str = "aqua-identity.json";
pub const SET_FOLDER: &str = "set-folder.json";
pub const LEAVES: &str = "leaves.json";
pub const FETCH_STATUS: &str = "fetch-status.json";
pub const CONTAINER_1: &str = "container-1.json";
pub const ATTESTATIONS_1: &str = "attestations-1.json";

/// A seal run seals one set of this many members, twice.
pub const MEMBERS: usize = 3;
/// The witnesses a run pulls: file, `fetch-status.json` key, method.
pub const WITNESS_FILES: [(&str, &str, WitnessMethod); 3] = [
    ("s1-evm.json", "s1_evm", WitnessMethod::Evm),
    ("s1-qtsa.json", "s1_qtsa", WitnessMethod::Qtsa),
    ("s2-qtsa.json", "s2_qtsa", WitnessMethod::Qtsa),
];

pub fn prepared_file(seal: usize) -> String {
    format!("prepared-seal-{seal}.json")
}
pub fn nonces_file(seal: usize) -> String {
    format!("nonces-{seal}.json")
}
pub fn member_tree_file(member: usize) -> String {
    format!("members/m{member}/tree.json")
}
pub fn member_name(member: usize) -> String {
    format!("m{member}.txt")
}
pub fn member_body_file(member: usize) -> String {
    format!("members/m{member}/files/{}", member_name(member))
}
pub fn epochs_file(epoch: u64) -> String {
    format!("epochs-{epoch}.json")
}
pub fn epoch_file(epoch: u64, method: WitnessMethod) -> String {
    format!("epoch-{epoch}-{}.json", method.as_str())
}

/// A run directory file that is missing or malformed. Never a pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunDirError {
    pub dir: PathBuf,
    pub file: String,
    pub problem: String,
}

impl fmt::Display for RunDirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "run directory {}: file {}: {}",
            self.dir.display(),
            self.file,
            self.problem
        )
    }
}

impl std::error::Error for RunDirError {}

fn named(dir: &Path, file: &str, problem: impl Into<String>) -> RunDirError {
    RunDirError {
        dir: dir.to_path_buf(),
        file: file.to_string(),
        problem: problem.into(),
    }
}

fn text_of(dir: &Path, file: &str) -> Result<String, RunDirError> {
    let path = dir.join(file);
    match std::fs::read_to_string(&path) {
        Ok(text) => Ok(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(named(dir, file, "missing")),
        Err(e) => Err(named(dir, file, format!("unreadable: {e}"))),
    }
}

fn typed<T: serde::de::DeserializeOwned>(dir: &Path, file: &str) -> Result<T, RunDirError> {
    serde_json::from_str(&text_of(dir, file)?)
        .map_err(|e| named(dir, file, format!("malformed: {e}")))
}

/// `0x` + 64 lowercase hex.
pub fn hex_digest(d: &BatchDigest) -> String {
    format!("0x{}", hex::encode(d))
}

pub fn digest_from_hex(s: &str) -> Result<BatchDigest> {
    let b = hex::decode(s.trim_start_matches("0x")).context("hex")?;
    <[u8; 32]>::try_from(b.as_slice()).map_err(|_| anyhow!("expected 32 bytes, got {}", b.len()))
}

fn nonces(dir: &Path, seal: usize) -> Result<Vec<BatchDigest>, RunDirError> {
    let file = nonces_file(seal);
    let raw: Vec<String> = typed(dir, &file)?;
    if raw.len() != MEMBERS {
        return Err(named(
            dir,
            &file,
            format!("malformed: {} nonces, expected {MEMBERS}", raw.len()),
        ));
    }
    raw.iter()
        .map(|s| digest_from_hex(s).map_err(|e| named(dir, &file, format!("malformed: {e:#}"))))
        .collect()
}

fn epoch_of(dir: &Path, meta: &Value) -> Result<u64, RunDirError> {
    meta["epoch_id"]
        .as_u64()
        .ok_or_else(|| named(dir, RUN_JSON, "malformed: no numeric epoch_id"))
}

/// Everything a replay reads is present and parses. Any gap is a [`RunDirError`] naming the file,
/// before any step runs.
pub fn verify_complete(dir: &Path) -> Result<(), RunDirError> {
    let meta: Value = typed(dir, RUN_JSON)?;
    let epoch = epoch_of(dir, &meta)?;
    for key in ["s1", "s2"] {
        if meta[key].as_str().is_none() {
            return Err(named(dir, RUN_JSON, format!("malformed: no string {key}")));
        }
    }
    let identity: Value = typed(dir, AQUA_IDENTITY)?;
    if identity["server_did"].as_str().is_none() {
        return Err(named(dir, AQUA_IDENTITY, "malformed: no string server_did"));
    }
    let _: Tree = typed(dir, SET_FOLDER)?;
    for member in 1..=MEMBERS {
        let _: Tree = typed(dir, &member_tree_file(member))?;
        let body = member_body_file(member);
        if !dir.join(&body).is_file() {
            return Err(named(dir, &body, "missing"));
        }
    }
    for seal in 1..=2 {
        nonces(dir, seal)?;
        let _: PreparedSeal = typed(dir, &prepared_file(seal))?;
    }
    for (file, _, method) in WITNESS_FILES {
        parse_witness(method, &text_of(dir, file)?)
            .map_err(|e| named(dir, file, format!("malformed: {e}")))?;
    }
    let _: Tree = typed(dir, CONTAINER_1)?;
    SealAttestations::parse(&text_of(dir, ATTESTATIONS_1)?)
        .map_err(|e| named(dir, ATTESTATIONS_1, format!("malformed: {e}")))?;
    let status: Value = typed(dir, FETCH_STATUS)?;
    for key in [
        "s1_evm",
        "s1_qtsa",
        "s2_qtsa",
        "epoch_evm",
        "epoch_qtsa",
        "epochs",
    ] {
        if status.get(key).is_none() {
            return Err(named(dir, FETCH_STATUS, format!("malformed: no {key}")));
        }
    }
    let epochs_name = epochs_file(epoch);
    let epochs: Value = typed(dir, &epochs_name)?;
    if epochs["epochs"].as_array().is_none() {
        return Err(named(dir, &epochs_name, "malformed: no epochs array"));
    }
    for method in [WitnessMethod::Evm, WitnessMethod::Qtsa] {
        let name = epoch_file(epoch, method);
        let body: Value = typed(dir, &name)?;
        if body["revisions"].as_object().is_none() {
            return Err(named(dir, &name, "malformed: no revisions object"));
        }
    }
    Ok(())
}

/// A path is refused when it sits inside (or is) `guarded`, compared as absolute lexical paths.
pub fn ensure_outside(path: &Path, guarded: &Path, what: &str, guarded_what: &str) -> Result<()> {
    let abs = std::path::absolute(path).with_context(|| format!("{}", path.display()))?;
    let guard = std::path::absolute(guarded).with_context(|| format!("{}", guarded.display()))?;
    if abs.starts_with(&guard) {
        anyhow::bail!(
            "{what} {} is inside {guarded_what} {}: refused",
            abs.display(),
            guard.display()
        );
    }
    Ok(())
}

/// How steps read the run directory and where what they derive goes.
#[derive(Debug, Clone)]
pub enum StoreMode {
    /// A live run: what a step derives is written into the run directory.
    Persist,
    /// A replay: nothing is written into the run directory. What a step derives goes to `out`
    /// if given, and what the run persisted is compared with it.
    Replay { out: Option<PathBuf> },
}

#[derive(Debug, Clone)]
pub struct Store {
    run: PathBuf,
    mode: StoreMode,
}

impl Store {
    pub fn new(run: &Path, mode: StoreMode) -> Self {
        Self {
            run: run.to_path_buf(),
            mode,
        }
    }

    pub fn run_dir(&self) -> &Path {
        &self.run
    }

    /// Where step logs and artifacts go; `None` writes nothing.
    pub fn write_dir(&self) -> Option<&Path> {
        match &self.mode {
            StoreMode::Persist => Some(&self.run),
            StoreMode::Replay { out } => out.as_deref(),
        }
    }

    pub fn read(&self, file: &str) -> Result<String> {
        let path = self.run.join(file);
        std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))
    }

    pub fn read_bytes(&self, file: &str) -> Result<Vec<u8>> {
        let path = self.run.join(file);
        std::fs::read(&path).with_context(|| format!("read {}", path.display()))
    }

    /// The files directly under `sub` in the run directory; none when it does not exist.
    pub fn list(&self, sub: &str) -> Result<Vec<String>> {
        let path = self.run.join(sub);
        if !path.exists() {
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&path).with_context(|| format!("{}", path.display()))? {
            names.push(entry?.file_name().to_string_lossy().into_owned());
        }
        names.sort();
        Ok(names)
    }

    /// A directory that exists even when empty, for the run's own record.
    pub fn ensure_dir(&self, sub: &str) -> Result<()> {
        if let Some(dir) = self.write_dir() {
            let path = dir.join(sub);
            std::fs::create_dir_all(&path).with_context(|| format!("mkdir {}", path.display()))?;
        }
        Ok(())
    }

    /// A step's output that a replay does not compare (it holds fresh randomness, or is a debug
    /// form).
    pub fn artifact(&self, file: &str, bytes: impl AsRef<[u8]>) -> Result<()> {
        match self.write_dir() {
            Some(dir) => write_file(&dir.join(file), bytes.as_ref()),
            None => Ok(()),
        }
    }

    /// A step's output that the same inputs must reproduce byte for byte: a replay compares it
    /// with what the run persisted and logs the assertion.
    pub fn derived(
        &self,
        log: &mut StepLog,
        file: &str,
        bytes: impl AsRef<[u8]>,
        falsifier: &str,
    ) -> Result<()> {
        let bytes = bytes.as_ref();
        if matches!(self.mode, StoreMode::Replay { .. }) {
            match std::fs::read(self.run.join(file)) {
                Ok(persisted) => {
                    log.check(
                        persisted == bytes,
                        format!(
                            "replay reproduces {file} byte for byte ({} vs {} persisted bytes)",
                            bytes.len(),
                            persisted.len()
                        ),
                        falsifier,
                    );
                }
                Err(_) => log.l(format!("{file}: not persisted by this run, not compared")),
            }
        }
        self.artifact(file, bytes)
    }
}

pub fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).with_context(|| format!("mkdir {}", p.display()))?;
    }
    std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
}

/// The Folder's genesis (the one revision without a previous revision): the set the head names.
pub fn genesis_of(t: &Tree) -> Result<RevisionLink> {
    let g: Vec<_> = t
        .revisions
        .iter()
        .filter(|(_, r)| r.get_previous_revision_hash().is_none())
        .map(|(k, _)| k.clone())
        .collect();
    match g.as_slice() {
        [one] => Ok(one.clone()),
        _ => anyhow::bail!(
            "expected exactly one genesis in the Folder tree, found {}",
            g.len()
        ),
    }
}

/// A member as persisted: name, tree, file bytes.
pub type MemberFiles = (String, Tree, Vec<u8>);

pub fn load_member_files(dir: &Path) -> Result<Vec<MemberFiles>, RunDirError> {
    (1..=MEMBERS)
        .map(|i| {
            let tree: Tree = typed(dir, &member_tree_file(i))?;
            let file = member_body_file(i);
            let bytes = std::fs::read(dir.join(&file))
                .map_err(|e| named(dir, &file, format!("unreadable: {e}")))?;
            Ok((member_name(i), tree, bytes))
        })
        .collect()
}

/// The members through the SDK's admission, off the runtime (the EVM host blocks on it).
pub async fn admit_members(aq: &Arc<Aquafier>, members: &[MemberFiles]) -> Result<Vec<MemberTree>> {
    let aq = aq.clone();
    let members = members.to_vec();
    blocking(move || {
        members
            .iter()
            .map(|(n, t, b)| {
                let file = FileData::new(n.clone(), b.clone(), n.clone().into());
                MemberTree::verify(&aq, t, &[], vec![file])
                    .map_err(|e| anyhow!("{n}: member tree not admitted: {e}"))
            })
            .collect::<Result<Vec<_>>>()
    })
    .await?
}

/// Every SDK verification call runs off the runtime: the EVM host blocks on its handle.
pub async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| anyhow!("blocking task failed: {e}"))
}

pub fn tips_of(members: &[MemberTree]) -> Result<Vec<RevisionLink>> {
    members
        .iter()
        .map(|m| {
            m.spine()
                .last()
                .cloned()
                .ok_or_else(|| anyhow!("member has no spine"))
        })
        .collect()
}

/// The two heads over one set: seal `i`'s leaves from the tips and its nonces, through the SDK.
pub fn leaves_of(tips: &[RevisionLink], nonces: &[BatchDigest]) -> Result<Vec<BatchDigest>> {
    tips.iter()
        .zip(nonces)
        .map(|(t, n)| shielded_leaf(t, n).map_err(|e| anyhow!("shielded_leaf: {e}")))
        .collect()
}

/// The persisted client state of a run, read back. Steps work from this alone.
pub struct RunState {
    pub meta: Value,
    pub server_did: String,
    /// The sealer's DID as the persisted prepared seal 1 names it.
    pub did: String,
    pub set: RevisionLink,
    pub members: Vec<MemberFiles>,
    pub tips: Vec<RevisionLink>,
    pub nonces: [Vec<BatchDigest>; 2],
    pub leaves: [Vec<BatchDigest>; 2],
    pub heads: [SealHead; 2],
}

impl RunState {
    pub async fn load(dir: &Path, aq: &Arc<Aquafier>) -> Result<Self> {
        let meta: Value = typed(dir, RUN_JSON)?;
        let identity: Value = typed(dir, AQUA_IDENTITY)?;
        let server_did = identity["server_did"]
            .as_str()
            .ok_or_else(|| named(dir, AQUA_IDENTITY, "malformed: no string server_did"))?
            .to_string();
        let folder: Tree = typed(dir, SET_FOLDER)?;
        let set = genesis_of(&folder).map_err(|e| named(dir, SET_FOLDER, format!("{e:#}")))?;
        let members = load_member_files(dir)?;
        let admitted = admit_members(aq, &members).await?;
        let tips = tips_of(&admitted)?;
        let nonces = [nonces(dir, 1)?, nonces(dir, 2)?];
        let leaves = [leaves_of(&tips, &nonces[0])?, leaves_of(&tips, &nonces[1])?];
        let heads = [
            SealHead::from_leaves(set.clone(), &leaves[0]).map_err(|e| anyhow!("head: {e}"))?,
            SealHead::from_leaves(set.clone(), &leaves[1]).map_err(|e| anyhow!("head: {e}"))?,
        ];
        let mut signers = BTreeSet::new();
        for (seal, key) in [(1, "s1"), (2, "s2")] {
            let file = prepared_file(seal);
            let prepared: PreparedSeal = typed(dir, &file)?;
            signers.insert(
                prepared
                    .signer()
                    .map_err(|e| named(dir, &file, format!("malformed: {e}")))?
                    .to_owned(),
            );
            let digest = prepared
                .submit_digest()
                .map_err(|e| named(dir, &file, format!("malformed: {e}")))?;
            let digest = hex_digest(&digest);
            if meta[key].as_str() != Some(digest.as_str()) {
                return Err(named(
                    dir,
                    RUN_JSON,
                    format!(
                        "{key} is {}, {file} submits {digest}",
                        meta[key].as_str().unwrap_or("absent")
                    ),
                )
                .into());
            }
        }
        if signers.len() != 1 {
            return Err(named(
                dir,
                &prepared_file(2),
                format!("the prepared seals name different signers: {signers:?}"),
            )
            .into());
        }
        let did = signers.into_iter().next().unwrap_or_default();
        Ok(Self {
            meta,
            server_did,
            did,
            set,
            members,
            tips,
            nonces,
            leaves,
            heads,
        })
    }
}
