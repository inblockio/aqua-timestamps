//! The live part of `seal`: the one place that holds the standing identity, a bearer token and
//! an HTTP client. It builds the two prepared seals, signs in, makes the run's only POSTs
//! (`/auth/session`, one `/v1/leaves`), waits for the epoch, pulls the witnesses and persists
//! every served body byte for byte. Then it drops the token and hands over to the steps.
//!
//! The identity reaches this module already loaded: see [`crate::identity::for_base_url`].

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use aqua_rs_sdk::core::seal::{prepare_seal, PreparedSeal, SealHead};
use aqua_rs_sdk::primitives::merkle::BatchDigest;
use aqua_rs_sdk::primitives::RevisionLink;
use aqua_rs_sdk::schema::template::BuiltInTemplate;
use aqua_rs_sdk::schema::templates::Folder;
use aqua_rs_sdk::schema::{AquaTreeWrapper, FileData};
use rand::RngCore;
use reqwest::Client;
use serde_json::{json, Value};

use super::log::{all_passed, utc, StepLog};
use super::policy::Reader;
use super::run_dir::{
    admit_members, ensure_outside, epoch_file, epochs_file, genesis_of, hex_digest, leaves_of,
    load_member_files, member_body_file, member_name, member_tree_file, nonces_file, prepared_file,
    tips_of, write_file, RunState, Store, StoreMode, AQUA_IDENTITY, FETCH_STATUS, LEAVES, MEMBERS,
    RUN_JSON, SET_FOLDER,
};
use super::sdk_rev;
use super::steps::{self, Ctx, Steps};
use crate::flow::{
    get_retrying, http_get, http_post, mint_bearer, wait_for_seal, PollBudget, SealTrigger,
};
use crate::identity::StandingIdentity;
use crate::target::is_loopback;
use crate::witness::{fetch_served, WitnessMethod};

/// Local clock ahead of the server by more than this stops the run: a T the SDK would read as
/// older than the local H is refused (the ordering row).
const MAX_CLOCK_AHEAD_SECS: i64 = 60;

/// Everything `seal` needs besides the identity.
pub struct SealConfig {
    pub base_url: String,
    pub run_dir: PathBuf,
    /// Where the identity lives: the run directory must be outside it.
    pub identity_dir: PathBuf,
    pub reader: Reader,
    pub seal_trigger: SealTrigger,
    /// When set, `/version`'s revision must equal it before anything is posted.
    pub expect_version: Option<String>,
    /// What `/.well-known/aqua-identity` must serve before anything is posted, and what step 2
    /// compares. Required unless `base_url` is loopback.
    pub expect_server_did: Option<String>,
    /// How long after the epoch's close to wait for its seal.
    pub seal_grace: Duration,
    /// How long after the epoch's close to wait for the witnesses (EVM serves at finality).
    pub witness_grace: Duration,
    pub poll_interval: Duration,
    /// How long step 1 retries "EVM not final yet" and "EVM host unavailable".
    pub finality_budget: Duration,
}

pub struct SealReport {
    pub logs: Vec<StepLog>,
    pub run_dir: PathBuf,
    /// `/version` read before the first POST and after the last step.
    pub version_before: String,
    pub version_after: String,
}

impl SealReport {
    pub fn passed(&self) -> bool {
        all_passed(&self.logs)
    }
}

/// The `revision` of a `GET /version` body.
pub fn served_revision(body: &str) -> Result<String> {
    let v: Value = serde_json::from_str(body).context("/version is not JSON")?;
    v["revision"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("/version has no string `revision`: {body}"))
}

/// The version guard before the first POST: `--expect-version`, when given, must be what serves.
pub fn check_expected_version(before: &str, expect: Option<&str>) -> Result<()> {
    if let Some(want) = expect {
        let got = served_revision(before)?;
        if got != want {
            bail!("/version serves {got}, --expect-version wants {want}: nothing was posted");
        }
    }
    Ok(())
}

/// Ruling 10: a remote run with no server DID pin is refused at the start. There is no default
/// in code; loopback is the only place a run may take the served DID as it comes.
pub fn require_server_did_pin(base_url: &str, pin: Option<&str>) -> Result<()> {
    if pin.is_none() && !is_loopback(base_url) {
        bail!("--expect-server-did is required on a non-loopback --base-url: {base_url} was not contacted");
    }
    Ok(())
}

/// The server DID pin before the first POST: what `/.well-known/aqua-identity` serves must be
/// what `--expect-server-did` names, byte for byte.
pub fn check_expected_server_did(identity_body: &str, expect: Option<&str>) -> Result<()> {
    if let Some(want) = expect {
        let identity: Value = serde_json::from_str(identity_body).context("aqua-identity json")?;
        let got = identity["server_did"].as_str().unwrap_or("");
        if got != want {
            bail!(
                "/.well-known/aqua-identity serves {got}, --expect-server-did wants {want}: nothing was posted"
            );
        }
    }
    Ok(())
}

/// The version guard after the run: the server that answered at the start still answers. `Err`
/// is the text of the failed assertion.
pub fn check_version_unchanged(before: &str, after: &str) -> std::result::Result<(), String> {
    if before == after {
        Ok(())
    } else {
        Err(format!(
            "/version moved during the run: before {before}, after {after}"
        ))
    }
}

/// What the run reads before it posts anything.
struct Preflight {
    version: String,
    identity_body: String,
    lines: Vec<String>,
}

async fn text_of(client: &Client, url: &str) -> Result<(u16, String)> {
    let resp = http_get(client, url, None).await?;
    let status = resp.status().as_u16();
    Ok((status, resp.text().await.unwrap_or_default()))
}

async fn preflight(client: &Client, base_url: &str) -> Result<Preflight> {
    let mut lines = Vec::new();
    let (status, version) = text_of(client, &format!("{base_url}/version")).await?;
    lines.push(format!("GET /version -> HTTP {status} {version}"));
    served_revision(&version)?;
    let health = http_get(client, &format!("{base_url}/health"), None).await?;
    let status = health.status().as_u16();
    let date = health
        .headers()
        .get(reqwest::header::DATE)
        .and_then(|d| d.to_str().ok())
        .map(str::to_string);
    let body = health.text().await.unwrap_or_default();
    lines.push(format!("GET /health -> HTTP {status} {body}"));
    if status != 200 {
        bail!("GET /health: HTTP {status} {body}");
    }
    let Some(date) = date else {
        bail!("no Date header on /health");
    };
    let local = chrono::Utc::now();
    let server = chrono::DateTime::parse_from_rfc2822(&date).context("Date header")?;
    let ahead = local.timestamp() - server.timestamp();
    lines.push(format!(
        "clock: server Date {date}, local {}, local minus server = {ahead} s (stops above {MAX_CLOCK_AHEAD_SECS})",
        local.to_rfc2822()
    ));
    if ahead > MAX_CLOCK_AHEAD_SECS {
        bail!("local clock ahead of the server by {ahead} s");
    }
    let (status, identity_body) =
        text_of(client, &format!("{base_url}/.well-known/aqua-identity")).await?;
    if status != 200 {
        bail!("GET /.well-known/aqua-identity: HTTP {status}");
    }
    lines.push(format!("GET /.well-known/aqua-identity -> {identity_body}"));
    let identity: Value = serde_json::from_str(&identity_body).context("aqua-identity json")?;
    if identity["server_did"].as_str().is_none() {
        bail!("/.well-known/aqua-identity has no string server_did");
    }
    Ok(Preflight {
        version,
        identity_body,
        lines,
    })
}

/// The Folder, three signed members, two nonce sets and the two prepared seals, all persisted
/// before anything leaves this machine.
async fn build_local_state(
    run: &Path,
    reader: &Reader,
    identity: &StandingIdentity,
    run_id: &str,
) -> Result<[PreparedSeal; 2]> {
    let aq = &reader.aq;
    let folder = aq
        .create_object(
            RevisionLink::from_bytes(Folder::TEMPLATE_LINK),
            None,
            json!({"name": format!("openwitness-seal-e2e {run_id}"), "items": []}),
            None,
        )
        .map_err(|e| anyhow!("create_object Folder: {e:?}"))?;
    write_file(
        &run.join(SET_FOLDER),
        (serde_json::to_string_pretty(&folder)? + "\n").as_bytes(),
    )?;

    let creds = identity.signing_credentials();
    for i in 1..=MEMBERS {
        let name = member_name(i);
        let body = format!("openwitness-seal-e2e member {i} {run_id}");
        let file = FileData::new(name.clone(), body.as_bytes().to_vec(), name.clone().into());
        let genesis = aq
            .create_minimal_genesis_revision(file, None)
            .map_err(|e| anyhow!("member genesis: {e:?}"))?;
        let link = genesis
            .revisions
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| anyhow!("empty member genesis"))?;
        let signed = aq
            .sign_aqua_tree(
                AquaTreeWrapper::new(genesis, None, Some(link)),
                &creds,
                None,
                None,
            )
            .await
            .map_err(|e| anyhow!("sign member: {e:?}"))?
            .aqua_tree;
        write_file(
            &run.join(member_tree_file(i)),
            (serde_json::to_string_pretty(&signed)? + "\n").as_bytes(),
        )?;
        write_file(&run.join(member_body_file(i)), body.as_bytes())?;
    }

    // Receipt nonces: 32 random bytes per entry from the OS RNG, one set per seal.
    let mut nonce_sets: Vec<Vec<BatchDigest>> = Vec::new();
    for seal in 1..=2 {
        let mut set = Vec::new();
        for _ in 0..MEMBERS {
            let mut n = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut n);
            set.push(n);
        }
        let shown: Vec<String> = set.iter().map(hex_digest).collect();
        write_file(
            &run.join(nonces_file(seal)),
            (serde_json::to_string_pretty(&shown)? + "\n").as_bytes(),
        )?;
        nonce_sets.push(set);
    }

    let members = load_member_files(run)?;
    let admitted = admit_members(aq, &members).await?;
    let tips = tips_of(&admitted)?;
    let set = genesis_of(&folder)?;
    let mut prepared = Vec::new();
    let mut leaves_out = Vec::new();
    for (seal, nonces) in nonce_sets.iter().enumerate() {
        let leaves = leaves_of(&tips, nonces)?;
        leaves_out.push(leaves.iter().map(hex_digest).collect::<Vec<_>>());
        let head = SealHead::from_leaves(set.clone(), &leaves).map_err(|e| anyhow!("{e}"))?;
        let p = prepare_seal(aq, &head, &creds)
            .await
            .map_err(|e| anyhow!("prepare_seal: {e}"))?;
        let signer = p.signer().map_err(|e| anyhow!("{e}"))?;
        if signer != identity.record.did {
            bail!(
                "prepared.signer() {signer} differs from identity.json {}",
                identity.record.did
            );
        }
        write_file(
            &run.join(prepared_file(seal + 1)),
            (serde_json::to_string_pretty(&p)? + "\n").as_bytes(),
        )?;
        prepared.push(p);
    }
    write_file(
        &run.join(LEAVES),
        (serde_json::to_string_pretty(&json!({"seal_1": leaves_out[0], "seal_2": leaves_out[1]}))?
            + "\n")
            .as_bytes(),
    )?;
    <[PreparedSeal; 2]>::try_from(prepared).map_err(|_| anyhow!("expected two prepared seals"))
}

fn write_run_json(run: &Path, meta: &Value) -> Result<()> {
    write_file(
        &run.join(RUN_JSON),
        (serde_json::to_string_pretty(meta)? + "\n").as_bytes(),
    )
}

/// Sign in, one `POST /v1/leaves` with both S, wait, pull, persist. The token ends here.
async fn submit_and_pull(
    client: &Client,
    cfg: &SealConfig,
    identity: &StandingIdentity,
    run_id: &str,
    sdk: &str,
    pre: &Preflight,
    prepared: &[PreparedSeal; 2],
) -> Result<()> {
    let (base_url, run) = (cfg.base_url.as_str(), cfg.run_dir.as_path());
    let s1 = hex_digest(&prepared[0].submit_digest().map_err(|e| anyhow!("{e}"))?);
    let s2 = hex_digest(&prepared[1].submit_digest().map_err(|e| anyhow!("{e}"))?);
    println!("S1 {s1}\nS2 {s2}");

    let bearer = mint_bearer(client, base_url, &identity.client_key()?).await?;
    // The record exists before the POST: an answer that never arrives or cannot be read may still
    // mean the server holds the leaves, and a rerun must not overwrite their prepared seals.
    let mut meta = json!({
        "run_id": run_id,
        "base_url": base_url,
        "s1": s1,
        "s2": s2,
        "submitted_at": utc(),
        "post_status": Value::Null,
        "server_version_before": pre.version,
        "sdk_rev": sdk,
    });
    write_run_json(run, &meta)?;
    let resp = http_post(
        client,
        &format!("{base_url}/v1/leaves"),
        Some(&bearer),
        &json!({"leaves": [s1, s2]}),
    )
    .await?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    println!("POST /v1/leaves -> {status} {body}");
    meta["post_status"] = json!(status);
    meta["post_body"] = json!(body);
    write_run_json(run, &meta)?;
    if status != 202 {
        bail!("POST /v1/leaves: expected 202, got {status} {body}");
    }
    let posted: Value = serde_json::from_str(&body).context("leaves response json")?;
    let epoch_id = posted["epoch_id"]
        .as_u64()
        .ok_or_else(|| anyhow!("leaves response has no epoch_id"))?;
    let closes_at = posted["epoch_closes_at"]
        .as_u64()
        .ok_or_else(|| anyhow!("leaves response has no epoch_closes_at"))?;
    meta["post_body"] = posted;
    meta["epoch_id"] = json!(epoch_id);
    meta["epoch_closes_at"] = json!(closes_at);
    write_run_json(run, &meta)?;

    if let SealTrigger::Driver(drive) = &cfg.seal_trigger {
        drive().await;
    }
    let after_close = |grace: Duration| {
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        Instant::now() + Duration::from_secs(closes_at.saturating_sub(now)) + grace
    };
    wait_for_seal(
        client,
        base_url,
        epoch_id,
        after_close(cfg.seal_grace),
        cfg.poll_interval,
        &mut |line| println!("{line}"),
    )
    .await?;
    println!("epoch {epoch_id} sealed at {}", utc());

    let budget = PollBudget {
        deadline: after_close(cfg.witness_grace),
        interval: cfg.poll_interval,
    };
    let show = |line: String| println!("{line}");
    let (mut log1, mut log2, mut log3) = (show, show, show);
    let (r1e, r1q, r2q) = tokio::join!(
        fetch_served(
            client,
            base_url,
            &s1,
            &bearer,
            WitnessMethod::Evm,
            &budget,
            &mut log1
        ),
        fetch_served(
            client,
            base_url,
            &s1,
            &bearer,
            WitnessMethod::Qtsa,
            &budget,
            &mut log2
        ),
        fetch_served(
            client,
            base_url,
            &s2,
            &bearer,
            WitnessMethod::Qtsa,
            &budget,
            &mut log3
        ),
    );
    let mut fetch_status = serde_json::Map::new();
    for (key, file, result) in [
        ("s1_evm", "s1-evm.json", r1e),
        ("s1_qtsa", "s1-qtsa.json", r1q),
        ("s2_qtsa", "s2-qtsa.json", r2q),
    ] {
        match result {
            Ok((status, body)) => {
                write_file(&run.join(file), body.as_bytes())?;
                fetch_status.insert(key.into(), json!({"status": status, "at": utc()}));
            }
            Err(e) => {
                fetch_status.insert(
                    key.into(),
                    json!({"status": Value::Null, "error": e.to_string(), "at": utc()}),
                );
            }
        }
    }
    let reads = read_epoch_bodies(
        client,
        base_url,
        &bearer,
        epoch_id,
        run,
        budget,
        &mut |line| println!("{line}"),
    )
    .await?;
    fetch_status.extend(reads);
    write_file(
        &run.join(FETCH_STATUS),
        (serde_json::to_string_pretty(&Value::Object(fetch_status))? + "\n").as_bytes(),
    )
}

/// The epoch's listing per method and its `/v1/epochs` row, persisted byte for byte, each read
/// retried within `budget` (see [`get_retrying`]). The answers go into `fetch-status.json`. A read
/// that stays down is recorded with its error and leaves no body, which fails step 7; it does not
/// discard a run that already holds its witnesses.
pub async fn read_epoch_bodies(
    client: &Client,
    base_url: &str,
    bearer: &str,
    epoch_id: u64,
    run: &Path,
    budget: PollBudget,
    log: &mut dyn FnMut(String),
) -> Result<serde_json::Map<String, Value>> {
    let listing = |method: WitnessMethod| {
        (
            format!("epoch_{}", method.as_str()),
            epoch_file(epoch_id, method),
            format!(
                "{base_url}/trees?epoch={epoch_id}&method={}",
                method.as_str()
            ),
        )
    };
    let mut fetch_status = serde_json::Map::new();
    for (key, file, url) in [
        listing(WitnessMethod::Evm),
        listing(WitnessMethod::Qtsa),
        (
            "epochs".to_string(),
            epochs_file(epoch_id),
            format!("{base_url}/v1/epochs?from={epoch_id}&limit=1"),
        ),
    ] {
        let entry = match get_retrying(client, &url, Some(bearer), &budget, log).await {
            Ok((status, body)) => {
                write_file(&run.join(file), body.as_bytes())?;
                json!({"status": status, "at": utc()})
            }
            Err(last) => json!({"status": Value::Null, "error": last, "at": utc()}),
        };
        fetch_status.insert(key, entry);
    }
    Ok(fetch_status)
}

/// Refuse a run directory that holds anything, or sits beside the key. A run writes through what
/// it finds: a held file is overwritten (a rerun, the prepared seals), a held symlink is followed.
pub fn check_run_dir(run_dir: &Path, identity_dir: &Path) -> Result<()> {
    ensure_outside(run_dir, identity_dir, "--run-dir", "the identity directory")?;
    let mut held = match std::fs::read_dir(run_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("read --run-dir {}", run_dir.display())),
    };
    if let Some(entry) = held.next() {
        let entry = entry.with_context(|| format!("read --run-dir {}", run_dir.display()))?;
        bail!(
            "{} is not empty (holds {}): name another --run-dir",
            run_dir.display(),
            entry.file_name().to_string_lossy()
        );
    }
    Ok(())
}

/// The whole `seal` run. Failed step assertions are in the report, not an `Err`; an `Err` means
/// the live part stopped before the steps could run.
pub async fn run_seal(cfg: SealConfig, identity: &StandingIdentity) -> Result<SealReport> {
    require_server_did_pin(&cfg.base_url, cfg.expect_server_did.as_deref())?;
    check_run_dir(&cfg.run_dir, &cfg.identity_dir)?;
    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .context("build reqwest client")?;
    let sdk = sdk_rev()?;
    let pre = preflight(&client, &cfg.base_url).await?;
    check_expected_version(&pre.version, cfg.expect_version.as_deref())?;
    check_expected_server_did(&pre.identity_body, cfg.expect_server_did.as_deref())?;

    let run = cfg.run_dir.clone();
    std::fs::create_dir_all(&run).with_context(|| format!("mkdir {}", run.display()))?;
    std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", run.display()))?;
    write_file(&run.join(AQUA_IDENTITY), pre.identity_body.as_bytes())?;
    let run_id = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    println!("run id {run_id}, run directory {}", run.display());
    let prepared = build_local_state(&run, &cfg.reader, identity, &run_id).await?;
    submit_and_pull(&client, &cfg, identity, &run_id, &sdk, &pre, &prepared).await?;

    let mut header = vec![
        format!("# SDK rev (Cargo.lock) = {sdk}"),
        format!("# server /version before the run: {}", pre.version),
        format!(
            "# identity = {} (alias {}, created_at {})",
            identity.record.did, identity.record.alias, identity.record.created_at
        ),
        format!("# run directory = {}", run.display()),
    ];
    header.extend(pre.lines.iter().map(|l| format!("# preflight: {l}")));

    let state = RunState::load(&run, &cfg.reader.aq).await?;
    let ctx = Ctx {
        store: Store::new(&run, StoreMode::Persist),
        reader: cfg.reader,
        state,
        header,
        expect_server_did: cfg.expect_server_did,
        finality_budget: cfg.finality_budget,
    };
    let pending = "server /version after the run: pending, written at the end of the run";
    let mut logs = steps::run(&ctx, Steps::All, pending).await?;

    let version_after = match text_of(&client, &format!("{}/version", cfg.base_url)).await {
        Ok((_, body)) => body,
        Err(e) => format!("unreachable: {e:#}"),
    };
    let moved = check_version_unchanged(&pre.version, &version_after);
    let closing = format!("server /version after the run: {version_after}");
    for log in &mut logs {
        if let Err(why) = &moved {
            log.check(false, why, "server redeployed during the run");
        }
        log.write(&run, &closing)?;
    }
    let mut meta: Value = serde_json::from_str(&ctx.store.read(RUN_JSON)?)?;
    meta["server_version_after"] = json!(version_after);
    write_run_json(&run, &meta)?;
    Ok(SealReport {
        logs,
        run_dir: run,
        version_before: pre.version,
        version_after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const V: &str = r#"{"service":"aqua-timestamp","revision":"abc","dirty":false}"#;

    #[test]
    fn the_expected_version_is_optional_and_exact() {
        assert!(check_expected_version(V, None).is_ok());
        assert!(check_expected_version(V, Some("abc")).is_ok());
        assert!(check_expected_version(V, Some("ab")).is_err());
        assert!(check_expected_version(V, Some("abcd")).is_err());
        assert!(check_expected_version("not json", Some("abc")).is_err());
    }

    #[test]
    fn the_server_did_pin_is_exact_and_required_off_loopback() {
        let body = r#"{"server_did":"did:pkh:eip155:1:0xAbC"}"#;
        assert!(check_expected_server_did(body, None).is_ok());
        assert!(check_expected_server_did(body, Some("did:pkh:eip155:1:0xAbC")).is_ok());
        for other in ["did:pkh:eip155:1:0xabc", "did:pkh:eip155:1:0xAb", ""] {
            assert!(
                check_expected_server_did(body, Some(other)).is_err(),
                "{other}"
            );
        }
        assert!(check_expected_server_did("{}", Some("x")).is_err());
        assert!(require_server_did_pin("https://openwitness.org", None).is_err());
        assert!(require_server_did_pin("https://openwitness.org", Some("x")).is_ok());
        assert!(require_server_did_pin("http://127.0.0.1:8080", None).is_ok());
    }

    #[test]
    fn a_new_deploy_is_no_failure_a_move_during_the_run_is() {
        // No pinned value: any version passes as long as it stays.
        assert!(check_version_unchanged(V, V).is_ok());
        let moved = V.replace("abc", "def");
        assert!(check_version_unchanged(V, &moved).is_err());
        assert!(check_version_unchanged(V, "unreachable: x").is_err());
    }

    #[test]
    fn the_run_dir_may_not_sit_in_the_identity_dir_or_reuse_a_run() {
        let tmp = tempfile::tempdir().unwrap();
        let id = tmp.path().join("id");
        assert!(check_run_dir(&id.join("run"), &id).is_err());
        assert!(check_run_dir(&id, &id).is_err());
        let run = tmp.path().join("run");
        assert!(check_run_dir(&run, &id).is_ok());
        std::fs::create_dir_all(&run).unwrap();
        std::fs::write(run.join(RUN_JSON), "{}").unwrap();
        assert!(check_run_dir(&run, &id).is_err());
        // Prepared seals with no record yet: a crash before the POST. Still not overwritten.
        std::fs::remove_file(run.join(RUN_JSON)).unwrap();
        assert!(check_run_dir(&run, &id).is_ok());
        std::fs::write(run.join(prepared_file(2)), "{}").unwrap();
        assert!(check_run_dir(&run, &id).is_err());
    }

    #[test]
    fn a_symlink_in_a_fresh_run_dir_is_refused_and_its_target_keeps_its_bytes() {
        const KEY: &[u8] = b"the key, not to be truncated";
        let tmp = tempfile::tempdir().unwrap();
        let id = tmp.path().join("id");
        let key = tmp.path().join("key");
        std::fs::write(&key, KEY).unwrap();
        let run = tmp.path().join("run");
        std::fs::create_dir(&run).unwrap();
        let planted = run.join(AQUA_IDENTITY);
        std::os::unix::fs::symlink(&key, &planted).unwrap();

        // What the run does once the guard lets the directory through.
        let checked = check_run_dir(&run, &id);
        if checked.is_ok() {
            write_file(&planted, b"written through").unwrap();
        }
        assert_eq!(std::fs::read(&key).unwrap(), KEY, "the target is untouched");
        let err = checked
            .expect_err("a run directory holding a symlink")
            .to_string();
        assert!(err.contains(&run.display().to_string()), "{err}");
    }

    #[test]
    fn a_run_dir_that_is_a_symlink_into_the_identity_dir_is_refused() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let id = tmp.path().join("id");
        let held = id.join("held");
        std::fs::create_dir_all(&held).unwrap();

        // Empty, so only the resolved comparison can refuse these.
        let to_held = tmp.path().join("to-held");
        symlink(&held, &to_held).unwrap();
        let to_id = tmp.path().join("to-id");
        symlink(&id, &to_id).unwrap();
        for run in [
            to_held.clone(),
            to_held.join("not/yet"),
            to_id.join("held"),
            to_id.join("not-yet"),
        ] {
            let err = check_run_dir(&run, &id).expect_err(&run.display().to_string());
            assert!(err.to_string().contains("inside"), "{err}");
        }

        // The identity directory itself reached through a link.
        let err = check_run_dir(&held, &to_id).expect_err("guard behind a link");
        assert!(err.to_string().contains("inside"), "{err}");

        // A name that does not exist yet can still walk back in.
        let back_in = tmp.path().join("not-yet/../id/run");
        assert!(check_run_dir(&back_in, &id).is_err());

        // A dangling link has no answer to where it leads: mkdir would refuse it, so do we.
        let dangling = tmp.path().join("dangling");
        symlink(id.join("absent"), &dangling).unwrap();
        assert!(check_run_dir(&dangling, &id).is_err());
        assert!(check_run_dir(&dangling.join("x"), &id).is_err());
    }

    #[test]
    fn a_run_dir_must_be_absent_or_empty_and_a_link_that_stays_outside_may_stay() {
        let tmp = tempfile::tempdir().unwrap();
        let id = tmp.path().join("id");
        std::fs::create_dir(&id).unwrap();

        let run = tmp.path().join("run");
        assert!(check_run_dir(&run, &id).is_ok(), "absent");
        std::fs::create_dir(&run).unwrap();
        assert!(check_run_dir(&run, &id).is_ok(), "empty");

        let elsewhere = tmp.path().join("elsewhere");
        std::os::unix::fs::symlink(&run, &elsewhere).unwrap();
        assert!(
            check_run_dir(&elsewhere, &id).is_ok(),
            "link to an empty dir"
        );

        std::fs::write(run.join("anything"), "x").unwrap();
        let err = check_run_dir(&run, &id).expect_err("non-empty").to_string();
        assert!(err.contains(&run.display().to_string()), "{err}");
        assert!(
            check_run_dir(&elsewhere, &id).is_err(),
            "link to a non-empty dir"
        );

        let file = tmp.path().join("file");
        std::fs::write(&file, "x").unwrap();
        assert!(check_run_dir(&file, &id).is_err(), "not a directory");
    }
}
