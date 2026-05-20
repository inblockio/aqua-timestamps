//! HTTP route handlers that aren't strictly part of auth.

use std::{convert::Infallible, sync::Arc};

use aqua_timestamp_core::{
    merkle::{hex_lower, parse_leaf_hex, LeafParseError},
    storage::TipPairIndex,
    witness::AnchorMethod,
};
use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        Html, IntoResponse, Response,
    },
    Json,
};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tracing::{info, warn};

use crate::{
    auth::{AuthApiError, BearerDid},
    landing,
    state::AppState,
};

/// Anchor methods advertised at M2. The providers themselves are stubbed
/// until M4 (EVM) and M5 (qTSA); the labels are stable across milestones
/// so clients can hard-code the strings now.
const ANCHOR_METHODS: &[&str] = &["evm", "qtsa"];

/// Hard cap on `GET /v1/epochs?limit=N`.
const EPOCHS_MAX_LIMIT: usize = 200;
const EPOCHS_DEFAULT_LIMIT: usize = 50;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub uptime_secs: u64,
    pub version: &'static str,
}

pub async fn health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        uptime_secs: state.started_at.elapsed().as_secs(),
        version: env!("CARGO_PKG_VERSION"),
    })
}

pub async fn landing_page() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        Html(landing::HTML),
    )
        .into_response()
}

/// `GET /docs` — browser-friendly agent integration guide.
pub async fn docs_page(State(state): State<Arc<AppState>>) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        Html(state.docs_html.clone()),
    )
        .into_response()
}

/// `GET /.well-known/aqua-skill.md` — main agent skill, in the same
/// shape Claude (and any other agent honoring the convention) consumes
/// for `~/.claude/skills/<name>/SKILL.md`. Public, no auth.
pub async fn well_known_skill_md(State(state): State<Arc<AppState>>) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/markdown; charset=utf-8")],
        state.well_known_skill_md.clone(),
    )
        .into_response()
}

/// `GET /.well-known/aqua-skill-auth.md` — SIWE / CAIP-122
/// authentication deep-dive (sub-article). Linked from the main skill.
/// Public, no auth.
pub async fn well_known_skill_auth_md(State(state): State<Arc<AppState>>) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/markdown; charset=utf-8")],
        state.well_known_skill_auth_md.clone(),
    )
        .into_response()
}

pub async fn aqua_identity(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(state.identity_response_json.clone())
}

// ── /v1/leaves ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct LeavesRequest {
    pub leaves: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct LeavesResponse {
    pub accepted: u64,
    pub duplicates: u64,
    pub epoch_id: u64,
    pub epoch_closes_at: u64,
    pub submitter_did: String,
}

/// `POST /v1/leaves`
///
/// Validates the batch, hex-decodes each leaf, then appends the whole
/// batch to the open accumulator. The accumulator lock is the linearization
/// point for the "leaf lands in `N` or `N+1`, never neither" invariant.
pub async fn submit_leaves(
    State(state): State<Arc<AppState>>,
    bearer: BearerDid,
    Json(req): Json<LeavesRequest>,
) -> Result<(StatusCode, Json<LeavesResponse>), AuthApiError> {
    if !state.is_allowed(&bearer.0) {
        warn!(did = %bearer.0, "v1.leaves denied by allowlist");
        return Err(AuthApiError::forbidden("did not on allowlist"));
    }

    let max = state.config.epoch.max_leaves_per_request;
    let n = req.leaves.len();
    if n == 0 {
        return Err(AuthApiError::bad_request(
            "leaves must contain at least one hash",
        ));
    }
    if n > max {
        return Err(AuthApiError::bad_request(format!(
            "leaves: {n} exceeds max_leaves_per_request {max}"
        )));
    }

    let mut decoded = Vec::with_capacity(n);
    for (i, raw) in req.leaves.iter().enumerate() {
        match parse_leaf_hex(raw) {
            Ok(bytes) => decoded.push(bytes),
            Err(LeafParseError::BadLength(len)) => {
                return Err(AuthApiError::bad_request(format!(
                    "leaves[{i}]: expected 64 hex chars (optionally 0x-prefixed), got {len}"
                )))
            }
            Err(LeafParseError::BadHex(e)) => {
                return Err(AuthApiError::bad_request(format!(
                    "leaves[{i}]: non-hex character ({e})"
                )))
            }
        }
    }

    let outcome = state.accumulator.append_batch(&decoded, &bearer.0);
    info!(
        did = %bearer.0,
        epoch_id = outcome.epoch_id,
        accepted = outcome.accepted,
        duplicates = outcome.duplicates,
        "v1.leaves accepted"
    );

    Ok((
        StatusCode::ACCEPTED,
        Json(LeavesResponse {
            accepted: outcome.accepted,
            duplicates: outcome.duplicates,
            epoch_id: outcome.epoch_id,
            epoch_closes_at: outcome.epoch_closes_at,
            submitter_did: bearer.0,
        }),
    ))
}

// ── /v1/schedule ──────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ScheduleResponse {
    pub current_epoch_id: u64,
    pub current_epoch_opened_at: u64,
    pub current_epoch_closes_at: u64,
    pub epoch_duration_secs: u64,
    pub last_sealed_epoch_id: Option<u64>,
    pub last_sealed_at: Option<u64>,
    pub anchor_methods: Vec<&'static str>,
}

pub async fn schedule(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ScheduleResponse>, ScheduleError> {
    let view = state.accumulator.current_view();

    let last_sealed_id = state
        .store
        .last_sealed_epoch_id()
        .map_err(|e| ScheduleError(format!("store: {e}")))?;

    let last_sealed_at = match last_sealed_id {
        Some(id) => state
            .store
            .get_epoch(id)
            .map_err(|e| ScheduleError(format!("store: {e}")))?
            .map(|r| r.closed_at),
        None => None,
    };

    Ok(Json(ScheduleResponse {
        current_epoch_id: view.epoch_id,
        current_epoch_opened_at: view.opened_at,
        current_epoch_closes_at: view.closes_at,
        epoch_duration_secs: state.config.epoch.duration_secs,
        last_sealed_epoch_id: last_sealed_id,
        last_sealed_at,
        anchor_methods: ANCHOR_METHODS.to_vec(),
    }))
}

#[derive(Debug)]
pub struct ScheduleError(String);

impl IntoResponse for ScheduleError {
    fn into_response(self) -> Response {
        warn!(error = %self.0, "schedule lookup failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "schedule lookup failed" })),
        )
            .into_response()
    }
}

// ── /v1/epochs ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct EpochsQuery {
    /// Inclusive upper bound on the returned epoch ids. Omitted = latest.
    pub from: Option<u64>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct EpochsResponse {
    pub epochs: Vec<EpochListItem>,
    pub next: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct EpochListItem {
    pub id: u64,
    pub opened_at: u64,
    pub closed_at: u64,
    pub merkle_root: String,
    pub leaf_count: u64,
    pub hash_type: String,
}

/// `GET /v1/epochs?from=&limit=`, bearer-gated.
///
/// The endpoint is authenticated so that M3 can layer DID-scoped views on
/// the same handler without changing the contract; allowlist enforcement
/// is not applied here because the list itself is non-sensitive (only the
/// roots and leaf counts are exposed, no client-submitted hashes).
pub async fn list_epochs(
    State(state): State<Arc<AppState>>,
    bearer: BearerDid,
    Query(q): Query<EpochsQuery>,
) -> Result<Json<EpochsResponse>, AuthApiError> {
    let limit = q
        .limit
        .unwrap_or(EPOCHS_DEFAULT_LIMIT)
        .clamp(1, EPOCHS_MAX_LIMIT);

    let (records, next) = state
        .store
        .list_epochs_desc(q.from, limit)
        .map_err(|e| AuthApiError::bad_request(format!("store: {e}")))?;

    info!(
        did = %bearer.0,
        from = ?q.from,
        limit,
        returned = records.len(),
        "v1.epochs listed"
    );

    Ok(Json(EpochsResponse {
        epochs: records
            .into_iter()
            .map(|r| EpochListItem {
                id: r.id,
                opened_at: r.opened_at,
                closed_at: r.closed_at,
                merkle_root: hex_lower(&r.merkle_root),
                leaf_count: r.leaf_count,
                hash_type: r.hash_type,
            })
            .collect(),
        next,
    }))
}

pub async fn favicon_ico() -> Response {
    static BYTES: &[u8] = include_bytes!("../assets/favicon.ico");
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "image/x-icon"),
            (header::CACHE_CONTROL, "public, max-age=604800"),
        ],
        BYTES,
    )
        .into_response()
}

pub async fn apple_touch_icon() -> Response {
    static BYTES: &[u8] = include_bytes!("../assets/favicon-180.png");
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "image/png"),
            (header::CACHE_CONTROL, "public, max-age=604800"),
        ],
        BYTES,
    )
        .into_response()
}

/// 404 fallback for routes we don't define yet (uniform JSON shape).
pub async fn not_found() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" })))
}

// ── /trees/{tip}, /trees/by-leaf/{leaf}, /trees, /trees?epoch=&method= ───
//
// The aqua-node REST contract defines `GET /trees` (list tips),
// `GET /trees/{tip_hex}` (the witness pair rooted at `tip_hex`), and
// `GET /trees/by-genesis/{genesis_hex}`. aqua-timestamp implements
// `/trees` and `/trees/{tip}` byte-for-byte against the aqua-node shape
// (`{revisions, file_index}` with the SDK's `BTreeMap<RevisionLink, _>`
// ordering), then ADDS two aqua-timestamp-specific variants that return
// the same shape:
//
// * `GET /trees/by-leaf/{leaf}?method=evm|qtsa` : resolve a witness pair
//   from a client-submitted leaf + anchor method.
// * `GET /trees?epoch=N&method=evm|qtsa` : union of witnesses for every
//   leaf the calling DID submitted in epoch `N`.
//
// All three return the same `Tree` shape so existing aqua-node clients
// can consume them unmodified. The list-tips form (no query string) is
// preserved as the legacy `GET /trees` path.

/// Query parameters for the union variant of `/trees`.
///
/// `epoch` AND `method` MUST be present together; either alone is a 400.
#[derive(Debug, Deserialize)]
pub struct TreesQuery {
    pub epoch: Option<u64>,
    pub method: Option<String>,
}

/// `GET /trees` (no query → legacy aqua-node tip list)
/// OR `GET /trees?epoch=N&method=evm|qtsa` (M3 union variant).
pub async fn list_or_query_trees(
    State(state): State<Arc<AppState>>,
    bearer: BearerDid,
    Query(q): Query<TreesQuery>,
) -> Result<Response, AuthApiError> {
    match (q.epoch, q.method.as_deref()) {
        (None, None) => list_tips_for_did(&state, &bearer.0),
        (Some(epoch), Some(method_str)) => {
            let method = AnchorMethod::parse(method_str).ok_or_else(|| {
                AuthApiError::bad_request(format!(
                    "method must be 'evm' or 'qtsa', got '{method_str}'"
                ))
            })?;
            union_for_epoch(&state, &bearer.0, epoch, method)
        }
        _ => Err(AuthApiError::bad_request(
            "epoch and method must be supplied together (or omit both for the tip list)",
        )),
    }
}

/// `GET /trees` shape: a JSON array of hex tip hashes belonging to the
/// caller's DID, sorted descending by epoch.
fn list_tips_for_did(state: &Arc<AppState>, did: &str) -> Result<Response, AuthApiError> {
    let tips = state
        .store
        .list_witness_tips_for_did(did)
        .map_err(|e| AuthApiError::bad_request(format!("store: {e}")))?;
    let body: Vec<String> = tips
        .into_iter()
        .map(|(_, tip)| format!("0x{}", hex::encode(tip)))
        .collect();
    info!(did, count = body.len(), "trees.list");
    Ok((StatusCode::OK, Json(body)).into_response())
}

/// `GET /trees?epoch=N&method=...` : union of witness pairs for every
/// leaf the caller submitted in epoch `N` under `method`. Empty
/// `revisions`/`file_index` if the caller submitted no leaves in that
/// epoch. 404 only if the epoch has not been sealed at all.
fn union_for_epoch(
    state: &Arc<AppState>,
    did: &str,
    epoch_id: u64,
    method: AnchorMethod,
) -> Result<Response, AuthApiError> {
    let epoch = state
        .store
        .get_epoch(epoch_id)
        .map_err(|e| AuthApiError::bad_request(format!("store: {e}")))?;
    if epoch.is_none() {
        return Ok(not_found_response("epoch not sealed yet"));
    }
    let entries = state
        .store
        .list_witnesses_for_did_in_epoch(did, epoch_id, method)
        .map_err(|e| AuthApiError::bad_request(format!("store: {e}")))?;

    let mut revisions: Map<String, Value> = Map::new();
    let mut file_index: Map<String, Value> = Map::new();

    for idx in entries {
        load_pair_into_maps(&state.store, &idx, &mut revisions, &mut file_index)
            .map_err(AuthApiError::bad_request)?;
    }

    info!(
        did,
        epoch = epoch_id,
        method = %method.as_str(),
        leaves = revisions.len() / 2,
        "trees.union"
    );

    Ok((
        StatusCode::OK,
        Json(json!({
            "revisions": Value::Object(revisions),
            "file_index": Value::Object(file_index),
        })),
    )
        .into_response())
}

/// `GET /trees/{tip_hex}` : aqua-node-compatible single-tree fetch.
pub async fn get_tree_by_tip(
    State(state): State<Arc<AppState>>,
    bearer: BearerDid,
    Path(tip_hex): Path<String>,
) -> Result<Response, AuthApiError> {
    let tip = parse_hash32(&tip_hex).map_err(AuthApiError::bad_request)?;
    let idx = match state
        .store
        .get_tip_pair(&tip)
        .map_err(|e| AuthApiError::bad_request(format!("store: {e}")))?
    {
        Some(p) => p,
        None => return Ok(not_found_response("unknown tip")),
    };
    if idx.submitter_did != bearer.0 {
        warn!(
            caller = %bearer.0,
            owner = %idx.submitter_did,
            "trees.tip access denied"
        );
        return Err(AuthApiError::forbidden("witness owned by a different DID"));
    }
    let body = build_pair_body(&state.store, &idx)
        .map_err(|e| AuthApiError::bad_request(format!("store: {e}")))?;
    info!(did = %bearer.0, tip = %format!("0x{}", hex::encode(tip)), "trees.tip");
    Ok((StatusCode::OK, Json(body)).into_response())
}

/// `GET /trees/by-leaf/{leaf_hex}?method=evm|qtsa` : aqua-timestamp
/// extension.
pub async fn get_tree_by_leaf(
    State(state): State<Arc<AppState>>,
    bearer: BearerDid,
    Path(leaf_hex): Path<String>,
    Query(q): Query<ByLeafQuery>,
) -> Result<Response, AuthApiError> {
    let method_str = q
        .method
        .ok_or_else(|| AuthApiError::bad_request("missing required query parameter 'method'"))?;
    let method = AnchorMethod::parse(&method_str).ok_or_else(|| {
        AuthApiError::bad_request(format!(
            "method must be 'evm' or 'qtsa', got '{method_str}'"
        ))
    })?;
    let leaf = parse_hash32(&leaf_hex).map_err(AuthApiError::bad_request)?;

    // Resolve ownership first. A leaf that doesn't exist at all is a 404;
    // a leaf owned by someone else is a 403 (the §M3 isolation invariant).
    let owner = state
        .store
        .get_leaf_owner(&leaf)
        .map_err(|e| AuthApiError::bad_request(format!("store: {e}")))?;
    match owner {
        None => return Ok(not_found_response("unknown leaf")),
        Some(d) if d != bearer.0 => {
            warn!(caller = %bearer.0, owner = %d, "trees.by-leaf access denied");
            return Err(AuthApiError::forbidden("leaf submitted by a different DID"));
        }
        Some(_) => {}
    }

    let tip = state
        .store
        .get_tip_for_leaf(&leaf, method)
        .map_err(|e| AuthApiError::bad_request(format!("store: {e}")))?;
    let tip = match tip {
        Some(t) => t,
        None => return Ok(not_found_response("no witness for that leaf/method yet")),
    };
    let idx = state
        .store
        .get_tip_pair(&tip)
        .map_err(|e| AuthApiError::bad_request(format!("store: {e}")))?
        .ok_or_else(|| {
            AuthApiError::bad_request("internal: tip_to_pair index missing for known tip")
        })?;
    let body = build_pair_body(&state.store, &idx)
        .map_err(|e| AuthApiError::bad_request(format!("store: {e}")))?;
    info!(
        did = %bearer.0,
        leaf = %format!("0x{}", hex::encode(leaf)),
        method = %method.as_str(),
        "trees.by-leaf"
    );
    Ok((StatusCode::OK, Json(body)).into_response())
}

#[derive(Debug, Deserialize)]
pub struct ByLeafQuery {
    pub method: Option<String>,
}

// ── /trees response helpers ───────────────────────────────────────────────

fn build_pair_body(
    store: &aqua_timestamp_core::storage::Store,
    idx: &TipPairIndex,
) -> Result<Value, String> {
    let mut revisions: Map<String, Value> = Map::new();
    let mut file_index: Map<String, Value> = Map::new();
    load_pair_into_maps(store, idx, &mut revisions, &mut file_index)?;
    Ok(json!({
        "revisions": Value::Object(revisions),
        "file_index": Value::Object(file_index),
    }))
}

/// Add the two revisions (object + signature) of the witness pair
/// described by `idx` into the supplied response maps. Mirrors aqua-node's
/// JSON shape: keys are `"0x<hex>"` revision hashes, values are the raw
/// `AnyRevision` JSON the SDK emitted at sign time.
fn load_pair_into_maps(
    store: &aqua_timestamp_core::storage::Store,
    idx: &TipPairIndex,
    revisions: &mut Map<String, Value>,
    file_index: &mut Map<String, Value>,
) -> Result<(), String> {
    let obj_bytes = store
        .get_revision_json(&idx.object_hash)
        .map_err(|e| format!("store: {e}"))?
        .ok_or_else(|| "witness object revision missing in store".to_string())?;
    let sig_bytes = store
        .get_revision_json(&idx.signature_hash)
        .map_err(|e| format!("store: {e}"))?
        .ok_or_else(|| "witness signature revision missing in store".to_string())?;

    let obj_json: Value = serde_json::from_slice(&obj_bytes).map_err(|e| format!("json: {e}"))?;
    let sig_json: Value = serde_json::from_slice(&sig_bytes).map_err(|e| format!("json: {e}"))?;

    let obj_hex = format!("0x{}", hex::encode(idx.object_hash));
    let sig_hex = format!("0x{}", hex::encode(idx.signature_hash));

    revisions.insert(obj_hex.clone(), obj_json);
    revisions.insert(sig_hex.clone(), sig_json);
    file_index.insert(obj_hex, Value::String(idx.object_file_name.clone()));
    file_index.insert(sig_hex, Value::String(idx.signature_file_name.clone()));
    Ok(())
}

fn parse_hash32(input: &str) -> Result<[u8; 32], String> {
    let trimmed = input.strip_prefix("0x").unwrap_or(input);
    if trimmed.len() != 64 {
        return Err(format!(
            "expected 64 hex chars (optionally 0x-prefixed), got {}",
            trimmed.len()
        ));
    }
    let bytes = hex::decode(trimmed).map_err(|e| format!("non-hex: {e}"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn not_found_response(msg: &str) -> Response {
    (StatusCode::NOT_FOUND, Json(json!({ "error": msg }))).into_response()
}

// ── GET /events (SSE) ─────────────────────────────────────────────────────

/// `GET /events` — Server-Sent Events stream.
///
/// Every active subscriber receives epoch-seal and anchor events as they
/// occur. No authentication is required (events carry no client-specific
/// data). Clients that fall too far behind are dropped per the Tokio
/// broadcast lagging contract; reconnect to resume.
pub async fn sse_events(
    State(state): State<Arc<AppState>>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let rx = state.event_bus.subscribe();
    let stream = tokio_stream::wrappers::BroadcastStream::new(rx).filter_map(|result| {
        futures_util::future::ready(match result {
            Ok(event) => {
                let name = event.event_name().to_owned();
                match serde_json::to_string(&event) {
                    Ok(json) => Some(Ok(Event::default().event(name).data(json))),
                    Err(_) => None,
                }
            }
            Err(_) => None,
        })
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

// ── GET /.well-known/aqua-orl ─────────────────────────────────────────────

/// `GET /.well-known/aqua-orl` — Operational Readiness Level declaration.
///
/// Returns the current ORL level and associated metadata so tooling and
/// agents can discover the service maturity without reading the source.
pub async fn aqua_orl() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "orl": 2,
        "label": "Development",
        "color": "#F97316",
        "since": "2026-05-17",
        "assessed_by": "tim.bansemer@inblock.io",
        "next_level_blockers": [
            "Security review not started",
            "Backup restore not verified",
            "Monitoring and alerting not active",
            "Dependency audit not completed"
        ],
        "checklist_url": "https://github.com/inblockio/aqua-timestamps/blob/main/ORL.md"
    }))
}
