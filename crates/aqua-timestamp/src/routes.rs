//! HTTP route handlers that aren't strictly part of auth.

use std::sync::Arc;

use aqua_timestamp_core::merkle::{hex_lower, parse_leaf_hex, LeafParseError};
use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
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

/// 404 fallback for routes we don't define yet (uniform JSON shape).
pub async fn not_found() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" })))
}
