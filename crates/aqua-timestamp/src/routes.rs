//! HTTP route handlers that aren't strictly part of auth.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    Json,
};
use serde::Serialize;
use serde_json::json;
use tracing::{info, warn};

use crate::{
    auth::{AuthApiError, BearerDid},
    landing,
    state::AppState,
};

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

/// Placeholder body for the M1 leaves endpoint. Real accumulation lands in M2.
#[derive(Serialize)]
pub struct LeavesAck {
    pub accepted: bool,
    pub epoch_id: Option<u64>,
}

/// `POST /v1/leaves` — auth-gated, allowlist-gated, no real accumulation.
pub async fn submit_leaves(
    State(state): State<Arc<AppState>>,
    bearer: BearerDid,
    body: Option<Json<serde_json::Value>>,
) -> Result<(StatusCode, Json<LeavesAck>), AuthApiError> {
    if !state.is_allowed(&bearer.0) {
        warn!(did = %bearer.0, "v1.leaves denied by allowlist");
        return Err(AuthApiError::forbidden("did not on allowlist"));
    }
    info!(
        did = %bearer.0,
        has_body = body.is_some(),
        "v1.leaves accepted (m1 stub)"
    );
    Ok((
        StatusCode::ACCEPTED,
        Json(LeavesAck {
            accepted: true,
            epoch_id: None,
        }),
    ))
}

/// 404 fallback for routes we don't define yet (uniform JSON shape).
pub async fn not_found() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" })))
}
