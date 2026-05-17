//! SIWE / CAIP-122 authentication routes and a bearer extractor for
//! protected endpoints.
//!
//! Implementation note: every primitive lives in `aqua-rs-auth`. This
//! module is purely transport glue (Axum handlers, JSON shapes, tracing).

use std::sync::Arc;

use aqua_auth::{verify_caip122, ChallengeStore, SessionStore};
use axum::{
    extract::{FromRef, Query, State},
    http::{header, request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::state::AppState;

/// JSON wire shape for `GET /auth/challenge?did=...`.
#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    pub nonce: String,
    pub message: String,
    pub expires_at: u64,
}

#[derive(Debug, Deserialize)]
pub struct ChallengeQuery {
    pub did: String,
}

/// JSON wire shape for `POST /auth/session`.
#[derive(Debug, Deserialize)]
pub struct SessionRequestBody {
    pub did: String,
    pub nonce: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub token: String,
    pub did: String,
    pub valid_until: u64,
    pub created_at: u64,
}

/// Convenient transport error type.
#[derive(Debug)]
pub struct AuthApiError {
    status: StatusCode,
    msg: String,
}

impl AuthApiError {
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            msg: msg.into(),
        }
    }
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            msg: msg.into(),
        }
    }
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            msg: msg.into(),
        }
    }
}

impl IntoResponse for AuthApiError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({ "error": self.msg });
        (self.status, Json(body)).into_response()
    }
}

/// `GET /auth/challenge?did=...`
pub async fn challenge(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ChallengeQuery>,
) -> Result<Json<ChallengeResponse>, AuthApiError> {
    let challenge = state
        .challenges
        .create(&q.did)
        .map_err(|e| AuthApiError::bad_request(format!("challenge: {e}")))?;
    info!(
        did = %q.did,
        nonce = %challenge.nonce,
        expires_at = challenge.expires_at,
        "auth.challenge issued"
    );
    Ok(Json(ChallengeResponse {
        nonce: challenge.nonce,
        message: challenge.message,
        expires_at: challenge.expires_at,
    }))
}

/// `POST /auth/session`
pub async fn session(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SessionRequestBody>,
) -> Result<Json<SessionResponse>, AuthApiError> {
    let challenge = state
        .challenges
        .validate(&req.nonce)
        .map_err(|e| AuthApiError::unauthorized(format!("challenge: {e}")))?;

    if challenge.did != req.did {
        warn!(
            req_did = %req.did,
            challenge_did = %challenge.did,
            "auth.session DID mismatch"
        );
        return Err(AuthApiError::unauthorized("did does not match challenge"));
    }

    let sig_bytes = hex::decode(req.signature.trim_start_matches("0x"))
        .map_err(|e| AuthApiError::bad_request(format!("signature hex: {e}")))?;
    let ok = verify_caip122(&req.did, &challenge.message, &sig_bytes)
        .map_err(|e| AuthApiError::bad_request(format!("signature: {e}")))?;
    if !ok {
        warn!(did = %req.did, "auth.session signature rejected");
        return Err(AuthApiError::unauthorized("signature verification failed"));
    }

    let session = state.sessions.create(&req.did);
    info!(
        did = %req.did,
        token_prefix = %&session.token[..8],
        valid_until = session.valid_until,
        "auth.session created"
    );
    Ok(Json(SessionResponse {
        token: session.token,
        did: session.did,
        valid_until: session.valid_until,
        created_at: session.created_at,
    }))
}

/// Axum extractor that validates the `Authorization: Bearer <token>` header
/// against the session store and returns the authenticated DID.
#[derive(Debug, Clone)]
pub struct BearerDid(pub String);

impl<S> axum::extract::FromRequestParts<S> for BearerDid
where
    Arc<AppState>: axum::extract::FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app: Arc<AppState> = Arc::<AppState>::from_ref(state);
        let header_value = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AuthApiError::unauthorized("missing authorization header"))?;

        let token = header_value
            .strip_prefix("Bearer ")
            .ok_or_else(|| AuthApiError::unauthorized("authorization scheme must be Bearer"))?
            .trim();
        if token.is_empty() {
            return Err(AuthApiError::unauthorized("empty bearer token"));
        }

        match app.sessions.validate(token) {
            Ok(did) => {
                info!(did = %did, "auth.bearer accepted");
                Ok(BearerDid(did))
            }
            Err(e) => {
                warn!(error = %e, "auth.bearer rejected");
                Err(AuthApiError::unauthorized(format!("bearer: {e}")))
            }
        }
    }
}

/// Construct the challenge / session stores from config.
pub fn build_stores(
    challenge_ttl_secs: u64,
    session_ttl_secs: u64,
    domain: String,
    uri: String,
) -> (Arc<ChallengeStore>, Arc<SessionStore>) {
    let challenges = Arc::new(ChallengeStore::new(challenge_ttl_secs, domain, uri));
    let sessions = Arc::new(SessionStore::new(session_ttl_secs));
    (challenges, sessions)
}
