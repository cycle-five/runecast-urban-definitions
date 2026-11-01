//! Routes. Public ones are forwarded by nginx under `/urban-definitions/`;
//! `/internal/*` and `/health` are reachable on the compose network only.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use metrics_exporter_prometheus::PrometheusHandle;
use serde::Deserialize;
use subtle::ConstantTimeEq;
use urban_definitions_wire::{ApiError, ErrorCode, LookupResponse, ProofOutcome};

use crate::clock::Clock;
use crate::metrics as m;
use crate::relay::UnlockRelay;
use crate::store::Definitions;

/// A finished proof's final answer is kept this long, so a lost response
/// can be re-asked.
pub const FINISHED_KEEP_SECS: i64 = 600;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Finished {
    /// The proof matched; the unlock relay is still running.
    Pending,
    Done(ProofOutcome),
    WrongFile,
}

/// How long a re-send or poll waits for a pending match (the relay's worst
/// case is about 17 s).
const PENDING_WAIT: Duration = Duration::from_secs(30);
const PENDING_POLL: Duration = Duration::from_millis(25);

#[derive(Clone)]
pub struct AppState {
    store: Arc<Definitions>,
    relay: Arc<dyn UnlockRelay>,
    internal_token: Arc<str>,
    metrics_token: Arc<str>,
    metrics: PrometheusHandle,
    clock: Arc<dyn Clock>,
    finished: Arc<Mutex<HashMap<String, (i64, Finished)>>>,
    /// Pause between unlock attempts.
    pub retry_delay: Duration,
}

impl AppState {
    pub fn new(
        store: Arc<Definitions>,
        relay: Arc<dyn UnlockRelay>,
        internal_token: String,
        metrics_token: String,
        metrics: PrometheusHandle,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            store,
            relay,
            internal_token: internal_token.into(),
            metrics_token: metrics_token.into(),
            metrics,
            clock,
            finished: Arc::default(),
            retry_delay: Duration::from_secs(1),
        }
    }

    /// Expires old finished records. Run every 30 s.
    pub fn sweep(&self) {
        m::record_resident();
        let cutoff = self.clock.now_unix() - FINISHED_KEEP_SECS;
        self.finished
            .lock()
            .expect("finished lock poisoned")
            .retain(|_, (at, _)| *at > cutoff);
    }

    /// The unlock relay, for the proof route.
    pub fn relay(&self) -> &Arc<dyn UnlockRelay> {
        &self.relay
    }

    /// Keeps the final answer for `id` for `FINISHED_KEEP_SECS`.
    pub fn record(&self, id: &str, what: Finished) {
        let now = self.clock.now_unix();
        self.finished
            .lock()
            .expect("finished lock poisoned")
            .insert(id.to_string(), (now, what));
    }

    pub fn recorded(&self, id: &str) -> Option<Finished> {
        self.finished
            .lock()
            .expect("finished lock poisoned")
            .get(id)
            .map(|(_, f)| *f)
    }

    /// The final answer for `id` if there is one; a pending match is waited
    /// out (bounded), so the caller never sees a half-finished proof.
    pub async fn settled(&self, id: &str) -> Option<Finished> {
        let deadline = tokio::time::Instant::now() + PENDING_WAIT;
        loop {
            match self.recorded(id) {
                Some(Finished::Pending) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(PENDING_POLL).await;
                }
                Some(Finished::Pending) => return None,
                other => return other,
            }
        }
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/urban-definitions/metrics", get(metrics_page))
        .route("/internal/definitions/{word}", get(lookup))
        .route("/health", get(|| async { StatusCode::OK }))
        .with_state(state)
}

pub fn status_of(code: ErrorCode) -> StatusCode {
    match code {
        ErrorCode::WrongFile => StatusCode::BAD_REQUEST,
        ErrorCode::BadTicket | ErrorCode::TicketExpired | ErrorCode::TicketUsed => {
            StatusCode::UNAUTHORIZED
        }
        ErrorCode::NotFound => StatusCode::NOT_FOUND,
        ErrorCode::Busy => StatusCode::CONFLICT,
        ErrorCode::Unavailable => StatusCode::INTERNAL_SERVER_ERROR,
        ErrorCode::Loading => StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::ChallengeExpired => StatusCode::GONE,
    }
}

pub fn error(code: ErrorCode) -> Response {
    (status_of(code), Json(ApiError { error: code })).into_response()
}

fn token_matches(provided: Option<&str>, expected: &str) -> bool {
    match provided {
        Some(t) => t.as_bytes().ct_eq(expected.as_bytes()).into(),
        None => false,
    }
}

#[derive(Deserialize)]
struct LookupQuery {
    #[serde(default)]
    glued: bool,
}

async fn lookup(
    State(s): State<AppState>,
    headers: HeaderMap,
    Path(word): Path<String>,
    Query(q): Query<LookupQuery>,
) -> Response {
    let provided = headers
        .get("x-internal-token")
        .and_then(|v| v.to_str().ok());
    if !token_matches(provided, &s.internal_token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Some(dump) = s.store.get() else {
        m::lookup("empty");
        return Json(LookupResponse::Empty).into_response();
    };
    let found = dump.index.lookup(&word.to_uppercase(), q.glued);
    m::lookup(if found.is_empty() { "miss" } else { "hit" });
    let definitions = found.iter().map(|d| d.to_string()).collect();
    Json(LookupResponse::Loaded { definitions }).into_response()
}

async fn metrics_page(State(s): State<AppState>, headers: HeaderMap) -> Response {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    if !token_matches(bearer, &s.metrics_token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    m::set_loaded(s.store.get().map(|d| d.index.entries()));
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        s.metrics.render(),
    )
        .into_response()
}
