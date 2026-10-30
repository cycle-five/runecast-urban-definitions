//! Routes. Public ones are forwarded by nginx under `/urban-definitions/`;
//! `/internal/*` and `/health` are reachable on the compose network only.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use metrics_exporter_prometheus::PrometheusHandle;
use serde::Deserialize;
use subtle::ConstantTimeEq;
use urban_definitions_wire::{
    ApiError, ChunkResponse, ErrorCode, LookupResponse, StartUpload, UploadOutcome,
};

use crate::metrics as m;
use crate::relay::{unlock_with_retry, UnlockRelay};
use crate::store::Definitions;
use crate::uploads::{ChunkStep, Clock, Uploads, CHUNK_SIZE};

/// A finished upload's final answer is kept this long, so a lost response
/// can be re-asked.
pub const FINISHED_KEEP_SECS: i64 = 600;
/// nginx `client_max_body_size 9m`: a chunk plus 1 MiB of slack, so a body one
/// byte over `CHUNK_SIZE` reaches the handler and gets `chunk_too_large`.
const CHUNK_BODY_LIMIT: usize = CHUNK_SIZE as usize + (1 << 20);

#[derive(Clone, Copy)]
enum Finished {
    Done(UploadOutcome),
    WrongFile,
}

#[derive(Clone)]
pub struct AppState {
    uploads: Arc<Uploads>,
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
        uploads: Arc<Uploads>,
        store: Arc<Definitions>,
        relay: Arc<dyn UnlockRelay>,
        internal_token: String,
        metrics_token: String,
        metrics: PrometheusHandle,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            uploads,
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

    /// Expires idle uploads and old finished records. Run every 30 s.
    pub fn sweep(&self) {
        self.uploads.sweep();
        let cutoff = self.clock.now_unix() - FINISHED_KEEP_SECS;
        self.finished
            .lock()
            .expect("finished lock poisoned")
            .retain(|_, (at, _)| *at > cutoff);
    }

    fn record(&self, id: &str, what: Finished) {
        let now = self.clock.now_unix();
        self.finished
            .lock()
            .expect("finished lock poisoned")
            .insert(id.to_string(), (now, what));
    }

    fn recorded(&self, id: &str) -> Option<Finished> {
        self.finished
            .lock()
            .expect("finished lock poisoned")
            .get(id)
            .map(|(_, f)| *f)
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/urban-definitions/uploads", post(start_upload))
        .route(
            "/urban-definitions/uploads/{id}",
            get(progress).delete(cancel),
        )
        .route(
            "/urban-definitions/uploads/{id}/chunks/{offset}",
            put(chunk).layer(DefaultBodyLimit::max(CHUNK_BODY_LIMIT)),
        )
        .route("/urban-definitions/metrics", get(metrics_page))
        .route("/internal/definitions/{word}", get(lookup))
        .route("/health", get(|| async { StatusCode::OK }))
        .with_state(state)
}

fn status_of(code: ErrorCode) -> StatusCode {
    match code {
        ErrorCode::WrongSize
        | ErrorCode::WrongOffset
        | ErrorCode::ChunkTooLarge
        | ErrorCode::WrongFile => StatusCode::BAD_REQUEST,
        ErrorCode::BadTicket | ErrorCode::TicketExpired | ErrorCode::TicketUsed => {
            StatusCode::UNAUTHORIZED
        }
        ErrorCode::NotFound => StatusCode::NOT_FOUND,
        ErrorCode::Busy => StatusCode::CONFLICT,
        ErrorCode::TooManyUploads => StatusCode::TOO_MANY_REQUESTS,
        ErrorCode::Unavailable => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn error(code: ErrorCode) -> Response {
    (status_of(code), Json(ApiError { error: code })).into_response()
}

fn token_matches(provided: Option<&str>, expected: &str) -> bool {
    match provided {
        Some(t) => t.as_bytes().ct_eq(expected.as_bytes()).into(),
        None => false,
    }
}

async fn start_upload(State(s): State<AppState>, Json(req): Json<StartUpload>) -> Response {
    match s.uploads.start(req) {
        Ok(started) => (StatusCode::CREATED, Json(started)).into_response(),
        Err(code) => {
            if let Some(label) = m::refusal_label(code) {
                m::upload(label);
            }
            tracing::info!(?code, "upload refused");
            error(code)
        }
    }
}

fn finished_response(f: Finished) -> Response {
    match f {
        Finished::Done(outcome) => Json(ChunkResponse::Finished { outcome }).into_response(),
        Finished::WrongFile => error(ErrorCode::WrongFile),
    }
}

async fn progress(State(s): State<AppState>, Path(id): Path<String>) -> Response {
    if let Some(f) = s.recorded(&id) {
        return finished_response(f);
    }
    match s.uploads.progress(&id) {
        Ok(p) => Json(p).into_response(),
        Err(code) => error(code),
    }
}

async fn cancel(State(s): State<AppState>, Path(id): Path<String>) -> StatusCode {
    if s.uploads.progress(&id).is_ok() {
        m::upload("abandoned");
        tracing::info!(upload_id = %id, "upload cancelled by the player");
    }
    s.uploads.cancel(&id);
    StatusCode::NO_CONTENT
}

async fn chunk(
    State(s): State<AppState>,
    Path((id, offset)): Path<(String, u64)>,
    body: axum::body::Bytes,
) -> Response {
    // A re-sent final chunk (lost response) gets the recorded answer; the
    // unlock relay never runs twice.
    if let Some(f) = s.recorded(&id) {
        return finished_response(f);
    }
    let uploads = s.uploads.clone();
    let upload_id = id.clone();
    let step =
        match tokio::task::spawn_blocking(move || uploads.chunk(&upload_id, offset, &body)).await {
            Ok(step) => step,
            Err(e) => {
                tracing::error!(upload_id = %id, error = %e, "chunk handling panicked");
                return error(ErrorCode::Unavailable);
            }
        };
    match step {
        Ok(ChunkStep::Progress(p)) => Json(ChunkResponse::Progress(p)).into_response(),
        Ok(ChunkStep::Matched { user_id, loaded }) => {
            let unlocked = unlock_with_retry(&*s.relay, user_id, s.retry_delay).await;
            let (outcome, label) = match (unlocked, loaded) {
                (false, _) => (UploadOutcome::UnlockFailed, "unlock_failed"),
                (true, true) => (UploadOutcome::Loaded, "loaded"),
                (true, false) => (UploadOutcome::Unlocked, "unlocked"),
            };
            if loaded {
                // The load itself counts even when the unlock then failed.
                m::upload("loaded");
            }
            if label != "loaded" {
                m::upload(label);
            }
            tracing::info!(user_id, upload_id = %id, loaded, label, "upload finished");
            let done = Finished::Done(outcome);
            s.record(&id, done);
            finished_response(done)
        }
        Err(code) => {
            if code == ErrorCode::WrongFile {
                m::upload("wrong_file");
                tracing::info!(upload_id = %id, "upload finished: wrong file");
                s.record(&id, Finished::WrongFile);
            } else if code == ErrorCode::NotFound {
                // Lost the race with a concurrent final chunk.
                if let Some(f) = s.recorded(&id) {
                    return finished_response(f);
                }
            }
            error(code)
        }
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
    let Some(index) = s.store.get() else {
        m::lookup("empty");
        return Json(LookupResponse::Empty).into_response();
    };
    let found = index.lookup(&word.to_uppercase(), q.glued);
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
    m::set_loaded(s.store.get().map(|i| i.entries()));
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        s.metrics.render(),
    )
        .into_response()
}
