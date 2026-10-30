//! Routes. Public ones are forwarded by nginx under `/urban-definitions/`;
//! `/internal/*` and `/health` are reachable on the compose network only.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use metrics_exporter_prometheus::PrometheusHandle;
use serde::Deserialize;
use subtle::ConstantTimeEq;
use tower::limit::GlobalConcurrencyLimitLayer;
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
/// At most this many chunk requests are in flight at once (each can hold up
/// to a 9 MiB body).
pub const CHUNK_CONCURRENCY: usize = 8;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Finished {
    /// The hash matched; the unlock relay is still running.
    Pending,
    Done(UploadOutcome),
    WrongFile,
}

/// How long a re-send or poll waits for a pending match (the relay's worst
/// case is about 17 s).
const PENDING_WAIT: Duration = Duration::from_secs(30);
const PENDING_POLL: Duration = Duration::from_millis(25);

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
        for _ in 0..self.uploads.sweep() {
            m::upload("abandoned");
        }
        m::record_resident();
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

    /// The final answer for `id` if there is one; a pending match is waited
    /// out (bounded), so the caller never sees a half-finished upload.
    async fn settled(&self, id: &str) -> Option<Finished> {
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
        .route("/urban-definitions/uploads", post(start_upload))
        .route(
            "/urban-definitions/uploads/{id}",
            get(progress).delete(cancel),
        )
        .route(
            "/urban-definitions/uploads/{id}/chunks/{offset}",
            put(chunk).layer(GlobalConcurrencyLimitLayer::new(CHUNK_CONCURRENCY)),
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
        Finished::Pending => error(ErrorCode::Unavailable),
        Finished::Done(outcome) => Json(ChunkResponse::Finished { outcome }).into_response(),
        Finished::WrongFile => error(ErrorCode::WrongFile),
    }
}

async fn progress(State(s): State<AppState>, Path(id): Path<String>) -> Response {
    if let Some(f) = s.settled(&id).await {
        return finished_response(f);
    }
    // The per-upload lock is held while a chunk parses: wait for it on the
    // blocking pool, not on a runtime worker.
    let uploads = s.uploads.clone();
    let lookup_id = id.clone();
    match tokio::task::spawn_blocking(move || uploads.progress(&lookup_id)).await {
        Ok(Ok(p)) => Json(p).into_response(),
        Ok(Err(code)) => error(code),
        Err(e) => {
            tracing::error!(upload_id = %id, error = %e, "progress lookup panicked");
            error(ErrorCode::Unavailable)
        }
    }
}

async fn cancel(State(s): State<AppState>, Path(id): Path<String>) -> StatusCode {
    if s.uploads.cancel(&id) {
        m::upload("abandoned");
        tracing::info!(upload_id = %id, "upload cancelled by the player");
    }
    StatusCode::NO_CONTENT
}

async fn chunk(
    State(s): State<AppState>,
    Path((id, offset)): Path<(String, u64)>,
    body: Body,
) -> Response {
    // Cheap refusals first: an unknown upload or a wrong offset never makes
    // the server buffer a 9 MiB body. A finished upload's re-send still gets
    // its recorded answer.
    if let Some(f) = s.settled(&id).await {
        return finished_response(f);
    }
    if let Err(code) = s.uploads.precheck(&id, offset) {
        return error(code);
    }
    let body = match axum::body::to_bytes(body, CHUNK_BODY_LIMIT).await {
        Ok(b) => b,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    // Run to completion even if the client disconnects: a dropped request
    // must not skip the unlock, the metrics or the final-answer record.
    match tokio::spawn(process_chunk(s, id.clone(), offset, body)).await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!(upload_id = %id, error = %e, "chunk task failed");
            error(ErrorCode::Unavailable)
        }
    }
}

async fn process_chunk(s: AppState, id: String, offset: u64, body: axum::body::Bytes) -> Response {
    // A re-sent final chunk (lost response) gets the recorded answer, waiting
    // for a match still in flight; the unlock relay never runs twice.
    if let Some(f) = s.settled(&id).await {
        return finished_response(f);
    }
    let user_id = s.uploads.user_of(&id);
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
            // No await between the upload leaving the table and this record,
            // so a concurrent re-send finds Pending, not NotFound.
            s.record(&id, Finished::Pending);
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
                tracing::info!(?user_id, upload_id = %id, "upload finished: wrong file");
                s.record(&id, Finished::WrongFile);
            } else if code == ErrorCode::NotFound {
                // Lost the race with a concurrent final chunk.
                if let Some(f) = s.settled(&id).await {
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
