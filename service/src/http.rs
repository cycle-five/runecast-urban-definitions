//! Routes. Public ones are forwarded by nginx under `/urban-definitions/`;
//! `/internal/*` and `/health` are reachable on the compose network only.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use metrics_exporter_prometheus::PrometheusHandle;
use serde::Deserialize;
use subtle::ConstantTimeEq;
use urban_definitions_wire::{
    ApiError, ChallengeRequest, ErrorCode, LookupResponse, ProofOutcome, ProofResponse,
};

use crate::challenges::{Challenges, CHALLENGE_PIECES};
use crate::clock::Clock;
use crate::dump::PROOF_PIECE_SIZE;
use crate::metrics as m;
use crate::relay::{unlock_with_retry, UnlockRelay};
use crate::store::Definitions;

/// A finished proof's final answer is kept this long, so a lost response
/// can be re-asked.
pub const FINISHED_KEEP_SECS: i64 = 600;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Finished {
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
    challenges: Arc<Challenges>,
    store: Arc<Definitions>,
    relay: Arc<dyn UnlockRelay>,
    internal_token: Arc<str>,
    metrics_token: Arc<str>,
    metrics: PrometheusHandle,
    clock: Arc<dyn Clock>,
    finished: Arc<Mutex<HashMap<String, (i64, Finished)>>>,
    /// Held across `prove` and the `Pending` record (no await inside), so a
    /// concurrent re-send always finds a record, never a gap.
    prove_gate: Arc<Mutex<()>>,
    /// Pause between unlock attempts.
    pub retry_delay: Duration,
}

impl AppState {
    pub fn new(
        challenges: Arc<Challenges>,
        store: Arc<Definitions>,
        relay: Arc<dyn UnlockRelay>,
        internal_token: String,
        metrics_token: String,
        metrics: PrometheusHandle,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            challenges,
            store,
            relay,
            internal_token: internal_token.into(),
            metrics_token: metrics_token.into(),
            metrics,
            clock,
            finished: Arc::default(),
            prove_gate: Arc::default(),
            retry_delay: Duration::from_secs(1),
        }
    }

    /// Expires old challenges and finished records. Run every 30 s.
    pub fn sweep(&self) {
        for _ in 0..self.challenges.sweep() {
            m::challenge("abandoned");
        }
        m::record_resident();
        let cutoff = self.clock.now_unix() - FINISHED_KEEP_SECS;
        self.finished
            .lock()
            .expect("finished lock poisoned")
            .retain(|_, (at, _)| *at > cutoff);
    }

    /// Keeps the final answer for `id` for `FINISHED_KEEP_SECS`.
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
    /// out (bounded), so the caller never sees a half-finished proof.
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

/// A challenge request is one ticket.
const CHALLENGE_BODY_LIMIT: usize = 4096;
/// A proof is exactly the challenged pieces, never more.
const PROOF_BODY_LIMIT: usize = CHALLENGE_PIECES * PROOF_PIECE_SIZE as usize;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/urban-definitions/challenges",
            post(start_challenge).layer(DefaultBodyLimit::max(CHALLENGE_BODY_LIMIT)),
        )
        .route(
            "/urban-definitions/challenges/{id}/proof",
            post(proof).layer(DefaultBodyLimit::max(PROOF_BODY_LIMIT)),
        )
        .route("/urban-definitions/metrics", get(metrics_page))
        .route("/internal/definitions/{word}", get(lookup))
        .route("/health", get(|| async { StatusCode::OK }))
        .with_state(state)
}

fn status_of(code: ErrorCode) -> StatusCode {
    match code {
        ErrorCode::WrongFile => StatusCode::BAD_REQUEST,
        ErrorCode::BadTicket | ErrorCode::TicketExpired | ErrorCode::TicketUsed => {
            StatusCode::UNAUTHORIZED
        }
        ErrorCode::NotFound => StatusCode::NOT_FOUND,
        ErrorCode::Busy => StatusCode::TOO_MANY_REQUESTS,
        ErrorCode::Unavailable => StatusCode::INTERNAL_SERVER_ERROR,
        ErrorCode::Loading => StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::ChallengeExpired => StatusCode::GONE,
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

async fn start_challenge(State(s): State<AppState>, Json(req): Json<ChallengeRequest>) -> Response {
    match s.challenges.issue(&req.ticket) {
        Ok(challenge) => {
            m::challenge("issued");
            (StatusCode::CREATED, Json(challenge)).into_response()
        }
        Err(code) => {
            m::challenge(match code {
                ErrorCode::Loading => "loading",
                ErrorCode::Busy => "busy",
                _ => "bad_ticket",
            });
            error(code)
        }
    }
}

fn finished_response(f: Finished) -> Response {
    match f {
        Finished::Pending => error(ErrorCode::Unavailable),
        Finished::Done(outcome) => Json(ProofResponse { outcome }).into_response(),
        Finished::WrongFile => error(ErrorCode::WrongFile),
    }
}

async fn proof(State(s): State<AppState>, Path(id): Path<String>, body: Bytes) -> Response {
    // A re-sent proof (lost response) gets the recorded answer.
    if let Some(f) = s.settled(&id).await {
        return finished_response(f);
    }
    // Run to completion even if the client disconnects: a dropped request
    // must not skip the unlock, the metrics or the final-answer record.
    match tokio::spawn(process_proof(s, id.clone(), body)).await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!(error = %e, "proof task failed");
            error(ErrorCode::Unavailable)
        }
    }
}

async fn process_proof(s: AppState, id: String, body: Bytes) -> Response {
    let proved = {
        let _gate = s.prove_gate.lock().expect("prove gate poisoned");
        let result = s.challenges.prove(&id, &body);
        match result {
            Ok(_) => s.record(&id, Finished::Pending),
            Err(ErrorCode::WrongFile) => s.record(&id, Finished::WrongFile),
            Err(_) => {}
        }
        result
    };
    match proved {
        Ok(user_id) => {
            let unlocked = unlock_with_retry(&*s.relay, user_id, s.retry_delay).await;
            let (outcome, label) = if unlocked {
                (ProofOutcome::Unlocked, "unlocked")
            } else {
                (ProofOutcome::UnlockFailed, "unlock_failed")
            };
            m::proof(label);
            tracing::info!(user_id, outcome = label, "proof finished");
            let done = Finished::Done(outcome);
            s.record(&id, done);
            finished_response(done)
        }
        Err(ErrorCode::WrongFile) => {
            m::proof("wrong_file");
            tracing::info!(outcome = "wrong_file", "proof finished");
            error(ErrorCode::WrongFile)
        }
        Err(ErrorCode::ChallengeExpired) => {
            m::proof("expired");
            error(ErrorCode::ChallengeExpired)
        }
        Err(code) => {
            // Lost the race with a concurrent proof for the same challenge.
            if let Some(f) = s.settled(&id).await {
                return finished_response(f);
            }
            m::proof("not_found");
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
