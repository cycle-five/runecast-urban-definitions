//! The HTTP surface, driven in-process with `tower::ServiceExt::oneshot`.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use urban_definitions_service::challenges::Challenges;
use urban_definitions_service::clock::{Clock, SystemClock};
use urban_definitions_service::dump;
use urban_definitions_service::http::{router, AppState};
use urban_definitions_service::known::KnownFile;
use urban_definitions_service::relay::UnlockRelay;
use urban_definitions_service::store::Definitions;
use urban_definitions_wire::{
    sign_ticket, Challenge, ErrorCode, LookupResponse, ProofOutcome, ProofResponse, Ticket,
    TICKET_TTL_SECS,
};

const INTERNAL: &str = "internal-token";
const METRICS: &str = "metrics-token";
const KEY: &[u8] = b"ticket-key";
const FIXTURE: &[u8] = include_bytes!("fixtures/mini.ndjson");

/// Records unlock calls; can be slow or failing.
#[derive(Default)]
struct FakeRelay {
    calls: Mutex<Vec<i64>>,
    delay: Duration,
    fail: bool,
}

#[async_trait]
impl UnlockRelay for FakeRelay {
    async fn unlock(&self, user_id: i64) -> anyhow::Result<()> {
        self.calls.lock().unwrap().push(user_id);
        tokio::time::sleep(self.delay).await;
        if self.fail {
            anyhow::bail!("backend down");
        }
        Ok(())
    }
}

fn prometheus() -> PrometheusHandle {
    static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();
    HANDLE
        .get_or_init(|| {
            let handle = PrometheusBuilder::new()
                .install_recorder()
                .expect("one global recorder");
            urban_definitions_service::metrics::init();
            handle
        })
        .clone()
}

struct Rig {
    app: Router,
    store: Arc<Definitions>,
    relay: Arc<FakeRelay>,
}

fn rig() -> Rig {
    rig_with(FakeRelay::default())
}

fn rig_with(relay: FakeRelay) -> Rig {
    let store = Arc::new(Definitions::new());
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let relay = Arc::new(relay);
    let challenges = Arc::new(Challenges::new(KEY.to_vec(), store.clone(), clock.clone()));
    let mut state = AppState::new(
        challenges,
        store.clone(),
        relay.clone(),
        INTERNAL.into(),
        METRICS.into(),
        prometheus(),
        clock,
    );
    state.retry_delay = Duration::from_millis(5);
    Rig {
        app: router(state),
        store,
        relay,
    }
}

/// Loads the fixture the way production loads muninn's file: zstd in,
/// verified, index and proof table out.
fn publish_fixture(store: &Definitions) {
    let known = KnownFile {
        size: FIXTURE.len() as u64,
        sha256: Sha256::digest(FIXTURE).into(),
        chunk_size: FIXTURE.len() as u64,
        chunks: vec![<[u8; 32]>::from(Sha256::digest(FIXTURE))].into(),
    };
    let compressed = zstd::encode_all(FIXTURE, 3).unwrap();
    let far_future = Instant::now() + Duration::from_secs(3600);
    let dump = dump::load(&compressed[..], &known, 64, far_future).expect("fixture loads");
    store.publish(dump);
}

async fn send(app: &Router, req: Request<Body>) -> (StatusCode, Vec<u8>) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, body.to_vec())
}

fn get(uri: &str, header: Option<(&str, &str)>) -> Request<Body> {
    let mut b = Request::builder().method(Method::GET).uri(uri);
    if let Some((k, v)) = header {
        b = b.header(k, v);
    }
    b.body(Body::empty()).unwrap()
}

async fn lookup(app: &Router, word: &str) -> LookupResponse {
    let (status, body) = send(
        app,
        get(
            &format!("/internal/definitions/{word}?glued=false"),
            Some(("x-internal-token", INTERNAL)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn upload_routes_are_gone() {
    let r = rig();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/urban-definitions/uploads")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"ticket":"t","size":5}"#))
        .unwrap();
    let (s, _) = send(&r.app, req).await;
    assert!(
        s == StatusCode::NOT_FOUND || s == StatusCode::METHOD_NOT_ALLOWED,
        "{s}"
    );
}

#[tokio::test]
async fn a_published_dump_serves_a_hit() {
    let r = rig();
    assert_eq!(lookup(&r.app, "JANKY").await, LookupResponse::Empty);
    publish_fixture(&r.store);
    assert!(matches!(
        lookup(&r.app, "JANKY").await,
        LookupResponse::Loaded { definitions } if !definitions.is_empty()
    ));
}

#[tokio::test]
async fn internal_routes_need_the_token() {
    let r = rig();
    let (s, _) = send(&r.app, get("/internal/definitions/JANKY", None)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = send(
        &r.app,
        get(
            "/internal/definitions/JANKY",
            Some(("x-internal-token", "bad")),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // Before any load.
    assert_eq!(lookup(&r.app, "JANKY").await, LookupResponse::Empty);
    // Health needs no token.
    assert_eq!(send(&r.app, get("/health", None)).await.0, StatusCode::OK);
}

#[tokio::test]
async fn unknown_word_is_an_empty_list_and_lookup_uppercases() {
    let r = rig();
    publish_fixture(&r.store);
    assert_eq!(
        lookup(&r.app, "zzzzqq").await,
        LookupResponse::Loaded {
            definitions: vec![]
        }
    );
    assert!(matches!(
        lookup(&r.app, "janky").await,
        LookupResponse::Loaded { definitions } if !definitions.is_empty()
    ));
}

#[tokio::test]
async fn glued_flag_reaches_the_index() {
    let r = rig();
    publish_fixture(&r.store);
    let ask = |glued: &str| {
        get(
            &format!("/internal/definitions/ICECREAM?glued={glued}"),
            Some(("x-internal-token", INTERNAL)),
        )
    };
    let (_, with) = send(&r.app, ask("true")).await;
    let (_, without) = send(&r.app, ask("false")).await;
    let with: LookupResponse = serde_json::from_slice(&with).unwrap();
    let without: LookupResponse = serde_json::from_slice(&without).unwrap();
    assert!(matches!(with, LookupResponse::Loaded { definitions } if !definitions.is_empty()));
    assert_eq!(
        without,
        LookupResponse::Loaded {
            definitions: vec![]
        }
    );
}

#[tokio::test]
async fn metrics_need_the_bearer() {
    let r = rig();
    let (s, _) = send(&r.app, get("/urban-definitions/metrics", None)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = send(
        &r.app,
        get(
            "/urban-definitions/metrics",
            Some(("authorization", "Bearer wrong")),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, body) = send(
        &r.app,
        get(
            "/urban-definitions/metrics",
            Some(("authorization", "Bearer metrics-token")),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let text = String::from_utf8(body).unwrap();
    assert!(text.contains("urban_definitions_loaded"), "{text}");
    assert!(text.contains("urban_definitions_resident_bytes"), "{text}");
}

fn ticket(user_id: i64, nonce: &str) -> String {
    let now = SystemClock.now_unix();
    sign_ticket(
        KEY,
        &Ticket {
            user_id,
            nonce: nonce.into(),
            expires_at: now + TICKET_TTL_SECS,
        },
    )
}

fn post_challenge(ticket: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/urban-definitions/challenges")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(format!(r#"{{"ticket":"{ticket}"}}"#)))
        .unwrap()
}

fn post_proof(id: &str, body: Vec<u8>) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(format!("/urban-definitions/challenges/{id}/proof"))
        .body(Body::from(body))
        .unwrap()
}

fn body_for(c: &Challenge) -> Vec<u8> {
    let size = c.piece_size as usize;
    c.pieces
        .iter()
        .flat_map(|&i| {
            let start = i as usize * size;
            FIXTURE[start..(start + size).min(FIXTURE.len())].to_vec()
        })
        .collect()
}

async fn challenge_for(r: &Rig, user_id: i64, nonce: &str) -> Challenge {
    let (s, body) = send(&r.app, post_challenge(&ticket(user_id, nonce))).await;
    assert_eq!(s, StatusCode::CREATED);
    serde_json::from_slice(&body).unwrap()
}

fn error_of(body: &[u8]) -> ErrorCode {
    serde_json::from_slice::<urban_definitions_wire::ApiError>(body)
        .unwrap()
        .error
}

#[tokio::test]
async fn challenge_while_loading_is_503_and_the_ticket_survives() {
    let r = rig();
    let t = ticket(7, "a");
    let (s, body) = send(&r.app, post_challenge(&t)).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error_of(&body), ErrorCode::Loading);
    publish_fixture(&r.store);
    let (s, _) = send(&r.app, post_challenge(&t)).await;
    assert_eq!(s, StatusCode::CREATED);
}

#[tokio::test]
async fn ticket_and_cap_errors_have_their_status() {
    let r = rig();
    publish_fixture(&r.store);
    let (s, body) = send(&r.app, post_challenge("garbage")).await;
    assert_eq!(
        (s, error_of(&body)),
        (StatusCode::UNAUTHORIZED, ErrorCode::BadTicket)
    );
    for n in 0..256 {
        challenge_for(&r, n, &format!("n{n}")).await;
    }
    let (s, body) = send(&r.app, post_challenge(&ticket(1, "extra"))).await;
    assert_eq!(
        (s, error_of(&body)),
        (StatusCode::TOO_MANY_REQUESTS, ErrorCode::Busy)
    );
}

#[tokio::test]
async fn a_proof_unlocks_through_the_relay() {
    let r = rig();
    publish_fixture(&r.store);
    let c = challenge_for(&r, 77, "a").await;
    let (s, body) = send(&r.app, post_proof(&c.challenge_id, body_for(&c))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body, br#"{"outcome":"unlocked"}"#);
    assert_eq!(*r.relay.calls.lock().unwrap(), vec![77]);
}

#[tokio::test]
async fn a_repeated_proof_returns_the_recorded_answer_and_relays_once() {
    let r = rig_with(FakeRelay {
        delay: Duration::from_millis(300),
        ..Default::default()
    });
    publish_fixture(&r.store);
    let c = challenge_for(&r, 77, "a").await;
    let first = {
        let app = r.app.clone();
        let req = post_proof(&c.challenge_id, body_for(&c));
        tokio::spawn(async move { send(&app, req).await })
    };
    // Re-send while the relay is still running.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (s, body) = send(&r.app, post_proof(&c.challenge_id, body_for(&c))).await;
    assert_eq!(s, StatusCode::OK);
    let resp: ProofResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp.outcome, ProofOutcome::Unlocked);
    let (s1, b1) = first.await.unwrap();
    assert_eq!((s1, b1), (StatusCode::OK, body));
    // And again, once finished.
    let (s, _) = send(&r.app, post_proof(&c.challenge_id, Vec::new())).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(*r.relay.calls.lock().unwrap(), vec![77]);
}

#[tokio::test]
async fn a_wrong_piece_is_400_wrong_file_and_the_relay_is_not_called() {
    let r = rig();
    publish_fixture(&r.store);
    let c = challenge_for(&r, 77, "a").await;
    let mut body = body_for(&c);
    body[10] ^= 1;
    let (s, resp) = send(&r.app, post_proof(&c.challenge_id, body)).await;
    assert_eq!(
        (s, error_of(&resp)),
        (StatusCode::BAD_REQUEST, ErrorCode::WrongFile)
    );
    // The recorded answer is what a re-send gets.
    let (s, resp) = send(&r.app, post_proof(&c.challenge_id, body_for(&c))).await;
    assert_eq!(
        (s, error_of(&resp)),
        (StatusCode::BAD_REQUEST, ErrorCode::WrongFile)
    );
    assert!(r.relay.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_failing_relay_reports_unlock_failed() {
    let r = rig_with(FakeRelay {
        fail: true,
        ..Default::default()
    });
    publish_fixture(&r.store);
    let c = challenge_for(&r, 77, "a").await;
    let (s, body) = send(&r.app, post_proof(&c.challenge_id, body_for(&c))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body, br#"{"outcome":"unlock_failed"}"#);
    assert_eq!(r.relay.calls.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn an_unknown_challenge_is_404() {
    let r = rig();
    publish_fixture(&r.store);
    let (s, body) = send(&r.app, post_proof("nope", vec![1, 2, 3])).await;
    assert_eq!(
        (s, error_of(&body)),
        (StatusCode::NOT_FOUND, ErrorCode::NotFound)
    );
}

#[tokio::test]
async fn an_oversized_proof_is_413() {
    let r = rig();
    publish_fixture(&r.store);
    let c = challenge_for(&r, 77, "a").await;
    let (s, _) = send(&r.app, post_proof(&c.challenge_id, vec![0; 32 * 4096 + 1])).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
    let big = format!(r#"{{"ticket":"{}"}}"#, "x".repeat(5000));
    let req = Request::builder()
        .method(Method::POST)
        .uri("/urban-definitions/challenges")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(big))
        .unwrap();
    assert_eq!(send(&r.app, req).await.0, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn metrics_count_challenges_and_proofs() {
    let r = rig();
    publish_fixture(&r.store);
    let c = challenge_for(&r, 77, "a").await;
    send(&r.app, post_proof(&c.challenge_id, body_for(&c))).await;
    let (_, body) = send(
        &r.app,
        get(
            "/urban-definitions/metrics",
            Some(("authorization", "Bearer metrics-token")),
        ),
    )
    .await;
    let text = String::from_utf8(body).unwrap();
    for series in [
        r#"urban_definitions_challenges_total{outcome="issued"}"#,
        r#"urban_definitions_challenges_total{outcome="abandoned"}"#,
        r#"urban_definitions_proofs_total{outcome="unlocked"}"#,
        r#"urban_definitions_proofs_total{outcome="not_found"}"#,
    ] {
        assert!(text.contains(series), "{series}\n{text}");
    }
}
