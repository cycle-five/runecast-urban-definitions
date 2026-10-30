//! The HTTP surface, driven in-process with `tower::ServiceExt::oneshot`.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use urban_definitions_service::http::{router, AppState};
use urban_definitions_service::known::KnownFile;
use urban_definitions_service::relay::UnlockRelay;
use urban_definitions_service::store::Definitions;
use urban_definitions_service::uploads::{Clock, SystemClock, Uploads, CHUNK_SIZE};
use urban_definitions_wire::{
    sign_ticket, ApiError, ChunkResponse, ErrorCode, LookupResponse, StartUpload, StartedUpload,
    Ticket, UploadOutcome,
};

const KEY: &[u8] = b"test-key";
const INTERNAL: &str = "internal-token";
const METRICS: &str = "metrics-token";
const FIXTURE: &[u8] = include_bytes!("fixtures/mini.ndjson");

#[derive(Default)]
struct FakeRelay {
    calls: Mutex<Vec<i64>>,
    fail: bool,
}

#[async_trait]
impl UnlockRelay for FakeRelay {
    async fn unlock(&self, user_id: i64) -> anyhow::Result<()> {
        self.calls.lock().unwrap().push(user_id);
        if self.fail {
            anyhow::bail!("backend unreachable");
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
    relay: Arc<FakeRelay>,
}

fn rig(fail: bool) -> Rig {
    let store = Arc::new(Definitions::new());
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let uploads = Arc::new(Uploads::new(
        vec![KnownFile {
            size: FIXTURE.len() as u64,
            sha256: Sha256::digest(FIXTURE).into(),
        }],
        KEY.to_vec(),
        store.clone(),
        clock.clone(),
    ));
    let relay = Arc::new(FakeRelay {
        fail,
        ..Default::default()
    });
    let mut state = AppState::new(
        uploads,
        store,
        relay.clone(),
        INTERNAL.into(),
        METRICS.into(),
        prometheus(),
        clock,
    );
    state.retry_delay = Duration::from_millis(1);
    Rig {
        app: router(state),
        relay,
    }
}

fn ticket(user_id: i64, nonce: &str) -> String {
    sign_ticket(
        KEY,
        &Ticket {
            user_id,
            nonce: nonce.into(),
            expires_at: SystemClock.now_unix() + 1800,
        },
    )
}

async fn send(app: &Router, req: Request<Body>) -> (StatusCode, Vec<u8>) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, body.to_vec())
}

fn json_post(uri: &str, body: &impl serde::Serialize) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

fn put_chunk(id: &str, offset: u64, bytes: Vec<u8>) -> Request<Body> {
    Request::builder()
        .method(Method::PUT)
        .uri(format!("/urban-definitions/uploads/{id}/chunks/{offset}"))
        .body(Body::from(bytes))
        .unwrap()
}

fn get(uri: &str, header: Option<(&str, &str)>) -> Request<Body> {
    let mut b = Request::builder().method(Method::GET).uri(uri);
    if let Some((k, v)) = header {
        b = b.header(k, v);
    }
    b.body(Body::empty()).unwrap()
}

async fn start(app: &Router, user: i64, nonce: &str) -> StartedUpload {
    let (status, body) = send(
        app,
        json_post(
            "/urban-definitions/uploads",
            &StartUpload {
                ticket: ticket(user, nonce),
                size: FIXTURE.len() as u64,
            },
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&body)
    );
    serde_json::from_slice(&body).unwrap()
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

fn finished(outcome: UploadOutcome) -> String {
    serde_json::to_string(&ChunkResponse::Finished { outcome }).unwrap()
}

#[tokio::test]
async fn full_upload_loads_and_unlocks() {
    let r = rig(false);
    assert_eq!(lookup(&r.app, "JANKY").await, LookupResponse::Empty);
    let up = start(&r.app, 42, "n1").await;
    let (status, body) = send(&r.app, put_chunk(&up.upload_id, 0, FIXTURE.to_vec())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        String::from_utf8(body).unwrap(),
        r#"{"status":"finished","outcome":"loaded"}"#
    );
    assert_eq!(*r.relay.calls.lock().unwrap(), vec![42]);
    match lookup(&r.app, "JANKY").await {
        LookupResponse::Loaded { definitions } => assert!(!definitions.is_empty()),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn relay_failure_still_publishes_and_reports_unlock_failed() {
    let r = rig(true);
    let up = start(&r.app, 42, "n1").await;
    let (status, body) = send(&r.app, put_chunk(&up.upload_id, 0, FIXTURE.to_vec())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        String::from_utf8(body).unwrap(),
        finished(UploadOutcome::UnlockFailed)
    );
    assert_eq!(r.relay.calls.lock().unwrap().len(), 3);
    assert!(matches!(
        lookup(&r.app, "JANKY").await,
        LookupResponse::Loaded { definitions } if !definitions.is_empty()
    ));
}

#[tokio::test]
async fn resent_final_chunk_gets_the_same_answer_without_a_second_unlock() {
    let r = rig(false);
    let up = start(&r.app, 42, "n1").await;
    let uri = format!("/urban-definitions/uploads/{}", up.upload_id);
    let (_, first) = send(&r.app, put_chunk(&up.upload_id, 0, FIXTURE.to_vec())).await;
    let (status, again) = send(&r.app, put_chunk(&up.upload_id, 0, FIXTURE.to_vec())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(again, first);
    assert_eq!(
        String::from_utf8(again).unwrap(),
        r#"{"status":"finished","outcome":"loaded"}"#
    );
    let (status, polled) = send(&r.app, get(&uri, None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(polled, first);
    assert_eq!(r.relay.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn wrong_file_is_400_and_stays_400_on_a_resend() {
    let r = rig(false);
    let up = start(&r.app, 42, "n1").await;
    let mut bad = FIXTURE.to_vec();
    bad[0] = b' ';
    for _ in 0..2 {
        let (status, body) = send(&r.app, put_chunk(&up.upload_id, 0, bad.clone())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            serde_json::from_slice::<ApiError>(&body).unwrap().error,
            ErrorCode::WrongFile
        );
    }
    assert!(r.relay.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn progress_and_cancel() {
    let r = rig(false);
    let up = start(&r.app, 42, "n1").await;
    let uri = format!("/urban-definitions/uploads/{}", up.upload_id);
    let (status, body) = send(&r.app, get(&uri, None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        String::from_utf8(body).unwrap(),
        format!(r#"{{"received":0,"size":{}}}"#, FIXTURE.len())
    );
    let del = Request::builder()
        .method(Method::DELETE)
        .uri(&uri)
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&r.app, del).await.0, StatusCode::NO_CONTENT);
    assert_eq!(send(&r.app, get(&uri, None)).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn start_errors_map_to_statuses() {
    let r = rig(false);
    let bad_size = StartUpload {
        ticket: ticket(1, "a"),
        size: 7,
    };
    let (s, _) = send(&r.app, json_post("/urban-definitions/uploads", &bad_size)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let bad_ticket = StartUpload {
        ticket: "nope".into(),
        size: FIXTURE.len() as u64,
    };
    let (s, body) = send(&r.app, json_post("/urban-definitions/uploads", &bad_ticket)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(
        serde_json::from_slice::<ApiError>(&body).unwrap().error,
        ErrorCode::BadTicket
    );
    start(&r.app, 5, "same-user").await;
    let again = StartUpload {
        ticket: ticket(5, "other"),
        size: FIXTURE.len() as u64,
    };
    let (s, body) = send(&r.app, json_post("/urban-definitions/uploads", &again)).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        serde_json::from_slice::<ApiError>(&body).unwrap().error,
        ErrorCode::TooManyUploads
    );
    let second_loader = StartUpload {
        ticket: ticket(6, "n6"),
        size: FIXTURE.len() as u64,
    };
    let (s, body) = send(
        &r.app,
        json_post("/urban-definitions/uploads", &second_loader),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(
        serde_json::from_slice::<ApiError>(&body).unwrap().error,
        ErrorCode::Busy
    );
}

#[tokio::test]
async fn internal_routes_need_the_token() {
    let r = rig(false);
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
    let r = rig(false);
    let up = start(&r.app, 42, "n1").await;
    send(&r.app, put_chunk(&up.upload_id, 0, FIXTURE.to_vec())).await;
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
    let r = rig(false);
    let up = start(&r.app, 42, "n1").await;
    send(&r.app, put_chunk(&up.upload_id, 0, FIXTURE.to_vec())).await;
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
async fn chunk_one_byte_over_the_limit_is_400_chunk_too_large() {
    let r = rig(false);
    let up = start(&r.app, 42, "n1").await;
    let (status, body) = send(
        &r.app,
        put_chunk(&up.upload_id, 0, vec![b'x'; CHUNK_SIZE as usize + 1]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        serde_json::from_slice::<ApiError>(&body).unwrap().error,
        ErrorCode::ChunkTooLarge
    );
}

#[tokio::test]
async fn bodies_far_over_the_limit_get_413() {
    let r = rig(false);
    let up = start(&r.app, 42, "n1").await;
    let (status, _) = send(
        &r.app,
        put_chunk(
            &up.upload_id,
            0,
            vec![b'x'; CHUNK_SIZE as usize + (2 << 20)],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn metrics_need_the_bearer() {
    let r = rig(false);
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
    assert!(text.contains("urban_definitions_uploads_total"), "{text}");
}
