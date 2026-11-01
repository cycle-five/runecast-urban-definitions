//! The HTTP surface, driven in-process with `tower::ServiceExt::oneshot`.

use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use urban_definitions_service::clock::{Clock, SystemClock};
use urban_definitions_service::dump;
use urban_definitions_service::http::{router, AppState};
use urban_definitions_service::known::KnownFile;
use urban_definitions_service::relay::UnlockRelay;
use urban_definitions_service::store::Definitions;
use urban_definitions_wire::LookupResponse;

const INTERNAL: &str = "internal-token";
const METRICS: &str = "metrics-token";
const FIXTURE: &[u8] = include_bytes!("fixtures/mini.ndjson");

/// Nothing in this file asks for an unlock.
struct NoRelay;

#[async_trait]
impl UnlockRelay for NoRelay {
    async fn unlock(&self, _user_id: i64) -> anyhow::Result<()> {
        anyhow::bail!("no unlock expected")
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
}

fn rig() -> Rig {
    let store = Arc::new(Definitions::new());
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let state = AppState::new(
        store.clone(),
        Arc::new(NoRelay),
        INTERNAL.into(),
        METRICS.into(),
        prometheus(),
        clock,
    );
    Rig {
        app: router(state),
        store,
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
