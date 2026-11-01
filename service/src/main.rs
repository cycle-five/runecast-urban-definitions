use std::sync::Arc;
use std::time::Duration;

use metrics_exporter_prometheus::PrometheusBuilder;
use urban_definitions_service::clock::SystemClock;
use urban_definitions_service::config::Config;
use urban_definitions_service::http::{router, AppState};
use urban_definitions_service::known::known_files;
use urban_definitions_service::loader::{backoff_delay, run_loader};
use urban_definitions_service::metrics;
use urban_definitions_service::relay::HttpRelay;
use urban_definitions_service::source::SshSource;
use urban_definitions_service::store::Definitions;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cfg = Config::from_env()?;
    let prometheus = PrometheusBuilder::new().install_recorder()?;
    metrics::init();

    let store = Arc::new(Definitions::new());
    match cfg.dump_source.clone() {
        Some(ssh) => {
            let known = known_files().remove(0);
            let source = Arc::new(SshSource::new(ssh));
            tokio::spawn(run_loader(source, known, store.clone(), |n| {
                backoff_delay(n, jitter())
            }));
        }
        None => tracing::error!("DUMP_SSH_HOST is not set: the dump is never loaded"),
    }
    let clock = Arc::new(SystemClock);
    let relay = Arc::new(HttpRelay::new(
        &cfg.backend_internal_url,
        cfg.internal_token.clone(),
    )?);
    let state = AppState::new(
        store,
        relay,
        cfg.internal_token,
        cfg.metrics_token,
        prometheus,
        clock,
    );

    let sweeper = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        loop {
            tick.tick().await;
            sweeper.sweep();
        }
    });

    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr).await?;
    tracing::info!(addr = %cfg.bind_addr, "urban-definitions listening");
    axum::serve(listener, router(state)).await?;
    Ok(())
}

/// A random value in `[0, 1)`; 0 if the system source fails (no jitter).
fn jitter() -> f64 {
    let mut b = [0u8; 8];
    if getrandom::getrandom(&mut b).is_err() {
        return 0.0;
    }
    (u64::from_le_bytes(b) >> 11) as f64 / (1u64 << 53) as f64
}
