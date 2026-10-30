use std::sync::Arc;
use std::time::Duration;

use metrics_exporter_prometheus::PrometheusBuilder;
use urban_definitions_service::config::Config;
use urban_definitions_service::http::{router, AppState};
use urban_definitions_service::known::KNOWN_FILES;
use urban_definitions_service::metrics;
use urban_definitions_service::relay::HttpRelay;
use urban_definitions_service::store::Definitions;
use urban_definitions_service::uploads::{SystemClock, Uploads};

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
    let clock = Arc::new(SystemClock);
    let uploads = Arc::new(Uploads::new(
        KNOWN_FILES.to_vec(),
        cfg.ticket_key.clone().into_bytes(),
        store.clone(),
        clock.clone(),
    ));
    let relay = Arc::new(HttpRelay::new(
        &cfg.backend_internal_url,
        cfg.internal_token.clone(),
    )?);
    let state = AppState::new(
        uploads,
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
