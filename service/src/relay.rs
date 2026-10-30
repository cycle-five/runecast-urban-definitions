//! The unlock call to the backend, behind a trait so tests use a fake.

use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use urban_definitions_wire::UnlockRequest;

pub const ATTEMPTS: usize = 3;

#[async_trait]
pub trait UnlockRelay: Send + Sync {
    /// Tells the backend the player proved they own the file.
    async fn unlock(&self, user_id: i64) -> anyhow::Result<()>;
}

/// Tries the unlock `ATTEMPTS` times, `delay` apart. True when one succeeded.
pub async fn unlock_with_retry(relay: &dyn UnlockRelay, user_id: i64, delay: Duration) -> bool {
    for attempt in 1..=ATTEMPTS {
        match relay.unlock(user_id).await {
            Ok(()) => return true,
            Err(e) => tracing::warn!(user_id, attempt, error = %e, "unlock call failed"),
        }
        if attempt < ATTEMPTS {
            tokio::time::sleep(delay).await;
        }
    }
    false
}

pub struct HttpRelay {
    client: reqwest::Client,
    url: String,
    token: String,
}

impl HttpRelay {
    pub fn new(backend_internal_url: &str, token: String) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .context("building unlock HTTP client")?;
        Ok(Self {
            client,
            url: format!(
                "{}/internal/urban-definitions/unlock",
                backend_internal_url.trim_end_matches('/')
            ),
            token,
        })
    }
}

#[async_trait]
impl UnlockRelay for HttpRelay {
    async fn unlock(&self, user_id: i64) -> anyhow::Result<()> {
        let body = serde_json::to_vec(&UnlockRequest { user_id })?;
        let resp = self
            .client
            .post(&self.url)
            .header("X-Internal-Token", &self.token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .context("unlock request failed")?;
        if resp.status() != reqwest::StatusCode::NO_CONTENT {
            anyhow::bail!("unlock returned status {}", resp.status());
        }
        Ok(())
    }
}
