//! Loads the dump from the source until one load verifies, then publishes it.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::dump::{self, LoadError, MAX_LOAD_SECS, PROOF_PIECE_SIZE};
use crate::known::KnownFile;
use crate::metrics;
use crate::source::DumpSource;
use crate::store::Definitions;

const BASE_SECS: u64 = 60;
const CAP_SECS: u64 = 1800;

/// The n-th consecutive failure waits `min(60 * 2^(n-1), 1800)` seconds plus
/// `jitter` (in `[0, 1)`) of 20 % of that.
pub fn backoff_delay(failures: u32, jitter: f64) -> Duration {
    let shift = failures.saturating_sub(1).min(16);
    let base = (BASE_SECS << shift).min(CAP_SECS);
    Duration::from_secs_f64(base as f64 * (1.0 + 0.2 * jitter.clamp(0.0, 1.0)))
}

fn attempt(
    source: &dyn DumpSource,
    known: &KnownFile,
) -> Result<dump::Dump, (&'static str, String)> {
    let stream = source.open().map_err(|e| ("source_error", e.to_string()))?;
    let deadline = Instant::now() + Duration::from_secs(MAX_LOAD_SECS);
    dump::load(stream, known, PROOF_PIECE_SIZE, deadline).map_err(|e| {
        let text = match &e {
            LoadError::Source(io) => io.to_string(),
            LoadError::WrongFile => "wrong file".to_string(),
            LoadError::TimedOut => "timed out".to_string(),
        };
        (e.label(), text)
    })
}

/// Loads until one load succeeds and is published, then returns. The only
/// writer of the store.
pub async fn run_loader(
    source: Arc<dyn DumpSource>,
    known: KnownFile,
    store: Arc<Definitions>,
    delay: impl Fn(u32) -> Duration + Send,
) {
    let known = Arc::new(known);
    let mut failures: u32 = 0;
    loop {
        let started = Instant::now();
        let (src, kn) = (source.clone(), known.clone());
        let result = tokio::task::spawn_blocking(move || attempt(src.as_ref(), &kn)).await;
        let result = result.unwrap_or_else(|e| Err(("source_error", format!("load task: {e}"))));
        match result {
            Ok(dump) => {
                let entries = dump.index.entries();
                let secs = started.elapsed().as_secs_f64();
                store.publish(dump);
                metrics::load("loaded");
                metrics::set_last_load_seconds(secs);
                metrics::set_loaded(Some(entries));
                tracing::info!(entries, seconds = secs, "dump loaded");
                return;
            }
            Err((outcome, error)) => {
                failures = failures.saturating_add(1);
                metrics::load(outcome);
                tracing::warn!(failures, outcome, error = %error, "dump load failed");
                tokio::time::sleep(delay(failures)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dump::PROOF_PIECE_SIZE;
    use crate::known::KnownFile;
    use crate::source::DumpSource;
    use sha2::{Digest, Sha256};
    use std::collections::VecDeque;
    use std::io::{self, Cursor, Read};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/mini.ndjson");

    fn known() -> KnownFile {
        KnownFile {
            size: FIXTURE.len() as u64,
            sha256: Sha256::digest(FIXTURE).into(),
            chunk_size: 10,
            chunks: FIXTURE
                .chunks(10)
                .map(|c| <[u8; 32]>::from(Sha256::digest(c)))
                .collect(),
        }
    }

    fn good() -> Vec<u8> {
        zstd::encode_all(FIXTURE, 3).unwrap()
    }

    fn tampered() -> Vec<u8> {
        let mut bad = FIXTURE.to_vec();
        let at = bad.iter().position(|&c| c == b'J').unwrap();
        bad[at] = b'K';
        zstd::encode_all(&bad[..], 3).unwrap()
    }

    struct Fake {
        queue: Mutex<VecDeque<io::Result<Vec<u8>>>>,
        repeat_last: Option<Vec<u8>>,
        opens: AtomicUsize,
    }

    impl DumpSource for Fake {
        fn open(&self) -> io::Result<Box<dyn Read + Send>> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            let next = self.queue.lock().unwrap().pop_front();
            match next {
                Some(Ok(b)) => Ok(Box::new(Cursor::new(b))),
                Some(Err(e)) => Err(e),
                None => Ok(Box::new(Cursor::new(
                    self.repeat_last.clone().unwrap_or_default(),
                ))),
            }
        }
    }

    #[test]
    fn backoff_doubles_from_a_minute_to_a_half_hour_cap() {
        let s = Duration::from_secs;
        assert_eq!(backoff_delay(1, 0.0), s(60));
        assert_eq!(backoff_delay(2, 0.0), s(120));
        assert_eq!(backoff_delay(5, 0.0), s(960));
        assert_eq!(backoff_delay(6, 0.0), s(1800));
        assert_eq!(backoff_delay(1000, 0.0), s(1800));
        assert!(backoff_delay(1, 0.999) < s(72));
        assert!(backoff_delay(1, 0.5) > s(60));
    }

    #[tokio::test]
    async fn retries_until_a_load_verifies() {
        let source = Arc::new(Fake {
            queue: Mutex::new(
                vec![Err(io::Error::other("refused")), Ok(tampered()), Ok(good())].into(),
            ),
            repeat_last: None,
            opens: AtomicUsize::new(0),
        });
        let store = Arc::new(Definitions::new());
        let asked = Arc::new(Mutex::new(Vec::new()));
        let log = asked.clone();
        run_loader(source.clone(), known(), store.clone(), move |n| {
            log.lock().unwrap().push(n);
            Duration::ZERO
        })
        .await;
        let d = store.get().expect("published");
        assert!(d.index.entries() > 0);
        assert_eq!(d.proof.piece_size(), PROOF_PIECE_SIZE);
        assert_eq!(source.opens.load(Ordering::SeqCst), 3);
        assert_eq!(*asked.lock().unwrap(), vec![1, 2]);
    }

    #[tokio::test]
    async fn nothing_is_published_while_loads_fail() {
        let source = Arc::new(Fake {
            queue: Mutex::new(VecDeque::new()),
            repeat_last: Some(tampered()),
            opens: AtomicUsize::new(0),
        });
        let store = Arc::new(Definitions::new());
        let run = run_loader(source, known(), store.clone(), |_| Duration::from_millis(5));
        let _ = tokio::time::timeout(Duration::from_millis(200), run).await;
        assert!(store.get().is_none());
    }
}
