//! Chunked upload sessions: SHA-256 gate against the known files, and the
//! single load slot that parses the first matching upload into the index.
//! Nothing from the file is written anywhere; bytes are hashed and parsed
//! in memory and dropped.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, TryLockError};

use sha2::{Digest, Sha256};
use urban_definitions_wire::{
    verify_ticket, ErrorCode, StartUpload, StartedUpload, TicketError, UploadMode, UploadProgress,
};

use crate::index::{IndexBuilder, MAX_LINE_BYTES};
use crate::known::KnownFile;
use crate::store::Definitions;

pub const CHUNK_SIZE: u64 = 8_388_608;
pub const MAX_UPLOADS: usize = 4;
pub const IDLE_SECS: i64 = 600;
const MAX_NONCE_CHARS: usize = 64;

pub trait Clock: Send + Sync {
    fn now_unix(&self) -> i64;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkStep {
    Progress(UploadProgress),
    /// The whole file matched a known hash. `loaded` is true when this
    /// upload published the index.
    Matched {
        user_id: i64,
        loaded: bool,
    },
}

/// Per-upload state; locked for the duration of one chunk's hash and parse.
struct Upload {
    size: u64,
    expected: [u8; 32],
    received: u64,
    /// Length of the last accepted chunk, to recognise a re-send.
    last_len: u64,
    last_active: i64,
    hasher: Sha256,
    /// `Some` in load mode only.
    builder: Option<IndexBuilder>,
    /// Partial line carried across chunks (load mode).
    carry: Vec<u8>,
}

struct Entry {
    user_id: i64,
    state: Arc<Mutex<Upload>>,
}

#[derive(Default)]
struct Inner {
    uploads: HashMap<String, Entry>,
    /// Used ticket nonces, kept until their ticket would have expired.
    used_nonces: HashMap<String, i64>,
    /// Id of the upload holding the load slot.
    load_slot: Option<String>,
}

impl Inner {
    /// True when an upload with that id existed.
    fn remove(&mut self, id: &str) -> bool {
        let existed = self.uploads.remove(id).is_some();
        if self.load_slot.as_deref() == Some(id) {
            self.load_slot = None;
        }
        existed
    }
}

pub struct Uploads {
    known: Vec<KnownFile>,
    ticket_key: Vec<u8>,
    store: Arc<Definitions>,
    clock: Arc<dyn Clock>,
    inner: Mutex<Inner>,
}

fn random_id() -> String {
    let mut raw = [0u8; 16];
    getrandom::getrandom(&mut raw).expect("OS randomness available");
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

impl Uploads {
    pub fn new(
        known: Vec<KnownFile>,
        ticket_key: Vec<u8>,
        store: Arc<Definitions>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            known,
            ticket_key,
            store,
            clock,
            inner: Mutex::new(Inner::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("uploads lock poisoned")
    }

    pub fn start(&self, req: StartUpload) -> Result<StartedUpload, ErrorCode> {
        let known = self
            .known
            .iter()
            .find(|k| k.size == req.size)
            .ok_or(ErrorCode::WrongSize)?;
        let now = self.clock.now_unix();
        let ticket = verify_ticket(&self.ticket_key, &req.ticket, now).map_err(|e| match e {
            TicketError::Expired => ErrorCode::TicketExpired,
            TicketError::Malformed | TicketError::BadSignature => ErrorCode::BadTicket,
        })?;
        if ticket.nonce.is_empty() || ticket.nonce.chars().count() > MAX_NONCE_CHARS {
            return Err(ErrorCode::BadTicket);
        }

        let mut inner = self.lock();
        if inner.used_nonces.contains_key(&ticket.nonce) {
            return Err(ErrorCode::TicketUsed);
        }
        if inner.uploads.values().any(|e| e.user_id == ticket.user_id)
            || inner.uploads.len() >= MAX_UPLOADS
        {
            return Err(ErrorCode::TooManyUploads);
        }
        let mode = if self.store.get().is_some() {
            UploadMode::Prove
        } else if inner.load_slot.is_some() {
            return Err(ErrorCode::Busy);
        } else {
            UploadMode::Load
        };

        // Consumed only once the upload really starts, so a refusal above
        // (busy, too many) leaves the player's link usable.
        inner.used_nonces.insert(ticket.nonce, ticket.expires_at);
        let upload_id = random_id();
        if mode == UploadMode::Load {
            inner.load_slot = Some(upload_id.clone());
        }
        inner.uploads.insert(
            upload_id.clone(),
            Entry {
                user_id: ticket.user_id,
                state: Arc::new(Mutex::new(Upload {
                    size: req.size,
                    expected: known.sha256,
                    received: 0,
                    last_len: 0,
                    last_active: now,
                    hasher: Sha256::new(),
                    builder: (mode == UploadMode::Load).then(IndexBuilder::new),
                    carry: Vec::new(),
                })),
            },
        );
        Ok(StartedUpload {
            upload_id,
            chunk_size: CHUNK_SIZE,
            mode,
        })
    }

    fn state_of(&self, id: &str) -> Result<(i64, Arc<Mutex<Upload>>), ErrorCode> {
        self.lock()
            .uploads
            .get(id)
            .map(|e| (e.user_id, e.state.clone()))
            .ok_or(ErrorCode::NotFound)
    }

    /// Hashes (and in load mode parses) one chunk. Holds only this upload's
    /// lock while doing so.
    pub fn chunk(
        &self,
        upload_id: &str,
        offset: u64,
        bytes: &[u8],
    ) -> Result<ChunkStep, ErrorCode> {
        let (user_id, state) = self.state_of(upload_id)?;
        let outcome = {
            let mut up = state.lock().expect("upload lock poisoned");
            self.apply_chunk(&mut up, user_id, offset, bytes)
        };
        match outcome {
            // Finished either way: the upload is over, free its slot.
            Ok(ChunkStep::Matched { .. }) | Err(ErrorCode::WrongFile) => {
                self.lock().remove(upload_id);
            }
            _ => {}
        }
        outcome
    }

    fn apply_chunk(
        &self,
        up: &mut Upload,
        user_id: i64,
        offset: u64,
        bytes: &[u8],
    ) -> Result<ChunkStep, ErrorCode> {
        let len = bytes.len() as u64;
        if len > CHUNK_SIZE {
            return Err(ErrorCode::ChunkTooLarge);
        }
        let progress = |up: &Upload| {
            ChunkStep::Progress(UploadProgress {
                received: up.received,
                size: up.size,
            })
        };
        // A lost acknowledgement: the last accepted chunk again.
        if len > 0 && len == up.last_len && offset + len == up.received {
            up.last_active = self.clock.now_unix();
            return Ok(progress(up));
        }
        if offset != up.received {
            return Err(ErrorCode::WrongOffset);
        }
        if up.received + len > up.size {
            return Err(ErrorCode::ChunkTooLarge);
        }

        up.hasher.update(bytes);
        if let Some(builder) = up.builder.as_mut() {
            feed_lines(builder, &mut up.carry, bytes)?;
        }
        up.received += len;
        up.last_len = len;
        up.last_active = self.clock.now_unix();

        if up.received < up.size {
            return Ok(progress(up));
        }

        // The whole file is in: check the hash before publishing anything.
        let digest: [u8; 32] = std::mem::take(&mut up.hasher).finalize().into();
        if digest != up.expected {
            return Err(ErrorCode::WrongFile);
        }
        let mut loaded = false;
        if let Some(mut builder) = up.builder.take() {
            if !up.carry.is_empty() {
                builder
                    .push_line(&up.carry)
                    .map_err(|_| ErrorCode::WrongFile)?;
            }
            self.store.publish(builder.finish());
            loaded = true;
        }
        Ok(ChunkStep::Matched { user_id, loaded })
    }

    pub fn progress(&self, upload_id: &str) -> Result<UploadProgress, ErrorCode> {
        let (_, state) = self.state_of(upload_id)?;
        let up = state.lock().expect("upload lock poisoned");
        Ok(UploadProgress {
            received: up.received,
            size: up.size,
        })
    }

    /// True when this call removed a live upload.
    pub fn cancel(&self, upload_id: &str) -> bool {
        self.lock().remove(upload_id)
    }

    /// The player an in-flight upload belongs to.
    pub fn user_of(&self, upload_id: &str) -> Option<i64> {
        self.lock().uploads.get(upload_id).map(|e| e.user_id)
    }

    /// Drops idle uploads (freeing the load slot) and nonces whose tickets
    /// have expired anyway. Called by the server every 30 s. Returns how many
    /// idle uploads it dropped.
    pub fn sweep(&self) -> usize {
        let now = self.clock.now_unix();
        let mut inner = self.lock();
        let idle: Vec<String> = inner
            .uploads
            .iter()
            .filter(|(_, e)| match e.state.try_lock() {
                Ok(up) => now - up.last_active > IDLE_SECS,
                // Busy hashing a chunk right now: not idle.
                Err(TryLockError::WouldBlock) => false,
                Err(TryLockError::Poisoned(_)) => true,
            })
            .map(|(id, _)| id.clone())
            .collect();
        let dropped = idle.len();
        for id in idle {
            inner.remove(&id);
        }
        inner.used_nonces.retain(|_, expires_at| *expires_at > now);
        dropped
    }

    #[cfg(test)]
    fn used_nonce_count(&self) -> usize {
        self.lock().used_nonces.len()
    }
}

/// Feeds every complete line in `carry + bytes` to the builder and leaves the
/// trailing partial line in `carry`. Splitting on the `\n` byte is safe for
/// UTF-8: it never occurs inside a multi-byte character.
fn feed_lines(
    builder: &mut IndexBuilder,
    carry: &mut Vec<u8>,
    bytes: &[u8],
) -> Result<(), ErrorCode> {
    let wrong = |_| ErrorCode::WrongFile;
    let mut rest = bytes;
    while let Some(nl) = rest.iter().position(|&b| b == b'\n') {
        let (line, tail) = (&rest[..nl], &rest[nl + 1..]);
        if carry.is_empty() {
            builder.push_line(line).map_err(wrong)?;
        } else {
            carry.extend_from_slice(line);
            builder.push_line(carry).map_err(wrong)?;
            carry.clear();
        }
        rest = tail;
    }
    carry.extend_from_slice(rest);
    if carry.len() > MAX_LINE_BYTES {
        return Err(ErrorCode::WrongFile);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Definitions;
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicI64, Ordering};
    use urban_definitions_wire::{sign_ticket, StartUpload, Ticket, UploadMode, UploadProgress};

    use crate::known::KnownFile;

    const KEY: &[u8] = b"test-key";
    const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/mini.ndjson");

    struct FakeClock(AtomicI64);
    impl Clock for FakeClock {
        fn now_unix(&self) -> i64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    struct Rig {
        up: Uploads,
        store: Arc<Definitions>,
        clock: Arc<FakeClock>,
    }

    fn known_for(bytes: &[u8]) -> KnownFile {
        KnownFile {
            size: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
        }
    }

    fn rig_for(bytes: &[u8]) -> Rig {
        let store = Arc::new(Definitions::new());
        let clock = Arc::new(FakeClock(AtomicI64::new(1_000)));
        let up = Uploads::new(
            vec![known_for(bytes)],
            KEY.to_vec(),
            store.clone(),
            clock.clone(),
        );
        Rig { up, store, clock }
    }

    fn rig() -> Rig {
        rig_for(FIXTURE)
    }

    fn ticket_for(user_id: i64, nonce: &str, expires_at: i64) -> String {
        sign_ticket(
            KEY,
            &Ticket {
                user_id,
                nonce: nonce.to_string(),
                expires_at,
            },
        )
    }

    fn start_as(r: &Rig, user: i64, nonce: &str) -> Result<StartedUpload, ErrorCode> {
        r.up.start(StartUpload {
            ticket: ticket_for(user, nonce, 1_000 + 1800),
            size: FIXTURE.len() as u64,
        })
    }

    /// Send `bytes` in `step`-sized chunks; returns the last step.
    fn send_all(r: &Rig, id: &str, bytes: &[u8], step: usize) -> Result<ChunkStep, ErrorCode> {
        let mut offset = 0usize;
        let mut last = None;
        while offset < bytes.len() {
            let end = (offset + step).min(bytes.len());
            last = Some(r.up.chunk(id, offset as u64, &bytes[offset..end])?);
            offset = end;
        }
        Ok(last.expect("non-empty"))
    }

    #[test]
    fn wrong_size_is_refused_before_any_bytes() {
        let r = rig();
        let err =
            r.up.start(StartUpload {
                ticket: ticket_for(1, "n", 2_800),
                size: FIXTURE.len() as u64 + 1,
            })
            .unwrap_err();
        assert_eq!(err, ErrorCode::WrongSize);
    }

    #[test]
    fn bad_expired_and_reused_tickets() {
        let r = rig();
        let size = FIXTURE.len() as u64;
        let bad = r.up.start(StartUpload {
            ticket: "garbage".into(),
            size,
        });
        assert_eq!(bad.unwrap_err(), ErrorCode::BadTicket);

        let expired = r.up.start(StartUpload {
            ticket: ticket_for(1, "old", 999),
            size,
        });
        assert_eq!(expired.unwrap_err(), ErrorCode::TicketExpired);

        let first = start_as(&r, 1, "once").unwrap();
        r.up.cancel(&first.upload_id);
        assert_eq!(start_as(&r, 1, "once").unwrap_err(), ErrorCode::TicketUsed);
    }

    #[test]
    fn empty_or_overlong_nonce_is_a_bad_ticket() {
        let r = rig();
        assert_eq!(start_as(&r, 1, "").unwrap_err(), ErrorCode::BadTicket);
        let long = "x".repeat(65);
        assert_eq!(start_as(&r, 1, &long).unwrap_err(), ErrorCode::BadTicket);
        start_as(&r, 1, &"x".repeat(64)).unwrap();
    }

    #[test]
    fn first_upload_loads_then_lookups_work() {
        let r = rig();
        let s = start_as(&r, 7, "a").unwrap();
        assert_eq!(s.mode, UploadMode::Load);
        assert_eq!(s.chunk_size, CHUNK_SIZE);
        let step = send_all(&r, &s.upload_id, FIXTURE, 7).unwrap();
        assert_eq!(
            step,
            ChunkStep::Matched {
                user_id: 7,
                loaded: true
            }
        );
        let idx = r.store.get().expect("published");
        assert!(!idx.lookup("JANKY", false).is_empty());
        // Finished upload is gone and its slot is free.
        assert_eq!(
            r.up.progress(&s.upload_id).unwrap_err(),
            ErrorCode::NotFound
        );
    }

    #[test]
    fn whole_file_in_one_chunk_and_odd_sizes_agree() {
        for step in [1usize, 3, 100, FIXTURE.len()] {
            let r = rig();
            let s = start_as(&r, 7, "a").unwrap();
            send_all(&r, &s.upload_id, FIXTURE, step).unwrap();
            let idx = r.store.get().unwrap();
            let whole = {
                let mut b = IndexBuilder::new();
                for l in FIXTURE.split(|&c| c == b'\n') {
                    b.push_line(l).unwrap();
                }
                b.finish()
            };
            assert_eq!(idx.entries(), whole.entries(), "step {step}");
            assert_eq!(idx.lookup("JANKY", false), whole.lookup("JANKY", false));
        }
    }

    #[test]
    fn final_line_without_trailing_newline_is_flushed() {
        let mut bytes = FIXTURE.to_vec();
        while bytes.last() == Some(&b'\n') {
            bytes.pop();
        }
        let r = rig_for(&bytes);
        let s =
            r.up.start(StartUpload {
                ticket: ticket_for(1, "a", 2_800),
                size: bytes.len() as u64,
            })
            .unwrap();
        send_all(&r, &s.upload_id, &bytes, 5).unwrap();
        let full = {
            let mut b = IndexBuilder::new();
            for l in bytes.split(|&c| c == b'\n') {
                b.push_line(l).unwrap();
            }
            b.finish()
        };
        assert_eq!(r.store.get().unwrap().entries(), full.entries());
    }

    #[test]
    fn multibyte_characters_split_across_chunks_parse_whole() {
        // The mini fixture is ASCII (its dump escapes), so build raw UTF-8 here.
        let line = |w: &str, d: &str| {
            format!(r#"{{"word":"{w}","definition":"{d}","thumbs_up":3,"thumbs_down":1}}"#)
        };
        let text = format!(
            "{}\n{}\n",
            line("Caf\u{e9}", "na\u{ef}ve \u{1F600} caf\u{e9}"),
            line("Plain", "plain")
        );
        let bytes = text.into_bytes();
        assert!(!bytes.is_ascii());
        for step in [1usize, 2, 3, 5] {
            let r = rig_for(&bytes);
            let s =
                r.up.start(StartUpload {
                    ticket: ticket_for(1, "a", 2_800),
                    size: bytes.len() as u64,
                })
                .unwrap();
            send_all(&r, &s.upload_id, &bytes, step).unwrap();
            let idx = r.store.get().unwrap();
            let defs = idx.lookup("PLAIN", false);
            assert_eq!(&*defs[0], "plain");
            assert_eq!(idx.entries(), 2, "step {step}");
        }
    }

    #[test]
    fn second_upload_only_proves() {
        let r = rig();
        let a = start_as(&r, 1, "a").unwrap();
        send_all(&r, &a.upload_id, FIXTURE, 4096).unwrap();
        let first = r.store.get().unwrap();

        let b = start_as(&r, 2, "b").unwrap();
        assert_eq!(b.mode, UploadMode::Prove);
        let step = send_all(&r, &b.upload_id, FIXTURE, 4096).unwrap();
        assert_eq!(
            step,
            ChunkStep::Matched {
                user_id: 2,
                loaded: false
            }
        );
        assert!(Arc::ptr_eq(&first, &r.store.get().unwrap()));
    }

    #[test]
    fn busy_while_a_load_is_in_flight() {
        let r = rig();
        let a = start_as(&r, 1, "a").unwrap();
        assert_eq!(a.mode, UploadMode::Load);
        assert_eq!(start_as(&r, 2, "b").unwrap_err(), ErrorCode::Busy);
        // A refused start does not burn the ticket.
        r.up.cancel(&a.upload_id);
        assert_eq!(start_as(&r, 2, "b").unwrap().mode, UploadMode::Load);
    }

    #[test]
    fn abandoned_load_frees_the_slot() {
        let r = rig();
        let a = start_as(&r, 1, "a").unwrap();
        r.up.chunk(&a.upload_id, 0, &FIXTURE[..10]).unwrap();
        r.clock.0.fetch_add(601, Ordering::SeqCst);
        assert_eq!(r.up.sweep(), 1);
        assert_eq!(r.up.sweep(), 0);
        assert_eq!(
            r.up.progress(&a.upload_id).unwrap_err(),
            ErrorCode::NotFound
        );
        let b =
            r.up.start(StartUpload {
                ticket: ticket_for(2, "b", 1_000 + 601 + 1800),
                size: FIXTURE.len() as u64,
            })
            .unwrap();
        assert_eq!(b.mode, UploadMode::Load);
    }

    #[test]
    fn cancel_and_user_of_report_what_they_found() {
        let r = rig();
        let a = start_as(&r, 7, "a").unwrap();
        assert_eq!(r.up.user_of(&a.upload_id), Some(7));
        assert!(r.up.cancel(&a.upload_id));
        assert!(!r.up.cancel(&a.upload_id));
        assert_eq!(r.up.user_of(&a.upload_id), None);
    }

    #[test]
    fn activity_defers_expiry() {
        let r = rig();
        let a = start_as(&r, 1, "a").unwrap();
        r.clock.0.fetch_add(400, Ordering::SeqCst);
        r.up.chunk(&a.upload_id, 0, &FIXTURE[..10]).unwrap();
        r.clock.0.fetch_add(400, Ordering::SeqCst);
        r.up.sweep();
        assert!(r.up.progress(&a.upload_id).is_ok());
    }

    #[test]
    fn sweep_prunes_used_nonces_after_ticket_expiry() {
        let r = rig();
        let a = start_as(&r, 1, "a").unwrap();
        r.up.cancel(&a.upload_id);
        assert_eq!(r.up.used_nonce_count(), 1);
        r.clock.0.fetch_add(1801, Ordering::SeqCst);
        r.up.sweep();
        assert_eq!(r.up.used_nonce_count(), 0);
    }

    #[test]
    fn one_upload_per_player_and_four_in_total() {
        let r = rig();
        start_as(&r, 1, "a").unwrap();
        assert_eq!(start_as(&r, 1, "b").unwrap_err(), ErrorCode::TooManyUploads);
        // Prove-mode uploads once something is loaded.
        r.store.publish(IndexBuilder::new().finish());
        for (u, n) in [(2, "c"), (3, "d"), (4, "e")] {
            start_as(&r, u, n).unwrap();
        }
        assert_eq!(start_as(&r, 5, "f").unwrap_err(), ErrorCode::TooManyUploads);
    }

    #[test]
    fn resent_last_chunk_is_idempotent() {
        let r = rig();
        let s = start_as(&r, 1, "a").unwrap();
        let step = 50usize;
        let mut offset = 0;
        while offset < FIXTURE.len() {
            let end = (offset + step).min(FIXTURE.len());
            let c = &FIXTURE[offset..end];
            let first = r.up.chunk(&s.upload_id, offset as u64, c).unwrap();
            if end < FIXTURE.len() {
                // The acknowledgement was lost: the page sends it again.
                let again = r.up.chunk(&s.upload_id, offset as u64, c).unwrap();
                assert_eq!(first, again);
            }
            offset = end;
        }
        assert!(r.store.get().is_some(), "hash still matched");
    }

    #[test]
    fn out_of_order_chunk_is_refused() {
        let r = rig();
        let s = start_as(&r, 1, "a").unwrap();
        r.up.chunk(&s.upload_id, 0, &FIXTURE[..10]).unwrap();
        assert_eq!(
            r.up.chunk(&s.upload_id, 20, &FIXTURE[20..30]).unwrap_err(),
            ErrorCode::WrongOffset
        );
        // Not the last chunk either.
        assert_eq!(
            r.up.chunk(&s.upload_id, 0, &FIXTURE[..4]).unwrap_err(),
            ErrorCode::WrongOffset
        );
        assert_eq!(
            r.up.progress(&s.upload_id).unwrap(),
            UploadProgress {
                received: 10,
                size: FIXTURE.len() as u64
            }
        );
    }

    #[test]
    fn oversize_chunk_is_refused() {
        let big = vec![b'a'; CHUNK_SIZE as usize + 1];
        let r = rig_for(&big);
        let s =
            r.up.start(StartUpload {
                ticket: ticket_for(1, "a", 2_800),
                size: big.len() as u64,
            })
            .unwrap();
        assert_eq!(
            r.up.chunk(&s.upload_id, 0, &big).unwrap_err(),
            ErrorCode::ChunkTooLarge
        );
    }

    #[test]
    fn unknown_upload_is_not_found() {
        let r = rig();
        assert_eq!(
            r.up.chunk("nope", 0, b"x").unwrap_err(),
            ErrorCode::NotFound
        );
        assert_eq!(r.up.progress("nope").unwrap_err(), ErrorCode::NotFound);
        r.up.cancel("nope");
    }

    #[test]
    fn mismatched_bytes_publish_nothing() {
        let r = rig();
        let s = start_as(&r, 1, "a").unwrap();
        let mut bad = FIXTURE.to_vec();
        let at = bad.iter().position(|&c| c == b'J').unwrap();
        bad[at] = b'K'; // still valid JSON, different hash
        let err = send_all(&r, &s.upload_id, &bad, 64).unwrap_err();
        assert_eq!(err, ErrorCode::WrongFile);
        assert!(r.store.get().is_none());
        assert_eq!(
            r.up.progress(&s.upload_id).unwrap_err(),
            ErrorCode::NotFound
        );
        // The load slot is free again.
        assert_eq!(start_as(&r, 2, "b").unwrap().mode, UploadMode::Load);
    }

    #[test]
    fn garbage_line_aborts_as_wrong_file() {
        let bytes = b"not json at all\n{}\n".to_vec();
        let r = rig_for(&bytes);
        let s =
            r.up.start(StartUpload {
                ticket: ticket_for(1, "a", 2_800),
                size: bytes.len() as u64,
            })
            .unwrap();
        assert_eq!(
            r.up.chunk(&s.upload_id, 0, &bytes).unwrap_err(),
            ErrorCode::WrongFile
        );
        assert!(r.store.get().is_none());
    }

    #[test]
    fn endless_line_aborts_as_wrong_file() {
        let bytes = vec![b'a'; MAX_LINE_BYTES + 10];
        let r = rig_for(&bytes);
        let s =
            r.up.start(StartUpload {
                ticket: ticket_for(1, "a", 2_800),
                size: bytes.len() as u64,
            })
            .unwrap();
        assert_eq!(
            send_all(&r, &s.upload_id, &bytes, 100_000).unwrap_err(),
            ErrorCode::WrongFile
        );
    }

    #[test]
    fn prove_mode_does_not_parse() {
        // Garbage that matches the known hash proves fine when the store is full.
        let bytes = b"not json at all\n".to_vec();
        let r = rig_for(&bytes);
        r.store.publish(IndexBuilder::new().finish());
        let s =
            r.up.start(StartUpload {
                ticket: ticket_for(1, "a", 2_800),
                size: bytes.len() as u64,
            })
            .unwrap();
        assert_eq!(s.mode, UploadMode::Prove);
        assert_eq!(
            r.up.chunk(&s.upload_id, 0, &bytes).unwrap(),
            ChunkStep::Matched {
                user_id: 1,
                loaded: false
            }
        );
    }
}
