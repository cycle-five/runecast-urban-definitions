//! The spot check: a challenge names 32 random 4 KiB pieces of the file, and
//! the player proves they hold it by sending exactly those pieces. Nothing
//! the player sends is stored or logged; the bytes are hashed and dropped.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use urban_definitions_wire::{verify_ticket, Challenge, ErrorCode, TicketError};

use crate::clock::Clock;
use crate::dump::Dump;
use crate::store::Definitions;

pub const CHALLENGE_PIECES: usize = 32;
pub const CHALLENGE_TTL_SECS: i64 = 120;
pub const MAX_OPEN_CHALLENGES: usize = 256;
const MAX_NONCE_CHARS: usize = 64;

struct Open {
    user_id: i64,
    expires_at: i64,
    pieces: Vec<u64>,
    /// The dump the pieces were drawn from.
    dump: Arc<Dump>,
}

#[derive(Default)]
struct Inner {
    challenges: HashMap<String, Open>,
    /// Spent ticket nonces -> (ticket expiry, the challenge they bought).
    nonces: HashMap<String, (i64, String)>,
}

pub struct Challenges {
    ticket_key: Vec<u8>,
    store: Arc<Definitions>,
    clock: Arc<dyn Clock>,
    inner: Mutex<Inner>,
}

fn random_u64() -> Result<u64, ErrorCode> {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).map_err(|_| ErrorCode::Unavailable)?;
    Ok(u64::from_le_bytes(b))
}

/// Uniform in `[0, bound)` by rejection sampling (no modulo bias). `bound > 0`.
fn below(bound: u64) -> Result<u64, ErrorCode> {
    let zone = (u64::MAX / bound) * bound;
    loop {
        let x = random_u64()?;
        if x < zone {
            return Ok(x % bound);
        }
    }
}

/// `min(wanted, count)` distinct indices below `count`, ascending.
fn sample_pieces(count: u64, wanted: usize) -> Result<Vec<u64>, ErrorCode> {
    if count <= wanted as u64 {
        return Ok((0..count).collect());
    }
    let mut chosen = BTreeSet::new();
    while chosen.len() < wanted {
        chosen.insert(below(count)?);
    }
    Ok(chosen.into_iter().collect())
}

fn random_id() -> Result<String, ErrorCode> {
    let mut raw = [0u8; 16];
    getrandom::getrandom(&mut raw).map_err(|_| ErrorCode::Unavailable)?;
    Ok(raw.iter().map(|b| format!("{b:02x}")).collect())
}

impl Challenges {
    pub fn new(ticket_key: Vec<u8>, store: Arc<Definitions>, clock: Arc<dyn Clock>) -> Self {
        Self {
            ticket_key,
            store,
            clock,
            inner: Mutex::new(Inner::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("challenges lock poisoned")
    }

    /// Store empty -> `Loading` (ticket NOT spent). Bad, expired or used
    /// ticket -> `BadTicket` / `TicketExpired` / `TicketUsed`. A ticket whose
    /// challenge is still open gets that same challenge back. Over
    /// `MAX_OPEN_CHALLENGES` -> `Busy` (ticket not spent).
    pub fn issue(&self, ticket: &str) -> Result<Challenge, ErrorCode> {
        let now = self.clock.now_unix();
        let t = verify_ticket(&self.ticket_key, ticket, now).map_err(|e| match e {
            TicketError::Expired => ErrorCode::TicketExpired,
            TicketError::Malformed | TicketError::BadSignature => ErrorCode::BadTicket,
        })?;
        if t.nonce.is_empty() || t.nonce.chars().count() > MAX_NONCE_CHARS {
            return Err(ErrorCode::BadTicket);
        }
        let dump = self.store.get().ok_or(ErrorCode::Loading)?;

        let mut inner = self.lock();
        if let Some((_, id)) = inner.nonces.get(&t.nonce) {
            return match inner.challenges.get(id) {
                Some(open) if open.expires_at > now => Ok(Challenge {
                    challenge_id: id.clone(),
                    piece_size: open.dump.proof.piece_size(),
                    pieces: open.pieces.clone(),
                }),
                _ => Err(ErrorCode::TicketUsed),
            };
        }
        let live = inner
            .challenges
            .values()
            .filter(|c| c.expires_at > now)
            .count();
        if live >= MAX_OPEN_CHALLENGES {
            return Err(ErrorCode::Busy);
        }
        let pieces = sample_pieces(dump.proof.piece_count(), CHALLENGE_PIECES)?;
        let challenge_id = random_id()?;
        let challenge = Challenge {
            challenge_id: challenge_id.clone(),
            piece_size: dump.proof.piece_size(),
            pieces: pieces.clone(),
        };
        inner
            .nonces
            .insert(t.nonce, (t.expires_at, challenge_id.clone()));
        inner.challenges.insert(
            challenge_id,
            Open {
                user_id: t.user_id,
                expires_at: now + CHALLENGE_TTL_SECS,
                pieces,
                dump,
            },
        );
        Ok(challenge)
    }

    /// Single use: removes the challenge whatever the outcome. Unknown ->
    /// `NotFound`; past expiry -> `ChallengeExpired`; a body that is not
    /// exactly the concatenated pieces -> `WrongFile`. `Ok` is the user id.
    pub fn prove(&self, challenge_id: &str, body: &[u8]) -> Result<i64, ErrorCode> {
        let open = self
            .lock()
            .challenges
            .remove(challenge_id)
            .ok_or(ErrorCode::NotFound)?;
        if self.clock.now_unix() >= open.expires_at {
            return Err(ErrorCode::ChallengeExpired);
        }
        let proof = &open.dump.proof;
        let mut rest = body;
        for &i in &open.pieces {
            let len = proof.piece_len(i).ok_or(ErrorCode::WrongFile)? as usize;
            if rest.len() < len {
                return Err(ErrorCode::WrongFile);
            }
            let (piece, tail) = rest.split_at(len);
            if !proof.matches(i, piece) {
                return Err(ErrorCode::WrongFile);
            }
            rest = tail;
        }
        if !rest.is_empty() {
            return Err(ErrorCode::WrongFile);
        }
        Ok(open.user_id)
    }

    /// Drops expired challenges and spent nonces past their ticket expiry;
    /// returns the challenges dropped unanswered.
    pub fn sweep(&self) -> usize {
        let now = self.clock.now_unix();
        let mut inner = self.lock();
        let before = inner.challenges.len();
        inner.challenges.retain(|_, c| c.expires_at > now);
        let dropped = before - inner.challenges.len();
        inner.nonces.retain(|_, (expires_at, _)| *expires_at > now);
        dropped
    }

    #[cfg(test)]
    fn counts(&self) -> (usize, usize) {
        let inner = self.lock();
        (inner.challenges.len(), inner.nonces.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::Clock;
    use crate::dump;
    use crate::known::KnownFile;
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::time::{Duration, Instant};
    use urban_definitions_wire::{sign_ticket, Ticket, TICKET_TTL_SECS};

    const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/mini.ndjson");
    const KEY: &[u8] = b"test-key";
    const T0: i64 = 1_000_000;

    struct FakeClock(AtomicI64);

    impl Clock for FakeClock {
        fn now_unix(&self) -> i64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    struct Rig {
        ch: Challenges,
        store: Arc<Definitions>,
        clock: Arc<FakeClock>,
    }

    fn publish(store: &Definitions) {
        let known = KnownFile {
            size: FIXTURE.len() as u64,
            sha256: Sha256::digest(FIXTURE).into(),
            chunk_size: FIXTURE.len() as u64,
            chunks: vec![<[u8; 32]>::from(Sha256::digest(FIXTURE))].into(),
        };
        let zst = zstd::encode_all(FIXTURE, 3).unwrap();
        let far = Instant::now() + Duration::from_secs(60);
        store.publish(dump::load(&zst[..], &known, 64, far).unwrap());
    }

    fn rig_empty() -> Rig {
        let store = Arc::new(Definitions::new());
        let clock = Arc::new(FakeClock(AtomicI64::new(T0)));
        let ch = Challenges::new(KEY.to_vec(), store.clone(), clock.clone());
        Rig { ch, store, clock }
    }

    fn rig() -> Rig {
        let r = rig_empty();
        publish(&r.store);
        r
    }

    fn ticket(r: &Rig, user_id: i64, nonce: &str) -> String {
        let expires_at = r.clock.now_unix() + TICKET_TTL_SECS;
        sign_ticket(
            KEY,
            &Ticket {
                user_id,
                nonce: nonce.into(),
                expires_at,
            },
        )
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

    #[test]
    fn a_challenge_names_32_distinct_sorted_pieces_in_range() {
        let r = rig();
        for n in 0..20 {
            let c = r.ch.issue(&ticket(&r, 1, &format!("n{n}"))).unwrap();
            assert_eq!(c.piece_size, 64);
            assert_eq!(c.pieces.len(), CHALLENGE_PIECES);
            assert!(c.pieces.windows(2).all(|w| w[0] < w[1]), "{:?}", c.pieces);
            assert!(c.pieces.iter().all(|&i| i < 135));
            assert_eq!(c.challenge_id.len(), 32);
        }
    }

    #[test]
    fn sampling_covers_a_small_file_and_stays_in_range() {
        assert_eq!(sample_pieces(4, 32).unwrap(), vec![0, 1, 2, 3]);
        assert_eq!(sample_pieces(0, 32).unwrap(), Vec::<u64>::new());
        let s = sample_pieces(33, 32).unwrap();
        assert_eq!(s.len(), 32);
        assert!(s.iter().all(|&i| i < 33));
    }

    #[test]
    fn rejection_sampling_stays_below_the_bound() {
        for bound in [1u64, 2, 3, 135, 468_219, u64::MAX / 2 + 1] {
            for _ in 0..50 {
                assert!(below(bound).unwrap() < bound);
            }
        }
    }

    #[test]
    fn loading_leaves_the_ticket_unspent() {
        let r = rig_empty();
        let t = ticket(&r, 1, "a");
        assert_eq!(r.ch.issue(&t).unwrap_err(), ErrorCode::Loading);
        publish(&r.store);
        assert!(r.ch.issue(&t).is_ok());
    }

    #[test]
    fn the_right_pieces_unlock_once() {
        let r = rig();
        let c = r.ch.issue(&ticket(&r, 42, "a")).unwrap();
        assert_eq!(r.ch.prove(&c.challenge_id, &body_for(&c)), Ok(42));
        assert_eq!(
            r.ch.prove(&c.challenge_id, &body_for(&c)),
            Err(ErrorCode::NotFound)
        );
    }

    #[test]
    fn one_wrong_piece_is_refused_and_spends_the_challenge() {
        let r = rig();
        let t = ticket(&r, 42, "a");
        let c = r.ch.issue(&t).unwrap();
        let mut body = body_for(&c);
        body[100] ^= 1;
        assert_eq!(
            r.ch.prove(&c.challenge_id, &body),
            Err(ErrorCode::WrongFile)
        );
        assert_eq!(
            r.ch.prove(&c.challenge_id, &body_for(&c)),
            Err(ErrorCode::NotFound)
        );
        assert_eq!(r.ch.issue(&t).unwrap_err(), ErrorCode::TicketUsed);
    }

    #[test]
    fn a_short_or_long_body_is_a_wrong_file() {
        let r = rig();
        for (n, edit) in [(0, 0), (1, 1), (2, 2)] {
            let c = r.ch.issue(&ticket(&r, 1, &format!("n{n}"))).unwrap();
            let mut body = body_for(&c);
            match edit {
                0 => {
                    body.pop();
                }
                1 => body.push(0),
                _ => body.clear(),
            }
            assert_eq!(
                r.ch.prove(&c.challenge_id, &body),
                Err(ErrorCode::WrongFile)
            );
        }
    }

    #[test]
    fn a_challenge_expires_after_two_minutes() {
        let r = rig();
        let c = r.ch.issue(&ticket(&r, 1, "a")).unwrap();
        r.clock
            .0
            .fetch_add(CHALLENGE_TTL_SECS + 1, Ordering::SeqCst);
        assert_eq!(
            r.ch.prove(&c.challenge_id, &body_for(&c)),
            Err(ErrorCode::ChallengeExpired)
        );
        assert_eq!(
            r.ch.prove(&c.challenge_id, &body_for(&c)),
            Err(ErrorCode::NotFound)
        );
    }

    #[test]
    fn the_same_ticket_gets_the_same_open_challenge() {
        let r = rig();
        let t = ticket(&r, 1, "a");
        let first = r.ch.issue(&t).unwrap();
        assert_eq!(r.ch.issue(&t).unwrap(), first);
        // Once it has expired, the ticket is spent.
        r.clock
            .0
            .fetch_add(CHALLENGE_TTL_SECS + 1, Ordering::SeqCst);
        assert_eq!(r.ch.issue(&t).unwrap_err(), ErrorCode::TicketUsed);
    }

    #[test]
    fn expired_and_used_tickets() {
        let r = rig();
        let old = ticket(&r, 1, "old");
        r.clock.0.fetch_add(TICKET_TTL_SECS + 1, Ordering::SeqCst);
        assert_eq!(r.ch.issue(&old).unwrap_err(), ErrorCode::TicketExpired);
        assert_eq!(r.ch.issue("garbage").unwrap_err(), ErrorCode::BadTicket);
        assert_eq!(
            r.ch.issue(&ticket(&r, 1, "")).unwrap_err(),
            ErrorCode::BadTicket
        );
        assert_eq!(
            r.ch.issue(&ticket(&r, 1, &"x".repeat(65))).unwrap_err(),
            ErrorCode::BadTicket
        );
        assert!(r.ch.issue(&ticket(&r, 1, &"x".repeat(64))).is_ok());
        let proved = ticket(&r, 2, "p");
        let c = r.ch.issue(&proved).unwrap();
        r.ch.prove(&c.challenge_id, &body_for(&c)).unwrap();
        assert_eq!(r.ch.issue(&proved).unwrap_err(), ErrorCode::TicketUsed);
    }

    #[test]
    fn open_challenges_are_capped() {
        let r = rig();
        for n in 0..MAX_OPEN_CHALLENGES {
            r.ch.issue(&ticket(&r, n as i64, &format!("n{n}"))).unwrap();
        }
        let extra = ticket(&r, 999, "extra");
        assert_eq!(r.ch.issue(&extra).unwrap_err(), ErrorCode::Busy);
        // A refused ticket is not spent: a slot freeing up lets it through.
        r.clock
            .0
            .fetch_add(CHALLENGE_TTL_SECS + 1, Ordering::SeqCst);
        assert!(r.ch.issue(&extra).is_ok());
    }

    #[test]
    fn sweep_drops_expired_challenges_and_spent_nonces() {
        let r = rig();
        r.ch.issue(&ticket(&r, 1, "a")).unwrap();
        let c = r.ch.issue(&ticket(&r, 2, "b")).unwrap();
        r.ch.prove(&c.challenge_id, &body_for(&c)).unwrap();
        assert_eq!(r.ch.sweep(), 0);
        assert_eq!(r.ch.counts(), (1, 2));
        r.clock
            .0
            .fetch_add(CHALLENGE_TTL_SECS + 1, Ordering::SeqCst);
        assert_eq!(r.ch.sweep(), 1);
        assert_eq!(r.ch.counts(), (0, 2));
        r.clock.0.fetch_add(TICKET_TTL_SECS, Ordering::SeqCst);
        assert_eq!(r.ch.sweep(), 0);
        assert_eq!(r.ch.counts(), (0, 0));
    }
}
