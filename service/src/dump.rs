//! The verified load of a dump stream.
//!
//! A zstd stream is decoded and checked as it is read: every chunk against the
//! compiled-in table before it is parsed, the whole file against its SHA-256
//! before anything is returned. Every small piece's hash is recorded as the
//! proof table, used for the spot-check challenge. Nothing touches disk and
//! definition text is never logged.

use std::io::{self, Read};
use std::time::Instant;

use sha2::{Digest, Sha256};

use crate::index::{feed_lines, Index, IndexBuilder};
use crate::known::KnownFile;

/// Size of the pieces the proof table hashes.
pub const PROOF_PIECE_SIZE: u64 = 4096;
/// One whole load may take at most this long.
pub const MAX_LOAD_SECS: u64 = 1800;

/// SHA-256 of every `piece_size` piece of the file; the last may be shorter.
pub struct ProofTable {
    piece_size: u64,
    size: u64,
    hashes: Box<[[u8; 32]]>,
}

impl ProofTable {
    pub fn piece_size(&self) -> u64 {
        self.piece_size
    }

    pub fn piece_count(&self) -> u64 {
        self.hashes.len() as u64
    }

    /// Length of piece `i`: `piece_size`, or the short last piece; `None` past the end.
    pub fn piece_len(&self, i: u64) -> Option<u64> {
        if i >= self.piece_count() {
            return None;
        }
        Some(self.piece_size.min(self.size - i * self.piece_size))
    }

    /// Whether `bytes` is exactly piece `i`. False if `i` is out of range or
    /// `bytes` is not exactly `piece_len(i)` long.
    pub fn matches(&self, i: u64, bytes: &[u8]) -> bool {
        let Some(len) = self.piece_len(i) else {
            return false;
        };
        bytes.len() as u64 == len
            && <[u8; 32]>::from(Sha256::digest(bytes)) == self.hashes[i as usize]
    }
}

pub struct Dump {
    pub index: Index,
    pub proof: ProofTable,
}

#[derive(Debug)]
pub enum LoadError {
    Source(io::Error),
    WrongFile,
    TimedOut,
}

impl LoadError {
    pub fn label(&self) -> &'static str {
        match self {
            LoadError::Source(_) => "source_error",
            LoadError::WrongFile => "wrong_file",
            LoadError::TimedOut => "timed_out",
        }
    }
}

/// Accumulates the proof table piece by piece.
struct ProofBuilder {
    piece_size: u64,
    size: u64,
    hasher: Sha256,
    filled: u64,
    hashes: Vec<[u8; 32]>,
}

impl ProofBuilder {
    fn new(piece_size: u64) -> Self {
        Self {
            piece_size,
            size: 0,
            hasher: Sha256::new(),
            filled: 0,
            hashes: Vec::new(),
        }
    }

    fn update(&mut self, mut bytes: &[u8]) {
        self.size += bytes.len() as u64;
        while !bytes.is_empty() {
            let take = ((self.piece_size - self.filled) as usize).min(bytes.len());
            self.hasher.update(&bytes[..take]);
            self.filled += take as u64;
            bytes = &bytes[take..];
            if self.filled == self.piece_size {
                self.cut();
            }
        }
    }

    fn cut(&mut self) {
        self.hashes
            .push(std::mem::take(&mut self.hasher).finalize().into());
        self.filled = 0;
    }

    fn finish(mut self) -> ProofTable {
        if self.filled > 0 {
            self.cut();
        }
        ProofTable {
            piece_size: self.piece_size,
            size: self.size,
            hashes: self.hashes.into_boxed_slice(),
        }
    }
}

/// Reads until `buf` is full or the stream ends; returns how many bytes it got.
/// The deadline is checked before every read.
fn fill(r: &mut impl Read, buf: &mut [u8], deadline: Instant) -> Result<usize, LoadError> {
    let mut got = 0;
    while got < buf.len() {
        if Instant::now() > deadline {
            return Err(LoadError::TimedOut);
        }
        match r.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == io::ErrorKind::TimedOut => return Err(LoadError::TimedOut),
            Err(e) => return Err(LoadError::Source(e)),
        }
    }
    Ok(got)
}

/// Decodes zstd from `compressed` and verifies as it reads:
/// - each `known.chunk_size` piece is checked against `known.chunks` BEFORE it is parsed;
/// - the whole-file SHA-256 is checked before returning;
/// - every `proof_piece_size` piece's SHA-256 goes into the proof table.
///
/// Fails `TimedOut` once `Instant::now() > deadline` (checked between reads).
pub fn load(
    compressed: impl Read,
    known: &KnownFile,
    proof_piece_size: u64,
    deadline: Instant,
) -> Result<Dump, LoadError> {
    assert!(proof_piece_size > 0 && known.chunk_size > 0);
    let mut decoder = zstd::stream::read::Decoder::new(compressed).map_err(LoadError::Source)?;
    let mut buf = vec![0u8; known.chunk_size.min(known.size) as usize];
    let mut whole = Sha256::new();
    let mut proof = ProofBuilder::new(proof_piece_size);
    let mut builder = IndexBuilder::new();
    let mut carry: Vec<u8> = Vec::new();
    let mut received: u64 = 0;

    while received < known.size {
        let want = known.chunk_size.min(known.size - received) as usize;
        let piece = &mut buf[..want];
        if fill(&mut decoder, piece, deadline)? != want {
            return Err(LoadError::WrongFile); // the stream ended early
        }
        let slot = (received / known.chunk_size) as usize;
        match known.chunks.get(slot) {
            Some(h) if <[u8; 32]>::from(Sha256::digest(&*piece)) == *h => {}
            _ => return Err(LoadError::WrongFile),
        }
        whole.update(&*piece);
        proof.update(piece);
        feed_lines(&mut builder, &mut carry, piece).map_err(|()| LoadError::WrongFile)?;
        received += want as u64;
    }

    // Anything after the expected end is not the file.
    let mut probe = [0u8; 1];
    if fill(&mut decoder, &mut probe, deadline)? != 0 {
        return Err(LoadError::WrongFile);
    }
    let digest: [u8; 32] = whole.finalize().into();
    if digest != known.sha256 {
        return Err(LoadError::WrongFile);
    }
    if !carry.is_empty() {
        builder
            .push_line(&carry)
            .map_err(|_| LoadError::WrongFile)?;
    }
    Ok(Dump {
        index: builder.finish(),
        proof: proof.finish(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::MAX_LINE_BYTES;
    use std::time::Duration;

    const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/mini.ndjson");

    fn known_for(bytes: &[u8], chunk_size: usize) -> KnownFile {
        KnownFile {
            size: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
            chunk_size: chunk_size as u64,
            chunks: bytes
                .chunks(chunk_size)
                .map(|c| <[u8; 32]>::from(Sha256::digest(c)))
                .collect(),
        }
    }

    fn zst(bytes: &[u8]) -> Vec<u8> {
        zstd::encode_all(bytes, 3).unwrap()
    }

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    fn built(bytes: &[u8]) -> Index {
        let mut b = IndexBuilder::new();
        for l in bytes.split(|&c| c == b'\n') {
            b.push_line(l).unwrap();
        }
        b.finish()
    }

    #[test]
    fn loads_a_verified_stream() {
        let d = load(&zst(FIXTURE)[..], &known_for(FIXTURE, 10), 64, far()).unwrap();
        let whole = built(FIXTURE);
        assert_eq!(d.index.entries(), whole.entries());
        assert_eq!(d.index.lookup("JANKY", false), whole.lookup("JANKY", false));
        assert_eq!(d.proof.piece_size(), 64);
        assert_eq!(d.proof.piece_count(), 135);
        assert_eq!(d.proof.piece_len(134), Some(8610 - 134 * 64));
        assert_eq!(d.proof.piece_len(135), None);
        for i in 0..135u64 {
            let start = (i * 64) as usize;
            let end = ((i as usize + 1) * 64).min(FIXTURE.len());
            assert!(d.proof.matches(i, &FIXTURE[start..end]), "{i}");
            assert!(!d.proof.matches(i, &FIXTURE[start..end - 1]), "short {i}");
            if end < FIXTURE.len() {
                assert!(!d.proof.matches(i, &FIXTURE[start..end + 1]), "long {i}");
            }
        }
        let mut longer = FIXTURE[134 * 64..].to_vec();
        longer.push(0);
        assert!(!d.proof.matches(134, &longer));
        assert!(!d.proof.matches(0, &FIXTURE[1..]));
        assert!(!d.proof.matches(135, FIXTURE));
    }

    #[test]
    fn a_tampered_stream_never_reaches_the_index() {
        let mut bad = FIXTURE.to_vec();
        let at = bad.iter().position(|&c| c == b'J').unwrap();
        bad[at] = b'K'; // still valid JSON, different hash
        let r = load(&zst(&bad)[..], &known_for(FIXTURE, 10), 64, far());
        assert!(matches!(r, Err(LoadError::WrongFile)));
    }

    #[test]
    fn extra_bytes_after_the_file_are_refused() {
        let mut more = FIXTURE.to_vec();
        more.extend_from_slice(b"{}\n");
        let r = load(&zst(&more)[..], &known_for(FIXTURE, 10), 64, far());
        assert!(matches!(r, Err(LoadError::WrongFile)));
    }

    #[test]
    fn a_short_stream_is_refused() {
        let r = load(
            &zst(&FIXTURE[..8000])[..],
            &known_for(FIXTURE, 10),
            64,
            far(),
        );
        assert!(matches!(r, Err(LoadError::WrongFile)));
    }

    #[test]
    fn garbled_zstd_is_a_source_error() {
        let mut z = zst(FIXTURE);
        z[20] ^= 0x01;
        let r = load(&z[..], &known_for(FIXTURE, 10), 64, far());
        assert!(matches!(r, Err(LoadError::Source(_))));
    }

    #[test]
    fn a_bad_frame_header_is_a_source_error() {
        let mut z = zst(FIXTURE);
        z[0] ^= 0xff;
        let r = load(&z[..], &known_for(FIXTURE, 10), 64, far());
        assert!(matches!(r, Err(LoadError::Source(_))));
    }

    #[test]
    fn the_whole_file_hash_still_gates() {
        let mut known = known_for(FIXTURE, 10);
        known.sha256 = [0u8; 32];
        let r = load(&zst(FIXTURE)[..], &known, 64, far());
        assert!(matches!(r, Err(LoadError::WrongFile)));
    }

    #[test]
    fn a_past_deadline_times_out() {
        let past = Instant::now() - Duration::from_secs(1);
        let r = load(&zst(FIXTURE)[..], &known_for(FIXTURE, 10), 64, past);
        assert!(matches!(r, Err(LoadError::TimedOut)));
    }

    #[test]
    fn labels_are_stable() {
        assert_eq!(LoadError::WrongFile.label(), "wrong_file");
        assert_eq!(LoadError::TimedOut.label(), "timed_out");
        assert_eq!(
            LoadError::Source(io::Error::other("x")).label(),
            "source_error"
        );
    }

    #[test]
    fn chunk_sizes_that_do_not_divide_the_proof_piece_agree() {
        let tables: Vec<ProofTable> = [1usize, 3, 100, FIXTURE.len()]
            .into_iter()
            .map(|cs| {
                load(&zst(FIXTURE)[..], &known_for(FIXTURE, cs), 64, far())
                    .unwrap()
                    .proof
            })
            .collect();
        for t in &tables[1..] {
            assert_eq!(t.piece_count(), tables[0].piece_count());
            assert_eq!(t.hashes, tables[0].hashes);
        }
    }

    #[test]
    fn multibyte_characters_split_across_chunks_parse_whole() {
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
            let d = load(&zst(&bytes)[..], &known_for(&bytes, step), 64, far()).unwrap();
            let defs = d.index.lookup("PLAIN", false);
            assert_eq!(&*defs[0], "plain");
            assert_eq!(d.index.entries(), 2, "step {step}");
        }
    }

    #[test]
    fn final_line_without_trailing_newline_is_flushed() {
        let mut bytes = FIXTURE.to_vec();
        while bytes.last() == Some(&b'\n') {
            bytes.pop();
        }
        let d = load(&zst(&bytes)[..], &known_for(&bytes, 5), 64, far()).unwrap();
        assert_eq!(d.index.entries(), built(&bytes).entries());
    }

    #[test]
    fn endless_line_aborts_as_wrong_file() {
        let bytes = vec![b'a'; MAX_LINE_BYTES + 10];
        let r = load(&zst(&bytes)[..], &known_for(&bytes, 100_000), 64, far());
        assert!(matches!(r, Err(LoadError::WrongFile)));
    }

    #[test]
    fn garbage_line_aborts_as_wrong_file() {
        let bytes = b"not json at all\n{}\n".to_vec();
        let r = load(&zst(&bytes)[..], &known_for(&bytes, bytes.len()), 64, far());
        assert!(matches!(r, Err(LoadError::WrongFile)));
    }

    #[test]
    fn a_crafted_valid_chunk_is_refused_at_that_chunk() {
        let crafted = b"{\"word\":\"EVIL\",\"definition\":\"x\"}\n";
        // Right total size, valid JSON in the first chunk, wrong hash for it.
        let mut stream = crafted.to_vec();
        stream.extend_from_slice(&FIXTURE[crafted.len()..]);
        let r = load(
            &zst(&stream)[..],
            &known_for(FIXTURE, crafted.len()),
            64,
            far(),
        );
        assert!(matches!(r, Err(LoadError::WrongFile)));
    }
}
