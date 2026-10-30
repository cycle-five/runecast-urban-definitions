//! The dump files the service accepts, compiled in. No env override.
//!
//! Each known file carries the SHA-256 of every `chunk_size` piece, so an
//! upload is verified chunk by chunk and unverified bytes are never parsed.

use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownFile {
    pub size: u64,
    /// SHA-256 of the whole file (defence in depth next to the chunk table).
    pub sha256: [u8; 32],
    /// Every piece but the last is exactly this long.
    pub chunk_size: u64,
    /// SHA-256 of each `chunk_size` piece, in order; the last piece may be shorter.
    pub chunks: Arc<[[u8; 32]]>,
}

pub const PRODUCTION_CHUNK_SIZE: u64 = 8_388_608;

const PRODUCTION_CHUNKS: &str = include_str!("known-chunks-33ac6e88.txt");

fn hex_digit(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!("compiled-in chunk table holds a non-hex character"),
    }
}

/// Parses one 64-hex-character hash per line; blank lines and `#` comments
/// are skipped. The table is compiled in, so malformed data panics.
pub fn parse_chunk_table(text: &str) -> Vec<[u8; 32]> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let raw = l.as_bytes();
            assert_eq!(raw.len(), 64, "chunk hash must be 64 hex characters");
            let mut out = [0u8; 32];
            for (i, pair) in raw.chunks(2).enumerate() {
                out[i] = hex_digit(pair[0]) << 4 | hex_digit(pair[1]);
            }
            out
        })
        .collect()
}

/// SHA-256 33ac6e88fc91cf6ca80bf1ad6431f1700bca25f3702f6b46cdef17b53b349aa6
pub fn known_files() -> Vec<KnownFile> {
    vec![KnownFile {
        size: 1_917_822_288,
        sha256: [
            0x33, 0xac, 0x6e, 0x88, 0xfc, 0x91, 0xcf, 0x6c, 0xa8, 0x0b, 0xf1, 0xad, 0x64, 0x31,
            0xf1, 0x70, 0x0b, 0xca, 0x25, 0xf3, 0x70, 0x2f, 0x6b, 0x46, 0xcd, 0xef, 0x17, 0xb5,
            0x3b, 0x34, 0x9a, 0xa6,
        ],
        chunk_size: PRODUCTION_CHUNK_SIZE,
        chunks: parse_chunk_table(PRODUCTION_CHUNKS).into(),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_table_has_229_well_formed_hashes() {
        let lines: Vec<&str> = PRODUCTION_CHUNKS
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        assert_eq!(lines.len(), 229);
        for l in &lines {
            assert_eq!(l.len(), 64, "{l}");
            assert!(l.bytes().all(|b| b.is_ascii_hexdigit()), "{l}");
        }
    }

    #[test]
    fn production_table_matches_the_file_size() {
        let k = &known_files()[0];
        assert_eq!(k.chunks.len() as u64, k.size.div_ceil(k.chunk_size));
    }

    #[test]
    fn parse_decodes_hex() {
        let t = parse_chunk_table(&format!("# c\n{}ff\n", "00".repeat(31)));
        assert_eq!(t.len(), 1);
        assert_eq!(t[0][31], 0xff);
        assert_eq!(t[0][0], 0);
    }
}
