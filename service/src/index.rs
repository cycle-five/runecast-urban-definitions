//! In-memory index of Urban Dictionary definitions, built from the NDJSON dump.
//!
//! Nothing here touches disk, and definition text is never logged.

use std::collections::HashMap;

use serde::Deserialize;

/// A dump line longer than this is not the dump.
pub const MAX_LINE_BYTES: usize = 256 * 1024;
/// Definitions kept per key and kind.
const KEEP: usize = 3;
/// Cleaned text is capped at this many characters, then `…` is appended.
const MAX_TEXT_CHARS: usize = 500;
/// Keys outside this letter count can never be played (both dictionaries are
/// 2..=15 letters), so the index does not store them.
const MIN_KEY_LEN: usize = 2;
const MAX_KEY_LEN: usize = 15;
/// A run of this many equal letters is collapsed.
const RUN: usize = 4;
/// A run is capped at this many letters when collapsed.
const RUN_CAP: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Exact,
    Collapsed,
    Glued,
}

impl KeyKind {
    const ALL: [KeyKind; 3] = [KeyKind::Exact, KeyKind::Collapsed, KeyKind::Glued];

    fn tier(self) -> usize {
        match self {
            KeyKind::Exact => 0,
            KeyKind::Collapsed => 1,
            KeyKind::Glued => 2,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    NotJson,
    LineTooLong,
}

/// The subset of a dump line we keep; unknown fields are ignored.
#[derive(Deserialize)]
struct DumpLine {
    word: String,
    definition: String,
    #[serde(default)]
    thumbs_up: i64,
    #[serde(default)]
    thumbs_down: i64,
}

fn collapse_runs(letters: &str) -> String {
    let mut out = String::with_capacity(letters.len());
    let mut prev = None;
    let mut run = 0;
    for c in letters.chars() {
        run = if prev == Some(c) { run + 1 } else { 1 };
        prev = Some(c);
        if run <= RUN_CAP {
            out.push(c);
        }
    }
    out
}

fn has_run(letters: &str) -> bool {
    let mut prev = None;
    let mut run = 0;
    for c in letters.chars() {
        run = if prev == Some(c) { run + 1 } else { 1 };
        prev = Some(c);
        if run >= RUN {
            return true;
        }
    }
    false
}

/// The keys an entry's word is stored under. Letters are ASCII A-Z; every
/// other character (spaces, punctuation, digits, non-ASCII) is dropped and
/// makes the word "glued".
pub fn word_keys(raw: &str) -> Vec<(String, KeyKind)> {
    let letters: String = raw
        .chars()
        .filter(char::is_ascii_alphabetic)
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if letters.is_empty() {
        return Vec::new();
    }
    let letters_only = raw.chars().all(|c| c.is_ascii_alphabetic());
    let (base, collapsed) = if letters_only {
        (KeyKind::Exact, KeyKind::Collapsed)
    } else {
        (KeyKind::Glued, KeyKind::Glued)
    };
    let mut keys = Vec::with_capacity(2);
    if has_run(&letters) {
        let short = collapse_runs(&letters);
        keys.push((letters, base));
        keys.push((short, collapsed));
    } else {
        keys.push((letters, base));
    }
    keys
}

/// Remove `[` and `]`, collapse whitespace runs to one space, trim, then cap.
pub fn clean_text(raw: &str) -> String {
    let stripped: String = raw.chars().filter(|&c| c != '[' && c != ']').collect();
    let joined = stripped.split_whitespace().collect::<Vec<_>>().join(" ");
    match joined.char_indices().nth(MAX_TEXT_CHARS) {
        Some((cut, _)) => {
            let mut out = String::with_capacity(cut + '…'.len_utf8());
            out.push_str(joined[..cut].trim_end());
            out.push('…');
            out
        }
        None => joined,
    }
}

/// One candidate definition: score, thumbs up, text.
type Scored = (i64, i64, Box<str>);

#[derive(Default)]
struct Slots {
    tiers: [Vec<Scored>; 3],
}

#[derive(Default)]
pub struct IndexBuilder {
    keys: HashMap<String, Slots>,
}

impl IndexBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse one dump line and fold it into the index. A blank line is skipped.
    pub fn push_line(&mut self, line: &[u8]) -> Result<(), ParseError> {
        if line.len() > MAX_LINE_BYTES {
            return Err(ParseError::LineTooLong);
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            return Ok(());
        }
        let parsed: DumpLine = serde_json::from_slice(line).map_err(|_| ParseError::NotJson)?;
        let mut keys = word_keys(&parsed.word);
        keys.retain(|(k, _)| (MIN_KEY_LEN..=MAX_KEY_LEN).contains(&k.len()));
        if keys.is_empty() {
            return Ok(());
        }
        let text = clean_text(&parsed.definition);
        if text.is_empty() {
            return Ok(());
        }
        let score = parsed.thumbs_up.saturating_sub(parsed.thumbs_down);
        let text: Box<str> = text.into_boxed_str();
        for (key, kind) in keys {
            let slot = &mut self.keys.entry(key).or_default().tiers[kind.tier()];
            slot.push((score, parsed.thumbs_up, text.clone()));
            // Stable sort: ties on both score and thumbs_up keep dump order.
            slot.sort_by_key(|a| std::cmp::Reverse((a.0, a.1)));
            slot.truncate(KEEP);
        }
        Ok(())
    }

    /// Compact the builder: one flat boxed slice per key, no spare capacity.
    pub fn finish(self) -> Index {
        let mut keys = HashMap::with_capacity(self.keys.len());
        let mut entries = 0;
        for (key, slots) in self.keys {
            let mut counts = [0u8; 3];
            let mut flat: Vec<Box<str>> = Vec::new();
            for (i, tier) in slots.tiers.into_iter().enumerate() {
                counts[i] = tier.len() as u8;
                flat.extend(tier.into_iter().map(|(_, _, text)| text));
            }
            entries += flat.len();
            keys.insert(
                key.into_boxed_str(),
                Row {
                    counts,
                    entries: flat.into_boxed_slice(),
                },
            );
        }
        keys.shrink_to_fit();
        Index { keys, entries }
    }
}

struct Row {
    /// How many entries of each tier, in `KeyKind` order, at the front of `entries`.
    counts: [u8; 3],
    entries: Box<[Box<str>]>,
}

pub struct Index {
    keys: HashMap<Box<str>, Row>,
    entries: usize,
}

impl Index {
    /// The best tier present for `word` (already uppercase ASCII letters):
    /// exact, else collapsed, else glued (only when `allow_glued`).
    pub fn lookup(&self, word: &str, allow_glued: bool) -> &[Box<str>] {
        let Some(row) = self.keys.get(word) else {
            return &[];
        };
        let mut start = 0;
        for kind in KeyKind::ALL {
            let n = row.counts[kind.tier()] as usize;
            if n > 0 && (kind != KeyKind::Glued || allow_glued) {
                return &row.entries[start..start + n];
            }
            start += n;
        }
        &[]
    }

    /// Total definitions stored.
    pub fn entries(&self) -> usize {
        self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINI: &str = include_str!("../tests/fixtures/mini.ndjson");

    fn mini() -> Index {
        let mut b = IndexBuilder::new();
        for line in MINI.lines() {
            b.push_line(line.as_bytes()).unwrap();
        }
        b.finish()
    }

    fn strs(s: &[Box<str>]) -> Vec<&str> {
        s.iter().map(|b| &**b).collect()
    }

    #[test]
    fn keys_exact() {
        assert_eq!(word_keys("Janky"), [("JANKY".to_string(), KeyKind::Exact)]);
    }

    #[test]
    fn keys_long_run_adds_collapsed() {
        assert_eq!(
            word_keys("sheeeeet"),
            [
                ("SHEEEEET".to_string(), KeyKind::Exact),
                ("SHEEET".to_string(), KeyKind::Collapsed)
            ]
        );
    }

    #[test]
    fn keys_glued_phrase_and_punctuation() {
        assert_eq!(
            word_keys("in sane"),
            [("INSANE".to_string(), KeyKind::Glued)]
        );
        assert_eq!(
            word_keys("ice-cream!!"),
            [("ICECREAM".to_string(), KeyKind::Glued)]
        );
    }

    #[test]
    fn keys_glued_with_run_is_also_collapsed_but_stays_glued() {
        assert_eq!(
            word_keys("so oooh"),
            [
                ("SOOOOH".to_string(), KeyKind::Glued),
                ("SOOOH".to_string(), KeyKind::Glued)
            ]
        );
    }

    #[test]
    fn keys_digits_and_non_ascii_dropped_no_letters_empty() {
        assert_eq!(word_keys("a1b"), [("AB".to_string(), KeyKind::Glued)]);
        assert!(word_keys("¯\\_(ツ)_/¯").is_empty());
        assert!(word_keys("").is_empty());
    }

    #[test]
    fn clean_collapses_whitespace_and_brackets() {
        assert_eq!(clean_text("a [link]  here\r\n\r\nnext"), "a link here next");
    }

    #[test]
    fn clean_caps_at_500_plus_ellipsis() {
        let out = clean_text(&"x".repeat(600));
        assert_eq!(out.chars().count(), 501);
        assert!(out.ends_with('…'));
        assert_eq!(clean_text(&"x".repeat(500)), "x".repeat(500));
    }

    #[test]
    fn clean_trims_whitespace_before_the_ellipsis() {
        // The 500-character cut lands right after a space.
        let raw = format!("{} {}", "x".repeat(499), "y".repeat(50));
        let out = clean_text(&raw);
        assert_eq!(out, format!("{}…", "x".repeat(499)));
    }

    fn one_line(word: &str) -> Index {
        let mut b = IndexBuilder::new();
        let line = format!(r#"{{"word":"{word}","definition":"d","thumbs_up":1,"thumbs_down":0}}"#);
        b.push_line(line.as_bytes()).unwrap();
        b.finish()
    }

    #[test]
    fn keys_that_can_never_be_played_are_not_indexed() {
        assert_eq!(one_line("a").entries(), 0);
        assert_eq!(one_line("abcdefghijklmnop").entries(), 0, "16 letters");
        assert_eq!(
            one_line("ice cream sandwich shop").entries(),
            0,
            "long glued phrase"
        );
        assert_eq!(one_line("ab").entries(), 1);
        assert_eq!(one_line("abcdefghijklmno").entries(), 1, "15 letters");
    }

    #[test]
    fn a_collapsed_key_can_survive_when_the_exact_one_is_too_long() {
        // 16 letters, collapses to 14: only the playable key is stored.
        let idx = one_line("aaaaaaaabcdefghi");
        assert_eq!(idx.entries(), 1);
        assert!(!idx.lookup("AAABCDEFGHI", false).is_empty());
    }

    #[test]
    fn lookup_keeps_three_best_in_score_order() {
        let idx = mini();
        assert_eq!(
            strs(idx.lookup("JANKY", false)),
            [
                "Fourth janky, highest score.",
                "Second best janky.",
                "Undesirable; less-than optimum."
            ]
        );
    }

    #[test]
    fn lookup_five_entries_keeps_three() {
        let idx = mini();
        assert_eq!(
            strs(idx.lookup("TINY", false)),
            ["tiny def 4", "tiny def 2", "tiny def 1"]
        );
    }

    #[test]
    fn lookup_ties_broken_by_thumbs_up() {
        let idx = mini();
        assert_eq!(
            strs(idx.lookup("TIE", false)),
            ["Tie more ups.", "Tie first.", "Tie lowest."]
        );
    }

    #[test]
    fn lookup_negative_only_entry_still_returned() {
        let idx = mini();
        assert_eq!(
            strs(idx.lookup("GLOOMY", false)),
            ["Only this, and it is hated."]
        );
    }

    #[test]
    fn lookup_exact_ignores_glued_unless_allowed() {
        let idx = mini();
        assert_eq!(strs(idx.lookup("INSANE", false)), ["Exact insane: crazy."]);
        assert_eq!(strs(idx.lookup("INSANE", true)), ["Exact insane: crazy."]);
    }

    #[test]
    fn lookup_glued_only_needs_allow_glued() {
        let idx = mini();
        assert!(idx.lookup("ICECREAM", false).is_empty());
        assert_eq!(
            strs(idx.lookup("ICECREAM", true)),
            ["Frozen dessert with cream. Yum.", "Punctuated ice cream."]
        );
    }

    #[test]
    fn lookup_collapsed_found_and_exact_beats_collapsed() {
        let idx = mini();
        assert_eq!(strs(idx.lookup("NOOOPE", false)), ["Collapsed nope."]);
        assert_eq!(strs(idx.lookup("SHEEET", false)), ["Exact sheeet."]);
        assert_eq!(
            strs(idx.lookup("SHEEEEET", false)),
            ["Collapsed sheeet, longer."]
        );
    }

    #[test]
    fn lookup_unknown_is_empty_and_text_is_cleaned() {
        let idx = mini();
        assert!(idx.lookup("NOPE", true).is_empty());
        assert_eq!(strs(idx.lookup("LINKY", false)), ["a link here next"]);
        assert_eq!(idx.lookup("LONG", false)[0].chars().count(), 501);
    }

    #[test]
    fn entries_counts_stored_definitions() {
        let idx = mini();
        assert!(idx.entries() > 10);
    }

    #[test]
    fn push_line_rejects_bad_input() {
        let mut b = IndexBuilder::new();
        assert_eq!(b.push_line(b"not json"), Err(ParseError::NotJson));
        let long = vec![b'a'; MAX_LINE_BYTES + 1];
        assert_eq!(b.push_line(&long), Err(ParseError::LineTooLong));
        assert_eq!(b.push_line(b""), Ok(()));
    }
}
