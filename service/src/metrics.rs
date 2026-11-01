//! Metric names and the small helpers that touch them.

pub const LOOKUP_RESULTS: [&str; 3] = ["hit", "miss", "empty"];

/// Registers every series at zero so a dashboard sees them before first use.
pub fn init() {
    for result in LOOKUP_RESULTS {
        metrics::counter!("urban_definitions_lookups_total", "result" => result).increment(0);
    }
    metrics::gauge!("urban_definitions_loaded").set(0.0);
    metrics::gauge!("urban_definitions_entries").set(0.0);
    metrics::gauge!("urban_definitions_resident_bytes").set(0.0);
}

/// Linux page size; `/proc/self/statm` counts pages.
const PAGE_BYTES: u64 = 4096;

/// Resident bytes from the text of `/proc/self/statm` (second field, in
/// pages); 0 when it cannot be parsed.
pub fn parse_statm(statm: &str) -> u64 {
    statm
        .split_whitespace()
        .nth(1)
        .and_then(|p| p.parse::<u64>().ok())
        .map_or(0, |pages| pages * PAGE_BYTES)
}

/// Publishes the process's resident memory (0 if unreadable).
pub fn record_resident() {
    let bytes = std::fs::read_to_string("/proc/self/statm")
        .map(|t| parse_statm(&t))
        .unwrap_or(0);
    metrics::gauge!("urban_definitions_resident_bytes").set(bytes as f64);
}

pub fn lookup(result: &'static str) {
    metrics::counter!("urban_definitions_lookups_total", "result" => result).increment(1);
}

pub fn set_loaded(entries: Option<usize>) {
    metrics::gauge!("urban_definitions_loaded").set(if entries.is_some() { 1.0 } else { 0.0 });
    metrics::gauge!("urban_definitions_entries").set(entries.unwrap_or(0) as f64);
}

#[cfg(test)]
mod tests {
    use super::parse_statm;

    #[test]
    fn statm_resident_is_the_second_field_in_pages() {
        assert_eq!(parse_statm("5000 250 100 10 0 400 0\n"), 250 * 4096);
    }

    #[test]
    fn unreadable_statm_is_zero() {
        assert_eq!(parse_statm(""), 0);
        assert_eq!(parse_statm("5000"), 0);
        assert_eq!(parse_statm("5000 abc"), 0);
    }
}
