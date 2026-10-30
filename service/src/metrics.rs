//! Metric names and the small helpers that touch them.

use urban_definitions_wire::ErrorCode;

pub const UPLOAD_OUTCOMES: [&str; 9] = [
    "wrong_size",
    "bad_ticket",
    "busy",
    "too_many",
    "wrong_file",
    "loaded",
    "unlocked",
    "unlock_failed",
    "abandoned",
];
pub const LOOKUP_RESULTS: [&str; 3] = ["hit", "miss", "empty"];

/// Registers every series at zero so a dashboard sees them before first use.
pub fn init() {
    for outcome in UPLOAD_OUTCOMES {
        metrics::counter!("urban_definitions_uploads_total", "outcome" => outcome).increment(0);
    }
    for result in LOOKUP_RESULTS {
        metrics::counter!("urban_definitions_lookups_total", "result" => result).increment(0);
    }
    metrics::gauge!("urban_definitions_loaded").set(0.0);
    metrics::gauge!("urban_definitions_entries").set(0.0);
}

pub fn upload(outcome: &'static str) {
    metrics::counter!("urban_definitions_uploads_total", "outcome" => outcome).increment(1);
}

pub fn lookup(result: &'static str) {
    metrics::counter!("urban_definitions_lookups_total", "result" => result).increment(1);
}

pub fn set_loaded(entries: Option<usize>) {
    metrics::gauge!("urban_definitions_loaded").set(if entries.is_some() { 1.0 } else { 0.0 });
    metrics::gauge!("urban_definitions_entries").set(entries.unwrap_or(0) as f64);
}

/// The outcome label for a refused upload step; `None` for errors that are
/// not an upload outcome (not found, bad offset, ...).
pub fn refusal_label(code: ErrorCode) -> Option<&'static str> {
    match code {
        ErrorCode::WrongSize => Some("wrong_size"),
        ErrorCode::BadTicket | ErrorCode::TicketExpired | ErrorCode::TicketUsed => {
            Some("bad_ticket")
        }
        ErrorCode::Busy => Some("busy"),
        ErrorCode::TooManyUploads => Some("too_many"),
        ErrorCode::WrongFile => Some("wrong_file"),
        _ => None,
    }
}
