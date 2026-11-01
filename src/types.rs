//! Typed request/response bodies for the service's HTTP API.

use serde::{Deserialize, Serialize};

/// Serde helper: an `i64` snowflake carried as a JSON string.
pub mod string_i64 {
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &i64, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(v)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<i64, D::Error> {
        String::deserialize(d)?.parse().map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LookupResponse {
    /// An empty `definitions` list means no entry for that word.
    Loaded {
        definitions: Vec<String>,
    },
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnlockRequest {
    #[serde(with = "string_i64")]
    pub user_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartUpload {
    pub ticket: String,
    pub size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UploadMode {
    Load,
    Prove,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartedUpload {
    pub upload_id: String,
    pub chunk_size: u64,
    pub mode: UploadMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadProgress {
    pub received: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UploadOutcome {
    /// Loaded and unlocked.
    Loaded,
    Unlocked,
    UnlockFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ChunkResponse {
    Progress(UploadProgress),
    Finished { outcome: UploadOutcome },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeRequest {
    pub ticket: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    pub challenge_id: String,
    pub piece_size: u64,
    pub pieces: Vec<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofOutcome {
    Unlocked,
    UnlockFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofResponse {
    pub outcome: ProofOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    WrongSize,
    BadTicket,
    TicketExpired,
    TicketUsed,
    Busy,
    TooManyUploads,
    NotFound,
    WrongOffset,
    ChunkTooLarge,
    WrongFile,
    Unavailable,
    Loading,
    ChallengeExpired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiError {
    pub error: ErrorCode,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check<T>(value: &T, json: &str)
    where
        T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        assert_eq!(serde_json::to_string(value).unwrap(), json);
        assert_eq!(&serde_json::from_str::<T>(json).unwrap(), value);
    }

    #[test]
    fn lookup_response() {
        check(&LookupResponse::Empty, r#"{"status":"empty"}"#);
        check(
            &LookupResponse::Loaded {
                definitions: vec!["a".into(), "b".into()],
            },
            r#"{"status":"loaded","definitions":["a","b"]}"#,
        );
    }

    #[test]
    fn unlock_request_user_id_is_string() {
        check(
            &UnlockRequest {
                user_id: 1098406821124911175,
            },
            r#"{"user_id":"1098406821124911175"}"#,
        );
    }

    #[test]
    fn start_upload() {
        check(
            &StartUpload {
                ticket: "t".into(),
                size: 5,
            },
            r#"{"ticket":"t","size":5}"#,
        );
    }

    #[test]
    fn started_upload_and_mode() {
        check(
            &StartedUpload {
                upload_id: "u".into(),
                chunk_size: 1024,
                mode: UploadMode::Prove,
            },
            r#"{"upload_id":"u","chunk_size":1024,"mode":"prove"}"#,
        );
        check(&UploadMode::Load, r#""load""#);
    }

    #[test]
    fn upload_outcome() {
        check(&UploadOutcome::Loaded, r#""loaded""#);
        check(&UploadOutcome::Unlocked, r#""unlocked""#);
        check(&UploadOutcome::UnlockFailed, r#""unlock_failed""#);
    }

    #[test]
    fn chunk_response() {
        check(
            &ChunkResponse::Progress(UploadProgress {
                received: 3,
                size: 9,
            }),
            r#"{"status":"progress","received":3,"size":9}"#,
        );
        check(
            &ChunkResponse::Finished {
                outcome: UploadOutcome::UnlockFailed,
            },
            r#"{"status":"finished","outcome":"unlock_failed"}"#,
        );
    }

    #[test]
    fn api_error_codes() {
        check(
            &ApiError {
                error: ErrorCode::TooManyUploads,
            },
            r#"{"error":"too_many_uploads"}"#,
        );
        check(&ErrorCode::WrongSize, r#""wrong_size""#);
        check(&ErrorCode::BadTicket, r#""bad_ticket""#);
        check(&ErrorCode::TicketExpired, r#""ticket_expired""#);
        check(&ErrorCode::TicketUsed, r#""ticket_used""#);
        check(&ErrorCode::Busy, r#""busy""#);
        check(&ErrorCode::NotFound, r#""not_found""#);
        check(&ErrorCode::WrongOffset, r#""wrong_offset""#);
        check(&ErrorCode::ChunkTooLarge, r#""chunk_too_large""#);
        check(&ErrorCode::WrongFile, r#""wrong_file""#);
        check(&ErrorCode::Unavailable, r#""unavailable""#);
    }

    #[test]
    fn challenge_request_and_challenge() {
        check(
            &ChallengeRequest { ticket: "t".into() },
            r#"{"ticket":"t"}"#,
        );
        check(
            &Challenge {
                challenge_id: "c".into(),
                piece_size: 4096,
                pieces: vec![1, 9],
            },
            r#"{"challenge_id":"c","piece_size":4096,"pieces":[1,9]}"#,
        );
    }

    #[test]
    fn proof_response() {
        check(
            &ProofResponse {
                outcome: ProofOutcome::Unlocked,
            },
            r#"{"outcome":"unlocked"}"#,
        );
        check(&ProofOutcome::UnlockFailed, r#""unlock_failed""#);
    }

    #[test]
    fn new_error_codes() {
        check(&ErrorCode::Loading, r#""loading""#);
        check(&ErrorCode::ChallengeExpired, r#""challenge_expired""#);
    }
}
