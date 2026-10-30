//! HMAC-signed, short-lived upload tickets. Free of service specifics so the
//! backend can depend on this crate to mint them.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::types::string_i64;

/// How long a freshly minted ticket stays valid.
pub const TICKET_TTL_SECS: i64 = 1800;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ticket {
    /// Discord snowflake; a JSON string on the wire.
    #[serde(with = "string_i64")]
    pub user_id: i64,
    pub nonce: String,
    /// Unix seconds; the ticket is invalid at and after this instant.
    pub expires_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketError {
    Malformed,
    BadSignature,
    Expired,
}

fn mac(key: &[u8], payload: &str) -> HmacSha256 {
    // HMAC accepts keys of any length, so this cannot fail.
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(payload.as_bytes());
    mac
}

/// `base64url(json(ticket)) + "." + base64url(hmac_sha256(key, first part))`, no padding.
pub fn sign_ticket(key: &[u8], ticket: &Ticket) -> String {
    let json = serde_json::to_vec(ticket).expect("Ticket serializes");
    let payload = URL_SAFE_NO_PAD.encode(json);
    let tag = mac(key, &payload).finalize().into_bytes();
    format!("{payload}.{}", URL_SAFE_NO_PAD.encode(tag))
}

pub fn verify_ticket(key: &[u8], token: &str, now_unix: i64) -> Result<Ticket, TicketError> {
    let mut parts = token.split('.');
    let (Some(payload), Some(sig), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(TicketError::Malformed);
    };
    let sig = URL_SAFE_NO_PAD
        .decode(sig)
        .map_err(|_| TicketError::Malformed)?;
    // verify_slice compares in constant time.
    mac(key, payload)
        .verify_slice(&sig)
        .map_err(|_| TicketError::BadSignature)?;
    let json = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| TicketError::Malformed)?;
    let ticket: Ticket = serde_json::from_slice(&json).map_err(|_| TicketError::Malformed)?;
    if now_unix >= ticket.expires_at {
        return Err(TicketError::Expired);
    }
    Ok(ticket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    const KEY: &[u8] = b"test-key-0123456789";

    fn ticket() -> Ticket {
        Ticket {
            user_id: 1098406821124911175,
            nonce: "abc123".to_string(),
            expires_at: 2_000_000_000,
        }
    }

    #[test]
    fn round_trips() {
        let t = ticket();
        let token = sign_ticket(KEY, &t);
        assert_eq!(verify_ticket(KEY, &token, t.expires_at - 1), Ok(t));
    }

    #[test]
    fn rejects_tampered_payload() {
        let t = ticket();
        let token = sign_ticket(KEY, &t);
        let mut chars: Vec<char> = token.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert_eq!(
            verify_ticket(KEY, &tampered, t.expires_at - 1),
            Err(TicketError::BadSignature)
        );
    }

    #[test]
    fn rejects_wrong_key() {
        let t = ticket();
        let token = sign_ticket(KEY, &t);
        assert_eq!(
            verify_ticket(b"other-key", &token, t.expires_at - 1),
            Err(TicketError::BadSignature)
        );
    }

    #[test]
    fn rejects_expired() {
        let t = ticket();
        let token = sign_ticket(KEY, &t);
        assert_eq!(
            verify_ticket(KEY, &token, t.expires_at),
            Err(TicketError::Expired)
        );
    }

    #[test]
    fn rejects_garbage() {
        for bad in ["x", "", "a.b.c"] {
            assert_eq!(verify_ticket(KEY, bad, 0), Err(TicketError::Malformed));
        }
    }

    #[test]
    fn user_id_is_a_string_on_the_wire() {
        let token = sign_ticket(KEY, &ticket());
        let payload = token.split('.').next().unwrap();
        let json = String::from_utf8(URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        assert!(
            json.contains(r#""user_id":"1098406821124911175""#),
            "{json}"
        );
    }
}
