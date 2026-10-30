//! Wire types and ticket signing for the RuneCast urban-definitions service.

pub mod ticket;
pub mod types;

pub use ticket::{sign_ticket, verify_ticket, Ticket, TicketError, TICKET_TTL_SECS};
pub use types::*;
