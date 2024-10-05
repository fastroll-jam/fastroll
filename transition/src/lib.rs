extern crate core;

pub mod components;
pub mod procedures;

use ark_ec_vrfs::prelude::ark_serialize::SerializationError;
use rjam_crypto::utils::CryptoError;
use rjam_state::StateManagerError;
use rjam_types::state::safrole::FallbackKeyError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransitionError {
    #[error("Timeslot value {next_slot} must be greater than the parent block {current_slot}")]
    InvalidTimeslot { next_slot: u32, current_slot: u32 },
    #[error("Timeslot value {0} is in the future")]
    FutureTimeslot(u32),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] SerializationError),
    #[error("Fallback key error: {0}")]
    FallbackKeyError(#[from] FallbackKeyError),
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("Submitted ticket already exists in the state")]
    DuplicateTicket,
    #[error("Submitted tickets must be ordered by the ticket proof hash")]
    TicketsNotOrdered,
    #[error("Submitted tickets must have valid ring VRF proofs")]
    BadTicketProof,
    #[error("StateManager error: {0}")]
    StateManagerError(#[from] StateManagerError),
}

pub trait Transition {
    type Context; // State-specific transition context
    fn to_next(&mut self, ctx: &Self::Context) -> Result<(), TransitionError>
    where
        Self: Sized;
}
