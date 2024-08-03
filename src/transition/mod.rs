use crate::{
    crypto::utils::CryptoError,
    state::{components::safrole::FallbackKeyError, global_state::GlobalStateError},
};
use ark_ec_vrfs::prelude::ark_serialize::SerializationError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransitionError {
    #[error("Timeslot value {new_slot} must be greater than the parent block {current_slot}")]
    InvalidTimeslot { new_slot: u32, current_slot: u32 },
    #[error("Timeslot value {0} is in the future")]
    FutureTimeslot(u32),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] SerializationError),
    #[error("Global state error: {0}")]
    GlobalStateError(#[from] GlobalStateError),
    #[error("Fallback key error: {0}")]
    FallbackKeyError(#[from] FallbackKeyError),
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
}

pub trait Transition {
    type Context; // State-specific transition context
    fn next(&mut self, ctx: &Self::Context) -> Result<(), TransitionError>
    where
        Self: Sized;
}
