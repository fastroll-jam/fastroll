use crate::state::{
    components::{safrole::FallbackKeyError, timeslot::Timeslot},
    global_state::GlobalStateError,
};
use ark_ec_vrfs::prelude::ark_serialize::SerializationError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransitionError {
    #[error("Serialization error: {0}")]
    SerializationError(#[from] SerializationError),
    #[error("Global state error: {0}")]
    GlobalStateError(#[from] GlobalStateError),
    #[error("Fallback key error: {0}")]
    FallbackKeyError(#[from] FallbackKeyError),
}

pub enum SlotType {
    NewBlock,
    NewEpoch, // The timeslot opens a new epoch
}

// TODO: add Extrinsics and other relevant input data for the state transition
pub struct TransitionContext {
    pub timeslot: Timeslot,
    pub slot_type: SlotType,
}

pub trait Transition {
    fn next(self, context: &TransitionContext) -> Result<Self, TransitionError>
    where
        Self: Sized;
}
