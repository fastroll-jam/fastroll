use crate::state::components::timeslot::Timeslot;
use ark_ec_vrfs::prelude::ark_serialize::SerializationError;
use std::{
    error::Error,
    fmt::{Display, Formatter},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransitionError {
    #[error("Serialization error: {0}")]
    SerializationError(#[from] SerializationError),
}

pub(crate) enum SlotType {
    NewBlock,
    NewEpoch, // The timeslot opens a new epoch
}

pub(crate) struct TransitionContext {
    pub(crate) timeslot: Timeslot,
    pub(crate) slot_type: SlotType,
}

pub trait Transition {
    fn next(self, context: &TransitionContext) -> Result<Self, TransitionError>
    where
        Self: Sized;
}
