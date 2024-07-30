use crate::state::components::timeslot::Timeslot;
use ark_ec_vrfs::prelude::ark_serialize::SerializationError;
use std::{
    error::Error,
    fmt::{Display, Formatter},
};

#[derive(Debug)]
pub enum TransitionError {
    SerializationError(SerializationError),
}

impl Display for TransitionError {
    fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl Error for TransitionError {}

impl From<SerializationError> for TransitionError {
    fn from(error: SerializationError) -> Self {
        TransitionError::SerializationError(error)
    }
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
