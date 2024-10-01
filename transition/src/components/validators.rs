use crate::{Transition, TransitionError};
use rjam_common::ValidatorSet;
use rjam_types::state::{
    timeslot::Timeslot,
    validators::{ActiveSet, PastSet, StagingSet},
};
use std::fmt::Display;

pub struct StagingSetContext {
    pub timeslot: Timeslot,
    pub is_new_epoch: bool,
}

impl Transition for StagingSet {
    type Context = StagingSetContext;

    fn to_next(&mut self, ctx: &Self::Context) -> Result<(), TransitionError>
    where
        Self: Sized,
    {
        // TODO: implement
        // This state is transitioned by the rule specified in a privileged service
        Ok(())
    }
}

pub struct ActiveSetContext {
    pub timeslot: Timeslot,
    pub is_new_epoch: bool,
    pub current_pending_validator_set: ValidatorSet, // from the Safrole state
}

impl Transition for ActiveSet {
    type Context = ActiveSetContext;
    fn to_next(&mut self, ctx: &Self::Context) -> Result<(), TransitionError>
    where
        Self: Sized,
    {
        if ctx.is_new_epoch {
            self.0 = ctx.current_pending_validator_set
        }
        Ok(())
    }
}

pub struct PastSetContext {
    pub timeslot: Timeslot,
    pub is_new_epoch: bool,
    pub current_active_set: ActiveSet,
}

impl Transition for PastSet {
    type Context = PastSetContext;
    fn to_next(&mut self, ctx: &Self::Context) -> Result<(), TransitionError>
    where
        Self: Sized,
    {
        if ctx.is_new_epoch {
            self.0 = ctx.current_active_set.0;
        }
        Ok(())
    }
}
