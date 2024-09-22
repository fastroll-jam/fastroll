use crate::{Transition, TransitionError};
use rjam_common::ValidatorSet;
use rjam_types::state::{
    timeslot::Timeslot,
    validators::{ActiveValidatorSet, PastValidatorSet, StagingValidatorSet},
};
use std::fmt::Display;

pub struct StagingValidatorSetContext {
    pub timeslot: Timeslot,
    pub is_new_epoch: bool,
}

impl Transition for StagingValidatorSet {
    type Context = StagingValidatorSetContext;

    fn to_next(&mut self, ctx: &Self::Context) -> Result<(), TransitionError>
    where
        Self: Sized,
    {
        // TODO: implement
        // This state is transitioned by the rule specified in a privileged service
        Ok(())
    }
}

pub struct ActiveValidatorSetContext {
    pub timeslot: Timeslot,
    pub is_new_epoch: bool,
    pub current_pending_validator_set: ValidatorSet, // from the Safrole state
}

impl Transition for ActiveValidatorSet {
    type Context = ActiveValidatorSetContext;
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

pub struct PastValidatorSetContext {
    pub timeslot: Timeslot,
    pub is_new_epoch: bool,
    pub current_active_set: ActiveValidatorSet,
}

impl Transition for PastValidatorSet {
    type Context = PastValidatorSetContext;
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
