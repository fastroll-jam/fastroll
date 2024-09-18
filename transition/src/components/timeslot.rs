use crate::{Transition, TransitionError};
use jam_types::state::timeslot::Timeslot;

pub struct TimeslotContext {
    pub header_timeslot: Timeslot,
}

impl Transition for Timeslot {
    type Context = TimeslotContext;

    fn to_next(&mut self, ctx: &Self::Context) -> Result<(), TransitionError>
    where
        Self: Sized,
    {
        let new_slot = ctx.header_timeslot.slot();
        let current_slot = self.slot();

        // Timeslot value must be greater than the parent block
        if new_slot <= current_slot {
            return Err(TransitionError::InvalidTimeslot {
                new_slot,
                current_slot,
            });
        }

        // Timeslot value must not be in the future
        if ctx.header_timeslot.is_in_future() {
            return Err(TransitionError::FutureTimeslot(new_slot));
        }

        self.0 = new_slot;
        Ok(())
    }
}
