use crate::{
    codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput},
    common::{COMMON_ERA_TIMESTAMP, EPOCH_LENGTH, SLOT_DURATION},
    impl_jam_codec_for_newtype,
    transition::{Transition, TransitionError},
};
use time::OffsetDateTime;

#[derive(Copy, Clone, Debug, Ord, PartialOrd, PartialEq, Eq)]
// #[repr(transparent)]
pub struct Timeslot(pub u32);
impl_jam_codec_for_newtype!(Timeslot, u32);

impl Timeslot {
    pub fn new(slot: u32) -> Self {
        Self(slot)
    }

    pub fn slot(&self) -> u32 {
        self.0
    }

    pub fn epoch(&self) -> u32 {
        self.0 / EPOCH_LENGTH as u32
    }

    pub fn slot_phase(&self) -> u32 {
        self.0 % EPOCH_LENGTH as u32 // FIXME: separate this logic with the epoch index and track this value in another field?
    }

    // pub fn is_new_epoch(&self) -> bool {
    //     self.0 % EPOCH_LENGTH as u32 == 0
    // } // FIXME: this also should be compared to the prior epoch number
    pub fn is_new_epoch(&self) -> bool {
        true
    } // FIXME: delete this (temporary code)

    pub fn to_unix_timestamp(&self) -> u64 {
        let slot_duration_secs = self.0 as u64 * SLOT_DURATION;
        COMMON_ERA_TIMESTAMP + slot_duration_secs
    }

    pub fn from_unix_timestamp(timestamp: u64) -> Option<Self> {
        if timestamp < COMMON_ERA_TIMESTAMP {
            return None;
        }
        let slot = (timestamp - COMMON_ERA_TIMESTAMP) / SLOT_DURATION;
        Some(Self(slot as u32))
    }

    /// Checks if the timeslot value is in the future compared to the current UTC time
    pub fn is_in_future(&self) -> bool {
        let current_utc_time = OffsetDateTime::now_utc().unix_timestamp() as u64;
        let slot_unix_time = self.to_unix_timestamp();

        slot_unix_time > current_utc_time
    }
}

pub struct TimeslotContext {
    pub header_timeslot: Timeslot,
}

impl Transition for Timeslot {
    type Context = TimeslotContext;
    fn next(&mut self, ctx: &Self::Context) -> Result<(), TransitionError>
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
