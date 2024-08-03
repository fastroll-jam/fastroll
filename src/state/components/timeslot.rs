use crate::{
    codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput},
    common::EPOCH_LENGTH,
    impl_jam_codec_for_newtype,
    transition::{Transition, TransitionError},
};

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
        self.0 % EPOCH_LENGTH as u32
    }

    pub fn is_new_epoch(&self) -> bool {
        self.0 % EPOCH_LENGTH as u32 == 0
    }
}

impl Transition for Timeslot {
    type Context = ();
    fn next(&mut self, ctx: &Self::Context) -> Result<(), TransitionError>
    where
        Self: Sized,
    {
        todo!()
    }
}
