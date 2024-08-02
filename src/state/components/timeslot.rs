use crate::{
    codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput},
    impl_jam_codec_for_newtype,
    transition::{Transition, TransitionError},
};

#[derive(Copy, Clone, Ord, PartialOrd, PartialEq, Eq)]
pub struct Timeslot(pub u32);
impl_jam_codec_for_newtype!(Timeslot, u32);

impl Transition for Timeslot {
    type Context = ();
    fn next(&mut self, ctx: &Self::Context) -> Result<(), TransitionError>
    where
        Self: Sized,
    {
        todo!()
    }
}
