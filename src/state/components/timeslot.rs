use crate::{
    codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput},
    impl_jam_codec_for_newtype,
    transition::{Transition, TransitionContext, TransitionError},
};

#[derive(Copy, Clone, Ord, PartialOrd, PartialEq, Eq)]
pub struct Timeslot(pub u32);
impl_jam_codec_for_newtype!(Timeslot, u32);

impl Transition for Timeslot {
    fn next(self, context: &TransitionContext) -> Result<Self, TransitionError>
    where
        Self: Sized,
    {
        todo!()
    }
}
