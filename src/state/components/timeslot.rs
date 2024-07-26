use crate::{
    codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput},
    impl_jam_codec_for_newtype,
};

pub(crate) struct Timeslot(pub(crate) u32);
impl_jam_codec_for_newtype!(Timeslot, u32);
