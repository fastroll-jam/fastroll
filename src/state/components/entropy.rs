use crate::{
    codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput},
    common::Hash32,
    impl_jam_codec_for_newtype,
};
pub(crate) struct EntropyAccumulator(pub(crate) [Hash32; 4]);
impl_jam_codec_for_newtype!(EntropyAccumulator, [Hash32; 4]);
