use crate::{
    codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput},
    common::Hash32,
    impl_jam_codec_for_newtype,
};
pub struct EntropyAccumulator(pub [Hash32; 4]);
impl_jam_codec_for_newtype!(EntropyAccumulator, [Hash32; 4]);
