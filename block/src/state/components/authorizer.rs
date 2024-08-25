use jam_codec::{
    impl_jam_codec_for_newtype, JamCodecError, JamDecode, JamEncode, JamInput, JamOutput,
};
use jam_common::{Hash32, CORE_COUNT};

pub(crate) struct AuthorizerPool(pub(crate) [Vec<Hash32>; CORE_COUNT]); // Vec<Hash32> length up to `O = 8`
impl_jam_codec_for_newtype!(AuthorizerPool, [Vec<Hash32>; CORE_COUNT]);

pub(crate) struct AuthorizerQueue(pub(crate) [[Hash32; 80]; CORE_COUNT]);
impl_jam_codec_for_newtype!(AuthorizerQueue, [[Hash32; 80]; CORE_COUNT]);
