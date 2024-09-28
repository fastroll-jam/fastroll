use rjam_codec::{
    impl_jam_codec_for_newtype, JamCodecError, JamDecode, JamEncode, JamInput, JamOutput,
};
use rjam_common::{Hash32, CORE_COUNT, MAX_AUTH_QUEUE_SIZE};

pub struct AuthPool(pub [Vec<Hash32>; CORE_COUNT]); // Vec<Hash32> length up to `O = 8`
impl_jam_codec_for_newtype!(AuthPool, [Vec<Hash32>; CORE_COUNT]);

#[derive(Clone, Copy)]
pub struct AuthQueue(pub [[Hash32; MAX_AUTH_QUEUE_SIZE]; CORE_COUNT]);
impl_jam_codec_for_newtype!(AuthQueue, [[Hash32; MAX_AUTH_QUEUE_SIZE]; CORE_COUNT]);
