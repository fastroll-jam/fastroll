use rjam_codec::{
    impl_jam_codec_for_newtype, JamCodecError, JamDecode, JamEncode, JamInput, JamOutput,
};
use rjam_common::{CoreIndex, Hash32, CORE_COUNT, MAX_AUTH_QUEUE_SIZE};

#[derive(Clone)]
pub struct AuthPool(pub Box<[Vec<Hash32>; CORE_COUNT]>); // Vec<Hash32> length up to `O = 8`
impl_jam_codec_for_newtype!(AuthPool, Box<[Vec<Hash32>; CORE_COUNT]>);

impl AuthPool {
    pub fn get_by_core_index(&self, core_index: CoreIndex) -> &[Hash32] {
        &self.0[core_index as usize]
    }
}

#[derive(Clone)]
pub struct AuthQueue(pub Box<[[Hash32; MAX_AUTH_QUEUE_SIZE]; CORE_COUNT]>);
impl_jam_codec_for_newtype!(AuthQueue, Box<[[Hash32; MAX_AUTH_QUEUE_SIZE]; CORE_COUNT]>);
