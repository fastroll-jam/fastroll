use crate::state_utils::{StateComponent, StateEntryType, StateKeyConstant};
use rjam_codec::{
    impl_jam_codec_for_newtype, JamCodecError, JamDecode, JamEncode, JamInput, JamOutput,
};
use rjam_common::{CoreIndex, Hash32, CORE_COUNT, HASH32_EMPTY, MAX_AUTH_QUEUE_SIZE};

#[derive(Clone)]
pub struct AuthPool(pub Box<[Vec<Hash32>; CORE_COUNT]>); // Vec<Hash32> length up to `O = 8`
impl_jam_codec_for_newtype!(AuthPool, Box<[Vec<Hash32>; CORE_COUNT]>);

impl StateComponent for AuthPool {
    const STATE_KEY_CONSTANT: StateKeyConstant = StateKeyConstant::AuthPool;

    fn from_entry_type(entry: &StateEntryType) -> Option<&Self> {
        if let StateEntryType::AuthPool(ref entry) = entry {
            Some(entry)
        } else {
            None
        }
    }

    fn from_entry_type_mut(entry: &mut StateEntryType) -> Option<&mut Self> {
        if let StateEntryType::AuthPool(ref mut entry) = entry {
            Some(entry)
        } else {
            None
        }
    }

    fn into_entry_type(self) -> StateEntryType {
        StateEntryType::AuthPool(self)
    }
}

impl AuthPool {
    pub fn get_by_core_index(&self, core_index: CoreIndex) -> &[Hash32] {
        &self.0[core_index as usize]
    }
}

#[derive(Clone)]
pub struct AuthQueue(pub Box<[[Hash32; MAX_AUTH_QUEUE_SIZE]; CORE_COUNT]>);
impl_jam_codec_for_newtype!(AuthQueue, Box<[[Hash32; MAX_AUTH_QUEUE_SIZE]; CORE_COUNT]>);

impl StateComponent for AuthQueue {
    const STATE_KEY_CONSTANT: StateKeyConstant = StateKeyConstant::AuthQueue;

    fn from_entry_type(entry: &StateEntryType) -> Option<&Self> {
        if let StateEntryType::AuthQueue(ref entry) = entry {
            Some(entry)
        } else {
            None
        }
    }

    fn from_entry_type_mut(entry: &mut StateEntryType) -> Option<&mut Self> {
        if let StateEntryType::AuthQueue(ref mut entry) = entry {
            Some(entry)
        } else {
            None
        }
    }

    fn into_entry_type(self) -> StateEntryType {
        StateEntryType::AuthQueue(self)
    }
}

impl Default for AuthQueue {
    fn default() -> Self {
        Self(Box::new([[HASH32_EMPTY; MAX_AUTH_QUEUE_SIZE]; CORE_COUNT]))
    }
}
