use crate::{
    impl_simple_state_component,
    state_utils::{SimpleStateComponent, StateComponent, StateEntryType, StateKeyConstant},
};
use rjam_codec::{
    impl_jam_codec_for_newtype, JamCodecError, JamDecode, JamEncode, JamInput, JamOutput,
};
use rjam_common::{CoreIndex, Hash32, CORE_COUNT, MAX_AUTH_POOL_SIZE, MAX_AUTH_QUEUE_SIZE};
use std::{
    array::from_fn,
    fmt::{Display, Formatter},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthPoolError {
    #[error("Invalid Core Index: {0}")]
    InvalidCoreIndex(CoreIndex),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthPool(pub Box<[Vec<Hash32>; CORE_COUNT]>); // Vec<Hash32> length up to `O = 8`
impl_jam_codec_for_newtype!(AuthPool, Box<[Vec<Hash32>; CORE_COUNT]>);
impl_simple_state_component!(AuthPool, AuthPool);

impl Default for AuthPool {
    fn default() -> Self {
        let arr = from_fn(|_| Vec::with_capacity(MAX_AUTH_POOL_SIZE));

        Self(Box::new(arr))
    }
}

impl Display for AuthPool {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "AuthPool {{")?;
        for (core_idx, pool) in self.0.iter().enumerate() {
            writeln!(f, "  core #{}: [", core_idx)?;
            for auth_hash in pool {
                writeln!(f, "    {}", &auth_hash)?;
            }
            writeln!(f, "  ]")?;
        }
        write!(f, "}}")
    }
}

impl AuthPool {
    pub fn get_by_core_index(&self, core_index: CoreIndex) -> Result<&[Hash32], AuthPoolError> {
        if core_index as usize >= CORE_COUNT {
            return Err(AuthPoolError::InvalidCoreIndex(core_index));
        }
        Ok(&self.0[core_index as usize])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthQueue(pub Box<[[Hash32; MAX_AUTH_QUEUE_SIZE]; CORE_COUNT]>);
impl_jam_codec_for_newtype!(AuthQueue, Box<[[Hash32; MAX_AUTH_QUEUE_SIZE]; CORE_COUNT]>);
impl_simple_state_component!(AuthQueue, AuthQueue);

impl Default for AuthQueue {
    fn default() -> Self {
        Self(Box::new(
            [[Hash32::default(); MAX_AUTH_QUEUE_SIZE]; CORE_COUNT],
        ))
    }
}
