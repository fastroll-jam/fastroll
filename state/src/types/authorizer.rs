use crate::{
    impl_simple_state_component,
    state_utils::{SimpleStateComponent, StateComponent, StateEntryType, StateKeyConstant},
};
use rjam_codec::prelude::*;
use rjam_common::{CoreIndex, Hash32, AUTH_QUEUE_SIZE, CORE_COUNT, MAX_AUTH_POOL_SIZE};
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

/// The authorizer pool.
///
/// Represents `α` of the GP.
#[derive(Clone, Debug, PartialEq, Eq, JamEncode, JamDecode)]
pub struct AuthPool(pub Box<[Vec<Hash32>; CORE_COUNT]>); // Vec<Hash32> length up to `O = 8`
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
            writeln!(f, "  core #{core_idx}: [")?;
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

/// The authorizer queue.
///
/// Represents `φ` of the GP.
#[derive(Clone, Debug, PartialEq, Eq, JamEncode, JamDecode)]
pub struct AuthQueue(pub Box<[[Hash32; AUTH_QUEUE_SIZE]; CORE_COUNT]>);
impl_simple_state_component!(AuthQueue, AuthQueue);

impl Default for AuthQueue {
    fn default() -> Self {
        let arr = from_fn(|_| from_fn(|_| Hash32::default()));
        Self(Box::new(arr))
    }
}
