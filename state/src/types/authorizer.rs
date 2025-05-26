use crate::{
    impl_simple_state_component,
    state_utils::{SimpleStateComponent, StateComponent, StateEntryType, StateKeyConstant},
};
use fr_codec::prelude::*;
use fr_common::{CoreIndex, Hash32, AUTH_QUEUE_SIZE, CORE_COUNT, MAX_AUTH_POOL_SIZE};
use fr_limited_vec::{FixedVec, LimitedVec};
use std::fmt::{Display, Formatter};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthPoolError {
    #[error("Invalid Core Index: {0}")]
    InvalidCoreIndex(CoreIndex),
}

pub type CoreAuthPool = LimitedVec<Hash32, MAX_AUTH_POOL_SIZE>;
pub type AuthPoolFixedVec = FixedVec<CoreAuthPool, CORE_COUNT>;

/// The authorizer pool.
///
/// Represents `α` of the GP.
#[derive(Clone, Debug, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct AuthPool(pub AuthPoolFixedVec);
impl_simple_state_component!(AuthPool, AuthPool);

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
        Ok(self.0[core_index as usize].as_ref())
    }
}

pub type CoreAuthQueue = FixedVec<Hash32, AUTH_QUEUE_SIZE>;
pub type AuthQueueFixedVec = FixedVec<CoreAuthQueue, CORE_COUNT>;

/// The authorizer queue.
///
/// Represents `φ` of the GP.
#[derive(Clone, Debug, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct AuthQueue(pub AuthQueueFixedVec);
impl_simple_state_component!(AuthQueue, AuthQueue);
