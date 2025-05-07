use fr_codec::JamCodecError;
use fr_crypto::error::CryptoError;
use fr_pvm_core::{error::VMCoreError, state::memory::MemoryError};
use fr_pvm_host::error::{HostCallError, PartialStateError};
use fr_state::error::StateManagerError;
use thiserror::Error;

// PVM Error Codes
#[derive(Debug, Error)]
pub enum PVMError {
    #[error("Account code not found")]
    AccountCodeNotFound,
    #[error("Account not found")]
    AccountNotFound,
    #[error("Spawned accumulate task panicked")]
    AccumulateTaskPanicked,
    #[error("CryptoError: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("MemoryError: {0}")]
    MemoryError(#[from] MemoryError),
    #[error("VMCoreError: {0}")]
    VMCoreError(#[from] VMCoreError),
    #[error("HostCallError: {0}")]
    HostCallError(#[from] HostCallError),
    #[error("PartialStateError: {0}")]
    PartialStateError(#[from] PartialStateError),
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
}
