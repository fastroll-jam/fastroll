use fr_codec::JamCodecError;
use fr_common::{CoreIndex, ServiceId, UnsignedGas};
use fr_crypto::error::CryptoError;
use fr_limited_vec::LimitedVecError;
use fr_pvm_core::{error::VMCoreError, state::memory::MemoryError};
use fr_state::error::StateManagerError;
use thiserror::Error;

/// PVM Host Call Error Codes
#[derive(Debug, Error)]
pub enum HostCallError {
    #[error("Accumulate context is not initialized")]
    AccumulateContextNotInitialized,
    #[error("AccountsSandbox is not initialized")]
    AccountsSandboxNotInitialized,
    #[error("Refine context is not initialized")]
    RefineContextNotInitialized,
    #[error("Gas limit overflowed (gas_limit={0})")]
    GasLimitOverflow(UnsignedGas),
    #[error("Data segment is too large")]
    DataSegmentTooLarge,
    #[error("Invalid host call invocation context")]
    InvalidContext,
    #[error("Service id overflowed")]
    ServiceIdOverflow,
    #[error("Account (s={0}) not found from the global account state")]
    AccountNotFound(ServiceId),
    #[error("Failed to insert an entry from an account storage")]
    AccountStorageInsertionFailed,
    #[error("Failed to remove an entry from an account storage")]
    AccountStorageRemovalFailed,
    #[error("Account lookups storage entry is not found. Key=({0}, {1})")]
    AccountLookupsEntryNotFound(String, u32),
    #[error("Account lookups storage entry is malformed. Key=({0}, {1})")]
    AccountLookupsEntryMalformed(String, u32),
    #[error("Exit reason of the PVM invocation is invalid")]
    InvalidExitReason,
    #[error("CryptoError: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("LimitedVecError: {0}")]
    LimitedVecError(#[from] LimitedVecError),
    #[error("MemoryError: {0}")]
    MemoryError(#[from] MemoryError),
    #[error("VMCoreError: {0}")]
    VMCoreError(#[from] VMCoreError),
    #[error("PartialStateError: {0}")]
    PartialStateError(#[from] PartialStateError),
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
}

/// PVM Host Call Partial State Error Codes
#[derive(Debug, Error)]
pub enum PartialStateError {
    #[error("Invalid core index: {0}")]
    InvalidAssignerCoreIndex(CoreIndex),
    #[error("Core index {0} out of bounds")]
    CoreIndexOutOfBounds(CoreIndex),
    #[error("Account (s={0}) not found from the global state")]
    AccountNotFoundFromGlobalState(ServiceId),
    #[error(
        "Accumulator account (s={0}) is not initialized in the service accounts partial state"
    )]
    AccumulatorAccountNotInitialized(ServiceId),
    #[error("Account ({0}) balance underflowed")]
    AccountBalanceUnderflow(ServiceId),
    #[error("Account ({0}) balance overflowed")]
    AccountBalanceOverflow(ServiceId),
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("LimitedVecError: {0}")]
    LimitedVecError(#[from] LimitedVecError),
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
}
