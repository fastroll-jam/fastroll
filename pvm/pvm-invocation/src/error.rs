use fr_codec::JamCodecError;
use fr_common::{workloads::WorkExecutionError, ServiceId};
use fr_crypto::error::CryptoError;
use fr_erasure_coding::ErasureCodingError;
use fr_merkle::common::MerkleError;
use fr_pvm_host::error::{HostCallError, PartialStateError};
use fr_pvm_interface::error::PVMError;
use fr_state::error::StateManagerError;
use thiserror::Error;

/// PVM Invocation Errors
#[derive(Debug, Error)]
pub enum PVMInvokeError {
    #[error("Spawned accumulate task panicked")]
    AccumulateTaskPanicked,
    #[error(
        "Number of import items referenced by work-package hashes is larger than allowed limit"
    )]
    SegmentLookupTableTooLarge,
    #[error("Work package is not authorized and `is_authorized` returned error code: {0}")]
    WorkPackageNotAuthorized(WorkExecutionError),
    #[error("Refine results blobs and authorization trace exceed size limit of work reports")]
    WorkReportBlobTooLarge,
    #[error("Account sandbox for accumulate host (s={0}) is missing")]
    MissingAccumulateHostSandbox(ServiceId),
    #[error("Number of work digests exceeds maximum")]
    WorkDigestsOverflow,
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("CryptoError: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("MerkleError: {0}")]
    MerkleError(#[from] MerkleError),
    #[error("ErasureCodingError: {0}")]
    ErasureCodingError(#[from] ErasureCodingError),
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
    #[error("PartialStateError: {0}")]
    PartialStateError(#[from] PartialStateError),
    #[error("PVMError: {0}")]
    PVMError(#[from] PVMError),
    #[error("HostCallError: {0}")]
    HostCallError(#[from] HostCallError),
}
