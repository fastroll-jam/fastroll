use fr_block::header_db::BlockHeaderDBError;
use fr_common::{CoreIndex, Hash32, PreimagesKey, ServiceId, StorageKey, ValidatorIndex};
use fr_crypto::error::CryptoError;
use fr_extrinsics::validation::error::XtError;
use fr_limited_vec::LimitedVecError;
use fr_merkle::common::MerkleError;
use fr_pvm_invocation::error::PVMInvokeError;
use fr_state::{
    error::StateManagerError,
    types::{LastAccumulateOutputsError, PendingReportsError, SlotSealerError},
};
use thiserror::Error;
use tokio::task::JoinError;

#[derive(Debug, Error)]
pub enum TransitionError {
    // Timeslot errors
    #[error("Timeslot value {new_slot} must be greater than the parent block {prev_slot}")]
    InvalidTimeslot { new_slot: u32, prev_slot: u32 },
    #[error("Timeslot value {0} is in the future")]
    FutureTimeslot(u32),
    // Pending Work Reports errors
    #[error("PendingReports Error")]
    PendingReportsError(#[from] PendingReportsError),
    #[error("Crypto Serialization Error")]
    CryptoSerializationError,
    // STF invariant violations
    #[error("Validator index is out of bound: {0}")]
    ValidatorIndexOutOfBounds(ValidatorIndex),
    #[error("AccumulateHistory state is missing")]
    AccumulateHistoryMissing,
    #[error("AccumulateHistory STF reports more accumulate_count({0}) than the total accumulatable reports ({1})")]
    InvalidAccumulateCount(usize, usize),
    #[error("Pending report not found for core index {0}")]
    PendingReportMissing(CoreIndex),
    #[error("Service account is added or updated in the partial state sandbox but its value is missing. service_id={0}")]
    TransitionedServiceAccountMissing(ServiceId),
    #[error("Service account's storage entry is added or updated in the partial state sandbox but its value is missing. service_id={0}, storage_key={1}")]
    TransitionedServiceAccountStorageMissing(ServiceId, StorageKey),
    #[error("Service account's preimages entry is added or updated in the partial state sandbox but its value is missing. service_id={0}, preimage_key={1}")]
    TransitionedServiceAccountPreimagesMissing(ServiceId, PreimagesKey),
    #[error("Service account's lookups entry is added or updated in the partial state sandbox but its value is missing. service_id={0}, lookups_key=({1}, {2})")]
    TransitionedServiceAccountLookupsMissing(ServiceId, Hash32, u32),
    #[error("Lookups metadata storage should have an empty timeslot sequence entry to integrate preimages. service_id={0}, lookups_key=({1}, {2})")]
    PreimageNotSolicited(ServiceId, Hash32, u32),
    // External errors
    #[error("XtError: {0}")]
    XtError(#[from] XtError),
    #[error("SlotSealerError: {0}")]
    SlotSealerError(#[from] SlotSealerError),
    #[error("CryptoError: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("LimitedVecError: {0}")]
    LimitedVecError(#[from] LimitedVecError),
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
    #[error("BlockHeaderDBError: {0}")]
    BlockHeaderDBError(#[from] BlockHeaderDBError),
    #[error("MerkleError: {0}")]
    MerkleError(#[from] MerkleError),
    #[error("PVMInvokeError: {0}")]
    PVMInvokeError(#[from] PVMInvokeError),
    #[error("JoinError: {0}")]
    JoinError(#[from] JoinError),
    #[error("LastAccumulateOutputsError: {0}")]
    LastAccumulateOutputsError(#[from] LastAccumulateOutputsError),
}
