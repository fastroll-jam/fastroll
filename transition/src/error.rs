use rjam_block::header_db::BlockHeaderDBError;
use rjam_crypto::CryptoError;
use rjam_extrinsics::validation::error::XtError;
use rjam_merkle::common::MerkleError;
use rjam_pvm_invocation::prelude::PVMError;
use rjam_state::{
    error::StateManagerError,
    types::{FallbackKeyError, PendingReportsError},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransitionError {
    // Timeslot errors
    #[error("Timeslot value {next_slot} must be greater than the parent block {current_slot}")]
    InvalidTimeslot { next_slot: u32, current_slot: u32 },
    #[error("Timeslot value {0} is in the future")]
    FutureTimeslot(u32),
    // Pending Work Reports errors
    #[error("PendingReports Error")]
    PendingReportsError(#[from] PendingReportsError),
    #[error("Crypto Serialization Error")]
    CryptoSerializationError,
    // External errors
    #[error("Extrinsic validation error: {0}")]
    XtValidationError(#[from] XtError),
    #[error("Fallback key error: {0}")]
    FallbackKeyError(#[from] FallbackKeyError),
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("StateManager error: {0}")]
    StateManagerError(#[from] StateManagerError),
    #[error("BlockHeaderDB error: {0}")]
    BlockHeaderDBError(#[from] BlockHeaderDBError),
    #[error("Merkle error: {0}")]
    MerkleError(#[from] MerkleError),
    #[error("PVM error: {0}")]
    PVMError(#[from] PVMError),
}
