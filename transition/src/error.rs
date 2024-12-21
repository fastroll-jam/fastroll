use ark_ec_vrfs::prelude::ark_serialize::SerializationError;
use rjam_crypto::CryptoError;
use rjam_db::BlockHeaderDBError;
use rjam_extrinsics::validation::error::ExtrinsicValidationError;
use rjam_merkle::common::MerkleError;
use rjam_pvm_core::types::error::PVMError;
use rjam_state::StateManagerError;
use rjam_types::state::*;
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
    // External errors
    #[error("Block header update error: {0}")]
    BlockHeaderUpdateError(#[from] BlockHeaderUpdateError),
    #[error("Extrinsic validation error: {0}")]
    ExtrinsicValidationError(#[from] ExtrinsicValidationError),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] SerializationError),
    #[error("Fallback key error: {0}")]
    FallbackKeyError(#[from] FallbackKeyError),
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("StateManager error: {0}")]
    StateManagerError(#[from] StateManagerError),
    #[error("Merkle error: {0}")]
    MerkleError(#[from] MerkleError),
    #[error("PVM error: {0}")]
    PVMError(#[from] PVMError),
}

#[derive(Debug, Error)]
pub enum BlockHeaderUpdateError {
    #[error("BlockHeaderDB error: {0}")]
    BlockHeaderDBError(#[from] BlockHeaderDBError),
    #[error("Timeslot error: {0}")]
    TimeslotError(#[from] TimeslotError),
}
