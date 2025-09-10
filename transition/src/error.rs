use fr_block::header_db::BlockHeaderDBError;
use fr_crypto::error::CryptoError;
use fr_extrinsics::validation::error::XtError;
use fr_limited_vec::LimitedVecError;
use fr_merkle::common::MerkleError;
use fr_pvm_invocation::error::PVMInvokeError;
use fr_state::{
    error::StateManagerError,
    types::{PendingReportsError, SlotSealerError},
};
use thiserror::Error;
use tokio::task::JoinError;

#[derive(Debug, Error)]
pub enum TransitionError {
    // Timeslot errors
    #[error("Timeslot value {next_slot} must be greater than the parent block {current_slot}")]
    InvalidTimeslot { next_slot: u32, current_slot: u32 },
    #[error("Timeslot value {0} is in the future")]
    FutureTimeslot(u32),
    #[error("Epoch index overflowed")]
    EpochIndexOverflow,
    // Pending Work Reports errors
    #[error("PendingReports Error")]
    PendingReportsError(#[from] PendingReportsError),
    #[error("Crypto Serialization Error")]
    CryptoSerializationError,
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
}
