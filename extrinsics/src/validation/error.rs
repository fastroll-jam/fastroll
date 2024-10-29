use ark_ec_vrfs::prelude::ark_serialize::SerializationError;
use rjam_codec::JamCodecError;
use rjam_crypto::CryptoError;
use rjam_state::StateManagerError;
use rjam_types::common::workloads::WorkReportError;
use thiserror::Error;

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Error)]
pub enum ExtrinsicValidationError {
    // Ticket validation errors
    #[error("Submitted ticket already exists in the accumulator")]
    DuplicateTicket,
    #[error("Submitted tickets must be ordered by the ticket proof hash")]
    TicketsNotOrdered,
    #[error("Submitted tickets must have valid ring VRF proofs")]
    BadTicketProof,
    #[error("Ticket attempt number must be either 0 or 1")]
    BadTicketAttemptNumber,
    #[error("Ticket submission period has ended")]
    TicketSubmissionClosed,
    #[error("Too many tickets")]
    TooManyTickets,
    // External errors
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("CryptoError: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("WorkReportError: {0}")]
    WorkReportError(#[from] WorkReportError),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] SerializationError),
}
