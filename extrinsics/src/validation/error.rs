use ark_ec_vrfs::prelude::ark_serialize::SerializationError;
use rjam_codec::JamCodecError;
use rjam_common::CoreIndex;
use rjam_crypto::CryptoError;
use rjam_state::StateManagerError;
use rjam_types::common::workloads::WorkReportError;
use thiserror::Error;

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Error)]
pub enum ExtrinsicValidationError {
    // Assurances validation errors
    #[error("The number of assurance entries exceeds the allowed validator count")]
    AssurancesEntryLimitExceeded,
    #[error("Assurance entries must be sorted by validator index")]
    AssurancesNotSorted,
    #[error("Invalid parent hash for assurance entry")]
    InvalidAssuranceParentHash,
    #[error("Invalid assurance signature")]
    InvalidAssuranceSignature,
    #[error("No pending report found for core {0}")]
    NoPendingReportForCore(CoreIndex),

    // Disputes validation errors
    #[error("Dispute entries must be sorted correctly")]
    DisputesNotSorted,
    #[error("Judgments must be sorted by validator index")]
    JudgmentsNotSorted,
    #[error("Duplicate verdict entry found")]
    DuplicateVerdict,
    #[error("Duplicate judgment entry found")]
    DuplicateJudgment,
    #[error("Duplicate culprit entry found")]
    DuplicateCulprit,
    #[error("Duplicate fault entry found")]
    DuplicateFault,
    #[error("Verdict entry already exists in past dispute sets")]
    VerdictAlreadyExists,
    #[error("Validator was not a culprit")]
    NotCulprit,
    #[error("Validator did not cast a faulty vote")]
    NotFault,
    #[error("Validator is not part of the active or past set")]
    InvalidValidatorSet,
    #[error("Invalid signature for judgment")]
    InvalidJudgmentSignature,
    #[error("Invalid culprit signature")]
    InvalidCulpritSignature,
    #[error("Invalid fault signature")]
    InvalidFaultSignature,

    // Guarantees validation errors
    #[error("The number of guarantee entries exceeds the allowed core count")]
    GuaranteesEntryLimitExceeded,
    #[error("Guarantee entries must be sorted by core index")]
    GuaranteesNotSorted,
    #[error("Duplicate core index found in guarantees")]
    DuplicateCoreIndex,
    #[error("Duplicate work package hashes found in guarantees")]
    DuplicateWorkPackageHash,
    #[error("Pending report exists for the core")]
    PendingReportExists,
    #[error("Invalid authorizer hash in work report")]
    InvalidAuthorizerHash,
    #[error("Work package hash already exists in block history")]
    WorkPackageAlreadyInHistory,
    #[error("Prerequisite work package not found")]
    PrerequisiteNotFound,
    #[error("Invalid code hash in work result")]
    InvalidCodeHash,
    #[error("Code hash not found for the service account")]
    CodeHashNotFound,
    #[error("Anchor block not found in recent block history")]
    AnchorBlockNotFound,
    #[error("Invalid anchor block")]
    InvalidAnchorBlock,
    #[error("Lookup anchor block timed out")]
    LookupAnchorBlockTimeout,
    #[error("Invalid number of guarantors, must be 2 or 3")]
    InvalidGuarantorCount,
    #[error("Credentials in guarantee must be sorted by the validator index")]
    CredentialsNotSorted,
    #[error("Duplicate guarantor entry found")]
    DuplicateGuarantor,

    // Preimages validation errors
    #[error("Preimage lookups must be sorted by service index")]
    PreimageLookupsNotSorted,
    #[error("Duplicate preimage lookup entry found")]
    DuplicatePreimageLookup,
    #[error("Preimage already integrated into the state")]
    PreimageAlreadyIntegrated,

    // Ticket validation errors
    #[error("The number of ticket entries exceeds the allowed tickets")]
    TicketsEntryLimitExceeded,
    #[error("Duplicate ticket found in accumulator")]
    DuplicateTicket,
    #[error("Ticket entries must be sorted by proof hash")]
    TicketsNotSorted,
    #[error("Invalid VRF proof for ticket entry")]
    InvalidTicketProof,
    #[error("Invalid ticket attempt number, must be 0 or 1")]
    InvalidTicketAttemptNumber,
    #[error("Ticket submission period has ended")]
    TicketSubmissionClosed,

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
