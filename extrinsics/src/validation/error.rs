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
    #[error("Assurance entries length exceeds the number of validators")]
    TooManyAssurances,
    #[error("Submitted assurances must be ordered by the validator index")]
    AssurancesNotOrdered,
    #[error("Submitted assurances must have correct parent hash anchored to")]
    BadParentHash,
    #[error("Submitted assurances must have valid signatures")]
    BadAssuranceSignature,
    #[error("No pending report exists in the core {0}")]
    NoPendingReportInCore(CoreIndex),
    // Disputes validation errors
    #[error("All disputes entries must be ordered correctly")]
    DisputesNotOrdered,
    #[error("Duplicate verdict entry")]
    DuplicateVerdict,
    #[error("Duplicate culprit entry")]
    DuplicateCulprit,
    #[error("Duplicate fault entry")]
    DuplicateFault,
    #[error("Verdicts must not be present in any past disputes set")]
    VerdictsAlreadyIntroduces,
    #[error("All judgments in verdicts must be ordered by the validator index")]
    JudgmentsNotOrdered,
    #[error("Duplicate judgment entry")]
    DuplicateJudgment,
    #[error("All judgments must have valid signature signed by the voter")]
    BadJudgmentSignature,
    #[error("The guarantor didn't submit bad report")]
    NotCulprit,
    #[error("The voter didn't cast bad vote")]
    NotFault,
    #[error("The validator must be part of either the active set or the past set")]
    InvalidValidatorSet,
    #[error("Bad culprit signature")]
    BadCulpritSignature,
    #[error("Bad fault signature")]
    BadFaultSignature,
    // Guarantees validation errors
    #[error("Guarantee entries length exceeds the number of cores")]
    TooManyGuarantees,
    #[error("Submitted guarantees must be ordered by the core indices of work reports")]
    GuaranteesNotOrdered,
    #[error("Duplicate core indices found in the guarantees")]
    DuplicateCore,
    #[error("Duplicate work package hashes found in the guarantees")]
    DuplicateWorkPackages,
    #[error("Valid pending report exists assigned to the core")]
    PendingReportExists,
    #[error("Bad authorizer hash")]
    BadAuthorizerHash,
    #[error("Submitted work package is already in the history")]
    WorkPackageAlreadyInHistory,
    #[error("Prerequisite work package must exist either in the current extrinsic or in the recent history")]
    PrerequisiteNotFound,
    #[error("Code hash of the work result is invalid")]
    BadCodeHash,
    #[error("Code hash not found from the service account")]
    CodeHashNotFound,
    #[error("The anchor block must be found in the recent block history")]
    AnchorBlockNotFound,
    #[error("Invalid anchor block")]
    InvalidAnchorBlock,
    #[error("Lookup anchor block is timed out")]
    LookupAnchorBlockTimeout,
    #[error("Number of credentials of guarantee must be either 2 or 3")]
    CredentialsLengthMismatch,
    #[error("Credentials in guarantee must be ordered by the validator index")]
    CredentialsNotOrdered,
    #[error("Duplicate guarantors")]
    DuplicateGuarantors,
    // Preimages validation errors
    #[error("PreimageLookups must be ordered by the service index")]
    PreimageLookupsNotOrdered,
    #[error("Duplicate preimage lookups entry")]
    DuplicatePreimageLookups,
    #[error("Provided preimage is already integrated to the state")]
    PreimageAlreadyIntegrated,
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
