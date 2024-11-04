use ark_ec_vrfs::prelude::ark_serialize::SerializationError;
use rjam_codec::JamCodecError;
use rjam_common::{Address, CoreIndex, ValidatorIndex};
use rjam_crypto::CryptoError;
use rjam_state::StateManagerError;
use rjam_types::common::workloads::WorkReportError;
use thiserror::Error;

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Error)]
pub enum ExtrinsicValidationError {
    // Assurances validation errors
    #[error("The number of assurance entries ({0}) exceeds the allowed validator count ({1})")]
    AssurancesEntryLimitExceeded(usize, usize),
    #[error("Assurance entries must be sorted by validator index")]
    AssurancesNotSorted,
    #[error("Invalid parent hash for assurance entry submitted: Extrinsic: {0}, Header: {1}. Assurer: {2}")]
    InvalidAssuranceParentHash(String, String, ValidatorIndex),
    #[error("Invalid assurance signature. Assurer: {0}")]
    InvalidAssuranceSignature(ValidatorIndex),
    #[error("No pending report found for core {0}. Assurer: {1}")]
    NoPendingReportForCore(CoreIndex, ValidatorIndex),

    // Disputes validation errors
    #[error("Verdict entry already exists in past dispute sets")]
    VerdictAlreadyExists,
    #[error("Verdicts entries must be sorted correctly")]
    VerdictsNotSorted,
    #[error("Judgments must be sorted by validator index")]
    JudgmentsNotSorted,
    #[error("Culprits entries must be sorted correctly")]
    CulpritsNotSorted,
    #[error("Faults entries must be sorted correctly")]
    FaultsNotSorted,
    #[error("Duplicate verdict entry found")]
    DuplicateVerdict,
    #[error("Duplicate judgment entry found")]
    DuplicateJudgment,
    #[error("Duplicate culprit entry found")]
    DuplicateCulprit,
    #[error("Duplicate fault entry found")]
    DuplicateFault,
    #[error("Validator was not a culprit. Validator Ed25519 key: {0}")]
    NotCulprit(String),
    #[error("Validator did not cast a faulty vote. Voter: {0}")]
    NotFault(String),
    #[error("Verdicts with all negative votes must have at least two culprits for the corresponding work report. Work report hash: {0}")]
    NotEnoughCulprit(String),
    #[error("Verdicts with all positive votes must have at least one fault for the corresponding work report. Work report hash: {0}")]
    NotEnoughFault(String),
    #[error(
        "Culprit is already in the punish set of the disputes state. Validator Ed25519 key: {0}"
    )]
    CulpritAlreadyReported(String),
    #[error(
        "Fault is already in the punish set of the disputes state. Validator Ed25519 key: {0}"
    )]
    FaultAlreadyReported(String),
    #[error("Validator is not part of the active or past set. Validator Ed25519 key: {0}")]
    InvalidValidatorSet(String),
    #[error("Epoch index of the verdict is older than the previous epoch. Epoch index: {0}, Current epoch index: {1}")]
    InvalidJudgmentsAge(u32, u32),
    #[error("Report hash of culprit entry is not found in the extrinsic verdicts. Validator Ed25519 key: {0}")]
    InvalidCulpritReportHash(String),
    #[error("Report hash of fault entry is not found in the extrinsic verdicts. Validator Ed25519 key: {0}")]
    InvalidFaultReportHash(String),
    #[error("Positive votes count must be one of the following: 0, `FLOOR_ONE_THIRDS_VALIDATOR_COUNT`, or `VALIDATORS_SUPER_MAJORITY`. Provided: {0}.")]
    InvalidVotesCount(usize),
    #[error("Invalid signature for judgment. Voter validator index: {0}")]
    InvalidJudgmentSignature(ValidatorIndex),
    #[error("Invalid culprit signature. Validator Ed25519 key: {0}")]
    InvalidCulpritSignature(String),
    #[error("Invalid fault signature. Validator Ed25519 key: {0}")]
    InvalidFaultSignature(String),

    // Guarantees validation errors
    #[error("The number of guarantee entries ({0}) exceeds the allowed core count ({1})")]
    GuaranteesEntryLimitExceeded(usize, usize),
    #[error("Guarantee entries must be sorted by core index")]
    GuaranteesNotSorted,
    #[error("Duplicate core index found in guarantees")]
    DuplicateCoreIndex,
    #[error("Duplicate work package hashes found in guarantees")]
    DuplicateWorkPackageHash,
    #[error("Duplicate guarantor entry found")]
    DuplicateGuarantor,
    #[error("Pending report exists for the core {0}.")]
    PendingReportExists(CoreIndex),
    #[error("Invalid authorizer hash in work report. Core index: {0}")]
    InvalidAuthorizerHash(CoreIndex),
    #[error("Work package hash already exists in block history. Core index: {0}, Work package hash: {1}")]
    WorkPackageAlreadyInHistory(CoreIndex, String),
    #[error("Prerequisite work package not found. Core index: {0}, Work package hash: {1}")]
    PrerequisiteNotFound(CoreIndex, String),
    #[error("Invalid code hash in work result. Core index: {0}, Service index: {1}, Provided code hash: {2}")]
    InvalidCodeHash(CoreIndex, Address, String),
    #[error("Code hash not found for the service account. Core index: {0}, Service index: {1}, Provided code hash: {2}")]
    CodeHashNotFound(CoreIndex, Address, String),
    #[error("Anchor block not found in recent history. Core index: {0}, Provided block hash: {1}")]
    AnchorBlockNotFound(CoreIndex, String),
    #[error("Invalid anchor block. Core index: {0}, Provided anchor hash: {1}")]
    InvalidAnchorBlock(CoreIndex, String),
    #[error("Lookup anchor block timed out. Core index: {0}, Provided lookup anchor hash: {1}")]
    LookupAnchorBlockTimeout(CoreIndex, String),
    #[error("Invalid number of guarantors ({0}), must be 2 or 3. Core index: {1}")]
    InvalidGuarantorCount(usize, CoreIndex),
    #[error("Credentials in guarantee must be sorted by the validator index. Core index: {0}")]
    CredentialsNotSorted(CoreIndex),

    // Preimages validation errors
    #[error("Preimage lookups must be sorted by service index")]
    PreimageLookupsNotSorted,
    #[error("Duplicate preimage lookup entry found")]
    DuplicatePreimageLookup,
    #[error("Preimage already integrated into the state. Service index: {0}")]
    PreimageAlreadyIntegrated(Address),

    // Ticket validation errors
    #[error("The number of ticket entries ({0}) exceeds the allowed tickets ({1})")]
    TicketsEntryLimitExceeded(usize, usize),
    #[error("Duplicate ticket found in accumulator")]
    DuplicateTicket,
    #[error("Ticket entries must be sorted by proof hash")]
    TicketsNotSorted,
    #[error("Invalid VRF proof for ticket entry. Proof: {0}")]
    InvalidTicketProof(String),
    #[error("Invalid ticket attempt number ({0}), must be 0 or 1")]
    InvalidTicketAttemptNumber(u8),
    #[error("Ticket submission period has ended. Current slot phase: {0}")]
    TicketSubmissionClosed(u32),

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
