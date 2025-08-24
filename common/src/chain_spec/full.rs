use crate::UnsignedGas;

/// `V`: The total number of validators.
pub const VALIDATOR_COUNT: usize = 1_023;

/// `C`: The total number of cores.
pub const CORE_COUNT: usize = 341;

/// `P`: Length of a timeslot in seconds.
pub const SLOT_DURATION: u64 = 6;

/// `D`: The period in timeslots after which an unreferenced preimage may be expunged.
/// `PREIMAGE_EXPIRATION_PERIOD` = `MAX_LOOKUP_ANCHOR_AGE` + `8-hour buffer`
pub const PREIMAGE_EXPIRATION_PERIOD: u32 = 19_200;

/// `E`: The length of an epoch in timeslots.
pub const EPOCH_LENGTH: usize = 600;

/// `Y`: The number of slots into an epoch at which ticket-submission ends.
pub const TICKET_CONTEST_DURATION: usize = 500;

/// `N`: The number of ticket entries per validator.
pub const TICKETS_PER_VALIDATOR: u8 = 2;

/// `K`: The maximum number of tickets which may be submitted in a single extrinsic.
pub const MAX_TICKETS_PER_EXTRINSIC: usize = 16;

/// `R`: The guarantor rotation period in timeslots.
pub const GUARANTOR_ROTATION_PERIOD: usize = 10;

/// `G_R`: The gas allocated to invoke a work-package's Refine logic.
pub const REFINE_GAS_PER_WORK_PACKAGE: UnsignedGas = 5_000_000_000;

/// `G_T`: The total gas allocated across for all Accumulation.
pub const ACCUMULATION_GAS_ALL_CORES: UnsignedGas = 3_500_000_000;

/// The total number of symbols in a codeword (message + recovery symbols) in erasure codec.
/// For `k:n` reed-solomon rate, this is `n`.
pub const ERASURE_CODE_TOTAL_CHUNKS: usize = VALIDATOR_COUNT;

/// The number of original message symbols. For `k:n` reed-solomon rate, this is `k`.
pub const ERASURE_CODE_MESSAGE_CHUNKS: usize = 342;
