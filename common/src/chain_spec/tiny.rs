/// `V`: The total number of validators.
pub const VALIDATOR_COUNT: usize = 6;

/// `C`: The total number of cores.
pub const CORE_COUNT: usize = 2;

/// `P`: Length of a timeslot in seconds.
pub const SLOT_DURATION: u64 = 6;

/// `D`: The period in timeslots after which an unreferenced preimage may be expunged.
/// `PREIMAGE_EXPIRATION_PERIOD` = `MAX_LOOKUP_ANCHOR_AGE` + `8-hour buffer`
/// 
/// `D` = (full `PREIMAGE_EXPIRATION_PERIOD`) * (tiny EPOCH_LENGTH) / (full EPOCH_LENGTH) = 384
/// Note: "tiny" configuration has `D` = 384, but here set as 32 for testing purpose.
pub const PREIMAGE_EXPIRATION_PERIOD: u32 = 32;

/// `E`: The length of an epoch in timeslots.
pub const EPOCH_LENGTH: usize = 12;

/// `Y`: The number of slots into an epoch at which ticket-submission ends.
pub const TICKET_CONTEST_DURATION: usize = 10;

/// `N`: The number of ticket entries per validator.
pub const TICKETS_PER_VALIDATOR: u8 = 3;

/// `K`: The maximum number of tickets which may be submitted in a single extrinsic.
pub const MAX_TICKETS_PER_EXTRINSIC: usize = 3;

/// `R`: The guarantor rotation period in timeslots.
pub const GUARANTOR_ROTATION_PERIOD: usize = 4;
