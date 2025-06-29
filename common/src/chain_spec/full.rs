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
