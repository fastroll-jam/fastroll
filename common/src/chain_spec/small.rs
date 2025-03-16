/// `V`: The total number of validators.
pub const VALIDATOR_COUNT: usize = 24;
pub const FLOOR_ONE_THIRDS_VALIDATOR_COUNT: usize = VALIDATOR_COUNT / 3;
pub const FLOOR_TWO_THIRDS_VALIDATOR_COUNT: usize = 2 * VALIDATOR_COUNT / 3;
pub const VALIDATORS_SUPER_MAJORITY: usize = FLOOR_TWO_THIRDS_VALIDATOR_COUNT + 1;

/// `C`: The total number of cores.
pub const CORE_COUNT: usize = 8;

/// `P`: Length of a timeslot in seconds.
pub const SLOT_DURATION: u64 = 6;

/// `E`: The length of an epoch in timeslots.
pub const EPOCH_LENGTH: usize = 36;

/// `Y`: The number of slots into an epoch at which ticket-submission ends.
pub const TICKET_CONTEST_DURATION: usize = 30;

/// `N`: The number of ticket entries per validator.
pub const TICKETS_PER_VALIDATOR: u8 = 3;

/// `K`: The maximum number of tickets which may be submitted in a single extrinsic.
pub const MAX_TICKETS_PER_EXTRINSIC: usize = 3;

/// The guarantor rotation period in timeslots.
pub const GUARANTOR_ROTATION_PERIOD: usize = 4;
