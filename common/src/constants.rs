// Constants

pub const COMMON_ERA_TIMESTAMP: u64 = 1704110400; // 1200 UTC on January 1, 2024
pub const SLOT_DURATION: u64 = 6; // 6 seconds per timeslot

#[cfg(not(feature = "testing"))]
pub const VALIDATOR_COUNT: usize = 1023; // 1023 validators
#[cfg(feature = "testing")]
pub const VALIDATOR_COUNT: usize = 6; // 6 validators (for tiny test vectors)
#[cfg(not(feature = "testing"))]
pub const EPOCH_LENGTH: usize = 600; // 600 timeslots per epoch
#[cfg(feature = "testing")]
pub const EPOCH_LENGTH: usize = 12; // 12 timeslots per epoch (for tiny test vectors)
pub const FLOOR_TWO_THIRDS_VALIDATOR_COUNT: usize = 2 * VALIDATOR_COUNT / 3; // 682 validators
pub const CORE_COUNT: usize = 341; // (1023 / 3 = 341) cores
#[cfg(not(feature = "testing"))]
pub const TICKET_SUBMISSION_DEADLINE_SLOT: usize = 500;
#[cfg(feature = "testing")]
pub const TICKET_SUBMISSION_DEADLINE_SLOT: usize = 10;

// Signing Contexts or Domain Specifiers

pub const X_A: &str = "jam_available"; // Ed25519 Availability assurances
pub const X_B: &str = "jam_beefy"; // BLS Accumulate-result-root MMR commitment
pub const X_E: &str = "jam_entropy"; // On-chain entropy generation
pub const X_F: &str = "jam_fallback_seal"; // Bandersnatch Fallback block seal
pub const X_G: &str = "jam_guarantee"; // Ed25519 Guarantee statements
pub const X_I: &str = "jam_announce"; // Ed25519 Audit announcement statements
pub const X_T: &str = "jam_ticket_seal"; // Bandersnatch RingVRF Ticket generation
pub const X_U: &str = "jam_audit"; // Bandersnatch Audit selection entropy
pub const X_1: &str = "jam_valid"; // Ed25519 Judgements for valid work-reports
pub const X_0: &str = "jam_invalid"; // Ed25519 Judgements for invalid work-reports
