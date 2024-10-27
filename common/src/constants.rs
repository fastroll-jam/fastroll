pub const HASH_SIZE: usize = 32; // 32-byte hash
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
pub const CORE_COUNT: usize = 341;
#[cfg(not(feature = "testing"))]
pub const TICKET_SUBMISSION_DEADLINE_SLOT: usize = 500;
#[cfg(feature = "testing")]
pub const TICKET_SUBMISSION_DEADLINE_SLOT: usize = 10;
pub const MAX_AUTH_POOL_SIZE: usize = 8;
pub const MAX_AUTH_QUEUE_SIZE: usize = 80;
pub const MAX_SERVICE_CODE_SIZE: usize = 4_000_000;
pub const TRANSFER_MEMO_SIZE: usize = 128;
pub const BLOCK_HISTORY_LENGTH: usize = 8;

// Signing Contexts or Domain Specifiers
pub const X_A: &[u8] = b"jam_available"; // Ed25519 Availability assurances
pub const X_B: &[u8] = b"jam_beefy"; // BLS Accumulate-result-root MMR commitment
pub const X_E: &[u8] = b"jam_entropy"; // On-chain entropy generation
pub const X_F: &[u8] = b"jam_fallback_seal"; // Bandersnatch Fallback block seal
pub const X_G: &[u8] = b"jam_guarantee"; // Ed25519 Guarantee statements
pub const X_I: &[u8] = b"jam_announce"; // Ed25519 Audit announcement statements
pub const X_T: &[u8] = b"jam_ticket_seal"; // Bandersnatch RingVRF Ticket generation
pub const X_U: &[u8] = b"jam_audit"; // Bandersnatch Audit selection entropy
pub const X_1: &[u8] = b"jam_valid"; // Ed25519 Judgements for valid work-reports
pub const X_0: &[u8] = b"jam_invalid"; // Ed25519 Judgements for invalid work-reports
