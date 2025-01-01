use crate::UnsignedGas;

pub const HASH_SIZE: usize = 32; // 32-byte hash
pub const PUBLIC_KEY_SIZE: usize = 336; // 336-byte validator public key
pub const COMMON_ERA_TIMESTAMP: u64 = 1_735_732_800; // 1200 UTC on January 1, 2025
pub const SLOT_DURATION: u64 = 6; // P; 6 seconds per timeslot

#[cfg(not(feature = "testing"))]
pub const VALIDATOR_COUNT: usize = 1023; // V; 1023 validators
#[cfg(feature = "testing")]
pub const VALIDATOR_COUNT: usize = 6; // 6 validators (for tiny test vectors)
#[cfg(not(feature = "testing"))]
pub const EPOCH_LENGTH: usize = 600; // E; 600 timeslots per epoch
#[cfg(feature = "testing")]
pub const EPOCH_LENGTH: usize = 12; // 12 timeslots per epoch (for tiny test vectors)
pub const FLOOR_ONE_THIRDS_VALIDATOR_COUNT: usize = VALIDATOR_COUNT / 3;
pub const FLOOR_TWO_THIRDS_VALIDATOR_COUNT: usize = 2 * VALIDATOR_COUNT / 3; // 682 validators
pub const VALIDATORS_SUPER_MAJORITY: usize = FLOOR_TWO_THIRDS_VALIDATOR_COUNT + 1;
#[cfg(not(feature = "testing"))]
pub const GUARANTOR_ROTATION_PERIOD: usize = 10; // 10 timeslots
#[cfg(feature = "testing")]
pub const GUARANTOR_ROTATION_PERIOD: usize = 4; // 4 timeslots (for tiny test vectors)

#[cfg(not(feature = "testing"))]
pub const CORE_COUNT: usize = 341; // C
#[cfg(feature = "testing")]
pub const CORE_COUNT: usize = 2; // 2 cores (for tiny test vectors)
#[cfg(not(feature = "testing"))]
pub const TICKET_SUBMISSION_DEADLINE_SLOT: usize = 500; // Y
#[cfg(feature = "testing")]
pub const TICKET_SUBMISSION_DEADLINE_SLOT: usize = 10;
#[cfg(not(feature = "testing"))]
pub const MAX_TICKETS_PER_VALIDATOR: u8 = 2;
#[cfg(feature = "testing")]
pub const MAX_TICKETS_PER_VALIDATOR: u8 = 3; // (for tiny vectors)
pub const MAX_AUTH_POOL_SIZE: usize = 8; // O
pub const MAX_AUTH_QUEUE_SIZE: usize = 80; // Q
pub const MAX_SERVICE_CODE_SIZE: usize = 4_000_000; // W_C
pub const TRANSFER_MEMO_SIZE: usize = 128; // W_T
pub const BLOCK_HISTORY_LENGTH: usize = 8; // H
pub const PENDING_REPORT_TIMEOUT: usize = 5; // U
pub const MAX_LOOKUP_ANCHOR_AGE: usize = 14_400; // L
pub const MAX_TICKETS_PER_EXTRINSIC: usize = 16; // K
pub const MAX_REPORT_DEPENDENCIES: usize = 8; // J
pub const WORK_REPORT_OUTPUT_SIZE_LIMIT: usize = 48 * (1 << 10);

// PVM Gas Allocations
pub const ACCUMULATION_GAS_PER_CORE: UnsignedGas = 10_000_000; // G_A
pub const ACCUMULATION_GAS_ALL_CORES: UnsignedGas = 3_500_000_000; // G_T
pub const IS_AUTHORIZED_GAS_PER_WORK_PACKAGE: UnsignedGas = 50_000_000; // G_I
pub const REFINE_GAS_PER_WORK_PACKAGE: UnsignedGas = 5_000_000_000; // G_R

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
