use crate::UnsignedGas;

/// JAM common era UNIX timestamp; 1200 UTC on January 1st, 2025.
pub const COMMON_ERA_TIMESTAMP: u64 = 1_735_732_800;

/// Size of Hash type in bytes.
pub const HASH_SIZE: usize = 32;

/// Size of validator public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 336;

/// `O`: The maximum number of items in the authorizations pool.
pub const MAX_AUTH_POOL_SIZE: usize = 8;

/// `Q`: The number of items in the authorizations queue.
pub const AUTH_QUEUE_SIZE: usize = 80;

/// `H`: The size of recent history, in blocks.
pub const BLOCK_HISTORY_LENGTH: usize = 8;

/// `U`: The period in timeslots after which reported but unavailable work may be replaced.
pub const PENDING_REPORT_TIMEOUT: usize = 5;

/// `L`: The maximum age in timeslots of the lookup anchor.
pub const MAX_LOOKUP_ANCHOR_AGE: usize = 14_400;

/// `J`: The maximum sum of dependency items in a work-report.
pub const MAX_REPORT_DEPENDENCIES: usize = 8;

/// `W_C`: The maximum size of service code in octets.
pub const MAX_SERVICE_CODE_SIZE: usize = 4_000_000;

/// `W_T`: The size of a transfer memo in octets.
pub const TRANSFER_MEMO_SIZE: usize = 128;

/// `W_R`: The maximum total size of all output blobs in a work-report, in octets.
pub const WORK_REPORT_OUTPUT_SIZE_LIMIT: usize = 48 * (1 << 10);

// --- Gas Limits

/// `G_A`: The gas allocated to invoke a work-report's Accumulation logic.
pub const ACCUMULATION_GAS_PER_CORE: UnsignedGas = 10_000_000;

/// `G_I`: The gas allocated to invoke a work-package's Is-Authorized logic.
pub const IS_AUTHORIZED_GAS_PER_WORK_PACKAGE: UnsignedGas = 50_000_000;

/// `G_R`: The gas allocated to invoke a work-package's Refine logic.
pub const REFINE_GAS_PER_WORK_PACKAGE: UnsignedGas = 5_000_000_000;

/// `G_T`: The total gas allocated across for all Accumulation.
pub const ACCUMULATION_GAS_ALL_CORES: UnsignedGas = 3_500_000_000;

// --- Signing Contexts

/// Signing context for Ed25519 Availability assurances.
pub const X_A: &[u8] = b"jam_available";

/// Signing context for BLS Accumulate-result-root MMR commitment.
pub const X_B: &[u8] = b"jam_beefy";

/// Signing context for on-chain entropy generation.
pub const X_E: &[u8] = b"jam_entropy";

/// Signing context for Bandersnatch Fallback block seal.
pub const X_F: &[u8] = b"jam_fallback_seal";

/// Signing context for Ed25519 Guarantee statements.
pub const X_G: &[u8] = b"jam_guarantee";

/// Signing context for Ed25519 Audit announcement statements.
pub const X_I: &[u8] = b"jam_announce";

/// Signing context for Bandersnatch RingVRF Ticket generation and regular block seal.
pub const X_T: &[u8] = b"jam_ticket_seal";

/// Signing context for Bandersnatch Audit selection entropy.
pub const X_U: &[u8] = b"jam_audit";

/// Signing context for Ed25519 Judgements for valid work-reports.
pub const X_1: &[u8] = b"jam_valid";

/// Signing context for Ed25519 Judgements for invalid work-reports.
pub const X_0: &[u8] = b"jam_invalid";
