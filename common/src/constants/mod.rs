use crate::{
    Balance, ServiceId, UnsignedGas, DATA_SEGMENTS_CHUNKS, ERASURE_CHUNK_SIZE, VALIDATOR_COUNT,
};

pub mod constants_encoder;

// --- Derived values from `VALIDATOR_COUNT`.
pub const FLOOR_ONE_THIRDS_VALIDATOR_COUNT: usize = VALIDATOR_COUNT / 3;
pub const FLOOR_TWO_THIRDS_VALIDATOR_COUNT: usize = 2 * VALIDATOR_COUNT / 3;
pub const VALIDATORS_SUPER_MAJORITY: usize = FLOOR_TWO_THIRDS_VALIDATOR_COUNT + 1;

/// JAM common era UNIX timestamp; 1200 UTC on January 1st, 2025.
pub const COMMON_ERA_TIMESTAMP: u64 = 1_735_732_800;

/// JAM common era UNIX timestamp in millis.
pub const COMMON_ERA_TIMESTAMP_MILLIS: u64 = COMMON_ERA_TIMESTAMP * 1_000;

/// Service Account Version.
pub const SERVICE_ACCOUNT_VERSION: u8 = 0;

/// Size of Hash type in octets.
pub const HASH_SIZE: usize = 32;

/// Size of JAM state keys in octets.
pub const STATE_KEY_SIZE: usize = 31;

/// Size of validator public key in octets.
pub const PUBLIC_KEY_SIZE: usize = 336;

/// `O`: The maximum number of items in the authorizations pool.
pub const MAX_AUTH_POOL_SIZE: usize = 8;

/// `Q`: The number of items in the authorizations queue.
pub const AUTH_QUEUE_SIZE: usize = 80;

/// `S`: The minimum public service index. Services of indices below these may only be created by the Registrar.
pub const MIN_PUBLIC_SERVICE_ID: ServiceId = 1 << 16;

/// `H`: The size of recent history, in blocks.
pub const BLOCK_HISTORY_LENGTH: usize = 8;

/// `I`: The maximum amount of work items in a package.
pub const MAX_WORK_ITEMS_PER_PACKAGE: usize = 16;

/// `J`: The maximum sum of dependency items in a work-report.
pub const MAX_REPORT_DEPENDENCIES: usize = 8;

/// `U`: The period in timeslots after which reported but unavailable work may be replaced.
pub const PENDING_REPORT_TIMEOUT: usize = 5;

/// `T`: The maximum number of extrinsics in a work-package.
pub const MAX_EXTRINSICS_PER_PACKAGE: usize = 128;

// --- Audit Param Constants

/// `A`: The period, in seconds, between audit tranches.
pub const AUDIT_TRANCHE_PERIOD: u32 = 8;

/// `F`: The audit bias factor, the expected number of additional validators who will audit
/// a work-report in the following tranche for each no-show in the previous.
pub const AUDIT_BIAS_FACTOR: usize = 2;

// --- Service Account Balance Requirements

/// `B_I`: The additional minimum balance required per item of elective service state.
pub const MIN_BALANCE_PER_ITEM: Balance = 10;

/// `B_L`: The additional minimum balance required per octet of elective service state.
pub const MIN_BALANCE_PER_OCTET: Balance = 1;

/// `B_S`: The basic minimum balance which all services require.
pub const MIN_BASIC_BALANCE: Balance = 100;

// --- Gas Limits

/// `G_A`: The gas allocated to invoke a work-report's Accumulation logic.
pub const ACCUMULATION_GAS_PER_CORE: UnsignedGas = 10_000_000;

/// `G_I`: The gas allocated to invoke a work-package's Is-Authorized logic.
pub const IS_AUTHORIZED_GAS_PER_WORK_PACKAGE: UnsignedGas = 50_000_000;

// --- Data Size Limits

/// `W_A`: The maximum size of is-authorized code in octets.
pub const MAX_IS_AUTHORIZED_CODE_SIZE: usize = 64_000;

/// `W_B`: The maximum size of the concatenated variable-size blobs, extrinsics and imported segments of
/// a work-package, in octets.
///
/// `W_B` = `W_M` * (`W_G` + 1 + (32 * ceil(log2(`W_T`)))) + 4096 + 1
pub const MAX_PACKAGE_AND_DATA_SIZE: usize = 13_791_360;

/// `W_C`: The maximum size of service code in octets.
pub const MAX_SERVICE_CODE_SIZE: usize = 4_000_000;

/// `W_F`: The additional footprint in the Audits DA of a single imported segment.
///
/// `W_F` = `W_G` + 32 * ceil(log2(`W_M`))
pub const AUDIT_DA_IMPORT_FOOTPRINT: usize = 4_488;

/// `W_G`: Data segment size (`W_E` * `W_P`).
pub const SEGMENT_SIZE: usize = ERASURE_CHUNK_SIZE * DATA_SEGMENTS_CHUNKS;

/// `W_M`: The maximum number of imports in a work-package.
pub const MAX_IMPORTS_PER_PACKAGE: usize = 3_072;

/// `W_R`: The maximum total size of all unbounded blobs in a work-report, in octets.
pub const WORK_REPORT_OUTPUT_SIZE_LIMIT: usize = 48 * (1 << 10);

/// `W_T`: The size of a transfer memo in octets.
pub const TRANSFER_MEMO_SIZE: usize = 128;

/// `W_X`: The maximum number of exports in a work-package.
pub const MAX_EXPORTS_PER_PACKAGE: usize = 3_072;

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
