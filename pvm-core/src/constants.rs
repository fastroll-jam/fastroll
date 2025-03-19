use rjam_common::UnsignedGas;

pub const BASE_GAS_CHARGE: UnsignedGas = 10;

pub const REGISTERS_COUNT: usize = 13;

/// PVM memory size (4GB)
pub const MEMORY_SIZE: usize = 1 << 32;

/// The standard PVM program size limit (4GB)
pub const STANDARD_PROGRAM_SIZE_LIMIT: usize = 1 << 32;

/// `Z_A`: The PVM dynamic address alignment factor (2)
pub const JUMP_ALIGNMENT: usize = 2;

/// `Z_I`: The standard PVM program initialization input data size (16MB)
pub const INIT_INPUT_SIZE: usize = 1 << 24;

/// `Z_P`: PVM memory page size (4KB)
pub const PAGE_SIZE: usize = 1 << 12;

/// `Z_Z`: The standard PVM program initialization zone size (64KB)
pub const INIT_ZONE_SIZE: usize = 1 << 16;

/// `D`: The period in timeslots after which an unreferenced preimage may be expunged.
pub const PREIMAGE_EXPIRATION_PERIOD: u32 = 19_200;

/// `W_E`: Erasure coding basic chunk size in octets
pub const ERASURE_CHUNK_SIZE: usize = 684;

/// `W_P`: The number of erasure-coded pieces in a segment
pub const DATA_SEGMENTS_CHUNKS: usize = 6;

/// `W_G`: Data segment size (`W_E` * `W_P`)
pub const SEGMENT_SIZE: usize = ERASURE_CHUNK_SIZE * DATA_SEGMENTS_CHUNKS;

/// `W_M`: Work package manifest size limit
pub const WORK_PACKAGE_MANIFEST_SIZE_LIMIT: usize = 1 << 11;
