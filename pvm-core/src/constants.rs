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
pub const PREIMAGE_EXPIRATION_PERIOD: u32 = 28_800;
pub const ERASURE_CHUNK_SIZE: usize = 684; // W_C
pub const DATA_SEGMENTS_CHUNKS: usize = 6; // W_S
pub const DATA_SEGMENTS_SIZE: usize = ERASURE_CHUNK_SIZE * DATA_SEGMENTS_CHUNKS; // W_C * W_S
pub const IMPORT_EXPORT_SEGMENTS_LENGTH_LIMIT: usize = 1 << 11; // W_M; Work package manifest size limit
