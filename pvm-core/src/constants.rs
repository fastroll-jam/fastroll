use rjam_common::UnsignedGas;

pub const BASE_GAS_USAGE: UnsignedGas = 10;
pub const REGISTERS_COUNT: usize = 13;
pub const HOST_CALL_INPUT_REGISTERS_COUNT: usize = 13;
pub const HOST_CALL_OUTPUT_REGISTERS_COUNT: usize = 13;
pub const MEMORY_SIZE: usize = u32::MAX as usize;
pub const PAGE_SIZE: usize = 1 << 14; // Z_P; 16KB page size
pub const REGION_SIZE: usize = 1 << 16; // Z_Q; 64KB memory region size
pub const INIT_SIZE: usize = 1 << 24; // Z_I; reserved region for initialization
pub const STANDARD_PROGRAM_SIZE_LIMIT: usize = 1 << 32;
pub const JUMP_ALIGNMENT: usize = 2; // Z_A
pub const PREIMAGE_EXPIRATION_PERIOD: u32 = 28_800;
pub const ERASURE_CHUNK_SIZE: usize = 684; // W_C
pub const DATA_SEGMENTS_CHUNKS: usize = 6; // W_S
pub const DATA_SEGMENTS_SIZE: usize = ERASURE_CHUNK_SIZE * DATA_SEGMENTS_CHUNKS; // W_C * W_S
