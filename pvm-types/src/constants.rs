pub const REGISTERS_COUNT: usize = 13;
pub const MEMORY_SIZE: usize = u32::MAX as usize;
pub const PAGE_SIZE: usize = 1 << 14; // Z_P; 16KB page size
pub const SEGMENT_SIZE: usize = 1 << 16; // Z_Q
pub const INPUT_SIZE: usize = 1 << 24; // Z_I
pub const STANDARD_PROGRAM_SIZE_LIMIT: usize = u32::MAX as usize;
pub const JUMP_ALIGNMENT: usize = 2; // Z_A
