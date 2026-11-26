//! PVM-specific constants
use crate::common::RegValue;

/// Maximum skip distance.
pub const MAX_SKIP_DISTANCE: usize = 24;

/// Maximum length of a single instruction in octets.
pub const MAX_INST_BLOB_LENGTH: usize = 16;

/// Maximum size `z` of a dynamic jump table entry in a PVM program blob, in octets.
pub const MAX_JUMP_TABLE_ENTRY_SIZE: usize = 4;

/// The number of PVM registers.
pub const REGISTERS_COUNT: usize = 13;

/// PVM memory size in octets.
pub const MEMORY_SIZE: usize = 1 << 32;

/// The standard PVM program size limit in octets.
pub const STANDARD_PROGRAM_SIZE_LIMIT: usize = 1 << 32;

/// Maximum number of inner PVM instances that a refine invocation holds at once.
pub const MAX_INNER_PVM_INSTANCES: usize = 63;

/// `Z_A`: The PVM dynamic address alignment factor.
pub const JUMP_ALIGNMENT: usize = 2;

/// `Z_C`: The maximum size of the instruction data `c` of a PVM program blob, in octets.
pub const MAX_INSTRUCTION_DATA_SIZE: usize = 1 << 25;

/// `Z_I`: The standard PVM program initialization input data size in octets.
pub const INIT_INPUT_SIZE: usize = 1 << 24;

/// `Z_J`: The maximum number of entries in the dynamic jump table `j` of a PVM program blob.
pub const MAX_JUMP_TABLE_ENTRY_COUNT: usize = 1 << 24;

/// `Z_P`: PVM memory page size.
pub const PAGE_SIZE: usize = 1 << 12;

/// `Z_Z`: The standard PVM program initialization zone size in octets.
pub const INIT_ZONE_SIZE: usize = 1 << 16;

/// Initial program counter value for `is_authorized` invocation.
pub const IS_AUTHORIZED_INITIAL_PC: RegValue = 0;

/// Initial program counter value for `refine` invocation.
pub const REFINE_INITIAL_PC: RegValue = 0;

/// Initial program counter value for `accumulate` invocation.
pub const ACCUMULATE_INITIAL_PC: RegValue = 5;
