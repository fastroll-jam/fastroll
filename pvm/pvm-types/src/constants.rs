//! PVM-specific constants
use crate::common::RegValue;
use fr_common::UnsignedGas;

/// Maximum skip distance.
pub const MAX_SKIP_DISTANCE: usize = 24;

/// Maximum length of a single instruction in octets.
pub const MAX_INST_BLOB_LENGTH: usize = 16;

/// Base gas charge for host function execution.
pub const HOSTCALL_BASE_GAS_CHARGE: UnsignedGas = 10;

/// Base gas charge for a single instruction.
pub const INST_BASE_GAS_CHARGE: UnsignedGas = 1;

/// The number of PVM registers.
pub const REGISTERS_COUNT: usize = 13;

/// PVM memory size in octets.
pub const MEMORY_SIZE: usize = 1 << 32;

/// The standard PVM program size limit in octets.
pub const STANDARD_PROGRAM_SIZE_LIMIT: usize = 1 << 32;

/// `Z_A`: The PVM dynamic address alignment factor.
pub const JUMP_ALIGNMENT: usize = 2;

/// `Z_I`: The standard PVM program initialization input data size in octets.
pub const INIT_INPUT_SIZE: usize = 1 << 24;

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

/// Initial program counter value for `on_transfer` invocation.
pub const ON_TRANSFER_INITIAL_PC: RegValue = 10;
