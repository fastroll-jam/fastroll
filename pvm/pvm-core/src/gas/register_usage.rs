//! Registers of the gas cost model (`š` and `ř` of the GP).

use crate::{
    program::instruction::{opcode::Opcode, Instruction},
    state::vm_state::RegIndex,
};
use std::ops::{BitOr, Sub};

/// Set of PVM registers used by the gas cost model to find dependencies between instructions.
///
/// Bit `i` stands for the 0-based register index `i`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RegisterSet(u16);

impl RegisterSet {
    pub const EMPTY: Self = Self(0);

    fn from_registers(registers: &[Option<RegIndex>]) -> Self {
        registers
            .iter()
            .flatten()
            .fold(Self::EMPTY, |set, &register| Self(set.0 | 1 << register))
    }

    pub fn intersects(&self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}

impl BitOr for RegisterSet {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl Sub for RegisterSet {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

/// Registers that an instruction reads and writes, regardless of whether it writes them at runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterUsage {
    /// `š`: Registers the instruction reads
    pub source_registers: RegisterSet,
    /// `ř`: Registers the instruction writes
    pub destination_registers: RegisterSet,
}

impl RegisterUsage {
    fn new(
        source_registers: &[Option<RegIndex>],
        destination_registers: &[Option<RegIndex>],
    ) -> Self {
        Self {
            source_registers: RegisterSet::from_registers(source_registers),
            destination_registers: RegisterSet::from_registers(destination_registers),
        }
    }
}

impl Instruction {
    /// Returns the registers that the instruction reads (`š`) and writes (`ř`).
    ///
    /// `ecalli` reads and writes none.
    /// The destination of `cmov_iz`, `cmov_nz`, `cmov_iz_imm` and `cmov_nz_imm` is also a source.
    /// The decoded fields hold the GP registers per group, e.g. `rs1` is `r_A` and `rd` is `r_D`.
    pub fn register_usage(&self) -> RegisterUsage {
        use Opcode::*;
        let (r_a, r_b, r_d) = (self.rs1, self.rs2, self.rd);
        match self.op {
            // Group 1, 2, 4 and 5: no registers
            TRAP | FALLTHROUGH | UNLIKELY | ECALLI | STORE_IMM_U8 | STORE_IMM_U16
            | STORE_IMM_U32 | STORE_IMM_U64 | JUMP => RegisterUsage::new(&[], &[]),

            // Group 3: one register and one extended width immediate
            LOAD_IMM_64 => RegisterUsage::new(&[], &[r_a]),

            // Group 6: one register and one immediate
            JUMP_IND | STORE_U8 | STORE_U16 | STORE_U32 | STORE_U64 => {
                RegisterUsage::new(&[r_a], &[])
            }
            LOAD_IMM | LOAD_U8 | LOAD_I8 | LOAD_U16 | LOAD_I16 | LOAD_U32 | LOAD_I32 | LOAD_U64 => {
                RegisterUsage::new(&[], &[r_a])
            }

            // Group 7: one register and two immediates
            STORE_IMM_IND_U8 | STORE_IMM_IND_U16 | STORE_IMM_IND_U32 | STORE_IMM_IND_U64 => {
                RegisterUsage::new(&[r_a], &[])
            }

            // Group 8: one register, one immediate and one offset
            LOAD_IMM_JUMP => RegisterUsage::new(&[], &[r_a]),
            BRANCH_EQ_IMM | BRANCH_NE_IMM | BRANCH_LT_U_IMM | BRANCH_LE_U_IMM | BRANCH_GE_U_IMM
            | BRANCH_GT_U_IMM | BRANCH_LT_S_IMM | BRANCH_LE_S_IMM | BRANCH_GE_S_IMM
            | BRANCH_GT_S_IMM => RegisterUsage::new(&[r_a], &[]),

            // Group 9: two registers
            MOVE_REG
            | COUNT_SET_BITS_64
            | COUNT_SET_BITS_32
            | LEADING_ZERO_BITS_64
            | LEADING_ZERO_BITS_32
            | TRAILING_ZERO_BITS_64
            | TRAILING_ZERO_BITS_32
            | SIGN_EXTEND_8
            | SIGN_EXTEND_16
            | ZERO_EXTEND_16
            | REVERSE_BYTES => RegisterUsage::new(&[r_a], &[r_d]),

            // Group 10: two registers and one immediate
            STORE_IND_U8 | STORE_IND_U16 | STORE_IND_U32 | STORE_IND_U64 => {
                RegisterUsage::new(&[r_a, r_b], &[])
            }
            CMOV_IZ_IMM | CMOV_NZ_IMM => RegisterUsage::new(&[r_a, r_b], &[r_a]),
            LOAD_IND_U8 | LOAD_IND_I8 | LOAD_IND_U16 | LOAD_IND_I16 | LOAD_IND_U32
            | LOAD_IND_I32 | LOAD_IND_U64 | ADD_IMM_32 | AND_IMM | XOR_IMM | OR_IMM
            | MUL_IMM_32 | SET_LT_U_IMM | SET_LT_S_IMM | SHLO_L_IMM_32 | SHLO_R_IMM_32
            | SHAR_R_IMM_32 | NEG_ADD_IMM_32 | SET_GT_U_IMM | SET_GT_S_IMM | SHLO_L_IMM_ALT_32
            | SHLO_R_IMM_ALT_32 | SHAR_R_IMM_ALT_32 | ADD_IMM_64 | MUL_IMM_64 | SHLO_L_IMM_64
            | SHLO_R_IMM_64 | SHAR_R_IMM_64 | NEG_ADD_IMM_64 | SHLO_L_IMM_ALT_64
            | SHLO_R_IMM_ALT_64 | SHAR_R_IMM_ALT_64 | ROT_R_64_IMM | ROT_R_64_IMM_ALT
            | ROT_R_32_IMM | ROT_R_32_IMM_ALT => RegisterUsage::new(&[r_b], &[r_a]),

            // Group 11: two registers and one offset
            BRANCH_EQ | BRANCH_NE | BRANCH_LT_U | BRANCH_LT_S | BRANCH_GE_U | BRANCH_GE_S => {
                RegisterUsage::new(&[r_a, r_b], &[])
            }

            // Group 12: two registers and two immediates
            LOAD_IMM_JUMP_IND => RegisterUsage::new(&[r_b], &[r_a]),

            // Group 13: three registers
            CMOV_IZ | CMOV_NZ => RegisterUsage::new(&[r_a, r_b, r_d], &[r_d]),
            ADD_32 | SUB_32 | MUL_32 | DIV_U_32 | DIV_S_32 | REM_U_32 | REM_S_32 | SHLO_L_32
            | SHLO_R_32 | SHAR_R_32 | ADD_64 | SUB_64 | MUL_64 | DIV_U_64 | DIV_S_64 | REM_U_64
            | REM_S_64 | SHLO_L_64 | SHLO_R_64 | SHAR_R_64 | AND | XOR | OR | MUL_UPPER_S_S
            | MUL_UPPER_U_U | MUL_UPPER_S_U | SET_LT_U | SET_LT_S | ROT_L_64 | ROT_L_32
            | ROT_R_64 | ROT_R_32 | AND_INV | OR_INV | XNOR | MAX | MAX_U | MIN | MIN_U => {
                RegisterUsage::new(&[r_a, r_b], &[r_d])
            }
        }
    }
}
