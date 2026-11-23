//! Per-instruction costs of the gas cost model.

use crate::{
    gas::register_usage::RegisterUsage,
    interpreter::Interpreter,
    program::{
        instruction::{opcode::Opcode, Instruction},
        types::program_state::ProgramState,
    },
};
use fr_pvm_types::common::RegValue;
use std::ops::{Add, Sub};

/// Counts of the five virtual CPU execution units (`𝔼`), used both as a requirement and as availability.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExecutionUnits {
    /// `A`
    pub arithmetic_logic: u8,
    /// `L`
    pub load: u8,
    /// `S`
    pub store: u8,
    /// `M`
    pub multiply: u8,
    /// `D`
    pub divide: u8,
}

impl ExecutionUnits {
    pub const NONE: Self = Self::new(0, 0, 0, 0, 0);
    const ARITHMETIC_LOGIC: Self = Self::new(1, 0, 0, 0, 0);
    const TWO_ARITHMETIC_LOGIC: Self = Self::new(2, 0, 0, 0, 0);
    const ARITHMETIC_LOGIC_AND_LOAD: Self = Self::new(1, 1, 0, 0, 0);
    const ARITHMETIC_LOGIC_AND_STORE: Self = Self::new(1, 0, 1, 0, 0);
    const ARITHMETIC_LOGIC_AND_MULTIPLY: Self = Self::new(1, 0, 0, 1, 0);
    const ARITHMETIC_LOGIC_AND_DIVIDE: Self = Self::new(1, 0, 0, 0, 1);

    pub const fn new(arithmetic_logic: u8, load: u8, store: u8, multiply: u8, divide: u8) -> Self {
        Self {
            arithmetic_logic,
            load,
            store,
            multiply,
            divide,
        }
    }

    /// Checks that each unit count of `self` is at most that of `available`.
    pub fn fits_within(&self, available: &Self) -> bool {
        self.arithmetic_logic <= available.arithmetic_logic
            && self.load <= available.load
            && self.store <= available.store
            && self.multiply <= available.multiply
            && self.divide <= available.divide
    }
}

impl Add for ExecutionUnits {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self::new(
            self.arithmetic_logic + other.arithmetic_logic,
            self.load + other.load,
            self.store + other.store,
            self.multiply + other.multiply,
            self.divide + other.divide,
        )
    }
}

impl Sub for ExecutionUnits {
    type Output = Self;

    /// Subtracts memberwise. The gas cost model subtracts only units that fit, so no member underflows.
    fn sub(self, other: Self) -> Self {
        Self::new(
            self.arithmetic_logic - other.arithmetic_logic,
            self.load - other.load,
            self.store - other.store,
            self.multiply - other.multiply,
            self.divide - other.divide,
        )
    }
}

/// `𝔪`: The latency of a load, in cycles.
const MEMORY_ACCESS_CYCLES: u32 = 25;

/// The latency of a store, in cycles. The GP writes it as 25 rather than `𝔪`, which it plans to replace with a paging cost.
const STORE_CYCLES: u32 = 25;

/// Cost of one instruction in the gas cost model, read by the simulation of its basic block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstructionCost {
    /// `č`: Cycles from the start of execution to the result
    pub cycles: u32,
    /// `ď`: Decode slots needed to decode the instruction
    pub decode_slots: u8,
    /// `x̌`: Execution units held while the instruction executes
    pub execution_units: ExecutionUnits,
}

impl InstructionCost {
    const fn new(cycles: u32, decode_slots: u8, execution_units: ExecutionUnits) -> Self {
        Self {
            cycles,
            decode_slots,
            execution_units,
        }
    }

    /// Looks up the cost of `instruction` at `pc` (0-based, in octets) in the gas cost table.
    ///
    /// Rows named in the GP table macros keep their names in the comments, e.g. `simplealuthreeop`.
    pub fn of(
        program_state: &ProgramState,
        pc: usize,
        instruction: &Instruction,
        register_usage: RegisterUsage,
    ) -> Self {
        use Opcode::*;
        // `𝔓`: The first value when a destination register is also a source register
        let if_registers_overlap = |overlapping: u8, disjoint: u8| {
            if register_usage
                .source_registers
                .intersects(register_usage.destination_registers)
            {
                overlapping
            } else {
                disjoint
            }
        };
        // `𝔓_S`: The first value when the first source register `r_A` is the destination register `r_D`
        let if_shifted_register_is_destination = |same: u8, different: u8| {
            if instruction.rs1 == instruction.rd {
                same
            } else {
                different
            }
        };
        let arithmetic_logic = |cycles, decode_slots| {
            Self::new(cycles, decode_slots, ExecutionUnits::ARITHMETIC_LOGIC)
        };
        let without_execution_units =
            |cycles, decode_slots| Self::new(cycles, decode_slots, ExecutionUnits::NONE);

        match instruction.op {
            MOVE_REG => without_execution_units(0, 1),

            // `simplealuthreeop` and `simplealutwoop`
            AND | XOR | OR | ADD_64 | SUB_64 | AND_IMM | XOR_IMM | OR_IMM | ADD_IMM_64
            | SHLO_R_IMM_64 | SHAR_R_IMM_64 | SHLO_L_IMM_64 | ROT_R_64_IMM | REVERSE_BYTES => {
                arithmetic_logic(1, if_registers_overlap(1, 2))
            }
            // `simplealuthreeopthirtytwo` and `simplealutwoopthirtytwo`
            ADD_32 | SUB_32 | ADD_IMM_32 | SHLO_R_IMM_32 | SHAR_R_IMM_32 | SHLO_L_IMM_32
            | ROT_R_32_IMM => arithmetic_logic(2, if_registers_overlap(2, 3)),

            // `trivialtwooponecycle`
            COUNT_SET_BITS_64 | COUNT_SET_BITS_32 | LEADING_ZERO_BITS_64 | LEADING_ZERO_BITS_32
            | SIGN_EXTEND_8 | SIGN_EXTEND_16 | ZERO_EXTEND_16 => arithmetic_logic(1, 1),
            // `trivialtwooptwocycles`
            TRAILING_ZERO_BITS_64 | TRAILING_ZERO_BITS_32 => {
                Self::new(2, 1, ExecutionUnits::TWO_ARITHMETIC_LOGIC)
            }

            // `shiftsandrotates` and `shiftsandrotatesthirtytwo`
            SHLO_L_64 | SHLO_R_64 | SHAR_R_64 | ROT_L_64 | ROT_R_64 => {
                arithmetic_logic(1, if_shifted_register_is_destination(2, 3))
            }
            SHLO_L_32 | SHLO_R_32 | SHAR_R_32 | ROT_L_32 | ROT_R_32 => {
                arithmetic_logic(2, if_shifted_register_is_destination(3, 4))
            }
            // `shiftsandrotatesalt` and `shiftsandrotatesaltthirtytwo`
            SHLO_L_IMM_ALT_64 | SHLO_R_IMM_ALT_64 | SHAR_R_IMM_ALT_64 | ROT_R_64_IMM_ALT => {
                arithmetic_logic(1, 3)
            }
            SHLO_L_IMM_ALT_32 | SHLO_R_IMM_ALT_32 | SHAR_R_IMM_ALT_32 | ROT_R_32_IMM_ALT => {
                arithmetic_logic(2, 4)
            }

            // `regcomp` and `regcompimm`
            SET_LT_U | SET_LT_S | SET_LT_U_IMM | SET_LT_S_IMM | SET_GT_U_IMM | SET_GT_S_IMM => {
                arithmetic_logic(3, 3)
            }
            // `cmov` and `cmovimm`
            CMOV_IZ | CMOV_NZ => arithmetic_logic(2, 2),
            CMOV_IZ_IMM | CMOV_NZ_IMM => arithmetic_logic(2, 3),
            // `minmax`
            MAX | MAX_U | MIN | MIN_U => arithmetic_logic(3, if_registers_overlap(2, 3)),

            // `indirectload` and `directload`
            LOAD_IND_U8 | LOAD_IND_I8 | LOAD_IND_U16 | LOAD_IND_I16 | LOAD_IND_U32
            | LOAD_IND_I32 | LOAD_IND_U64 | LOAD_U8 | LOAD_I8 | LOAD_U16 | LOAD_I16 | LOAD_U32
            | LOAD_I32 | LOAD_U64 => Self::new(
                MEMORY_ACCESS_CYCLES,
                1,
                ExecutionUnits::ARITHMETIC_LOGIC_AND_LOAD,
            ),
            // `indirectstoreimm`, `indirectstore`, `storeimm` and `directstore`
            STORE_IMM_IND_U8 | STORE_IMM_IND_U16 | STORE_IMM_IND_U32 | STORE_IMM_IND_U64
            | STORE_IND_U8 | STORE_IND_U16 | STORE_IND_U32 | STORE_IND_U64 | STORE_IMM_U8
            | STORE_IMM_U16 | STORE_IMM_U32 | STORE_IMM_U64 | STORE_U8 | STORE_U16 | STORE_U32
            | STORE_U64 => Self::new(STORE_CYCLES, 1, ExecutionUnits::ARITHMETIC_LOGIC_AND_STORE),

            // `branch` and `branchimm`
            BRANCH_EQ | BRANCH_NE | BRANCH_LT_U | BRANCH_LT_S | BRANCH_GE_U | BRANCH_GE_S => {
                Self::branch(program_state, pc, instruction.imm1)
            }
            BRANCH_EQ_IMM | BRANCH_NE_IMM | BRANCH_LT_U_IMM | BRANCH_LE_U_IMM | BRANCH_GE_U_IMM
            | BRANCH_GT_U_IMM | BRANCH_LT_S_IMM | BRANCH_LE_S_IMM | BRANCH_GE_S_IMM
            | BRANCH_GT_S_IMM => Self::branch(program_state, pc, instruction.imm2),

            // `divrem`
            DIV_U_32 | DIV_S_32 | REM_U_32 | REM_S_32 | DIV_U_64 | DIV_S_64 | REM_U_64
            | REM_S_64 => Self::new(60, 4, ExecutionUnits::ARITHMETIC_LOGIC_AND_DIVIDE),

            AND_INV | OR_INV => arithmetic_logic(2, 3),
            XNOR => arithmetic_logic(2, if_registers_overlap(2, 3)),
            NEG_ADD_IMM_64 => arithmetic_logic(2, 3),
            NEG_ADD_IMM_32 => arithmetic_logic(3, 4),
            LOAD_IMM => without_execution_units(1, 1),
            LOAD_IMM_64 => without_execution_units(1, 2),

            MUL_64 | MUL_IMM_64 => Self::new(
                3,
                if_registers_overlap(1, 2),
                ExecutionUnits::ARITHMETIC_LOGIC_AND_MULTIPLY,
            ),
            MUL_32 | MUL_IMM_32 => Self::new(
                4,
                if_registers_overlap(2, 3),
                ExecutionUnits::ARITHMETIC_LOGIC_AND_MULTIPLY,
            ),
            MUL_UPPER_S_S | MUL_UPPER_U_U => {
                Self::new(4, 4, ExecutionUnits::ARITHMETIC_LOGIC_AND_MULTIPLY)
            }
            MUL_UPPER_S_U => Self::new(6, 4, ExecutionUnits::ARITHMETIC_LOGIC_AND_MULTIPLY),

            // `finish`
            TRAP | FALLTHROUGH => without_execution_units(2, 1),
            UNLIKELY => without_execution_units(40, 1),
            JUMP | LOAD_IMM_JUMP => without_execution_units(15, 1),
            JUMP_IND | LOAD_IMM_JUMP_IND => without_execution_units(22, 1),

            ECALLI => arithmetic_logic(100, 4),
        }
    }

    /// Returns the cost of a branch (`𝔟`), whose latency is 1 when the target or the next instruction is `unlikely` or `trap`, and 20 otherwise.
    fn branch(program_state: &ProgramState, pc: usize, target: Option<u64>) -> Self {
        let next_pc = Interpreter::next_pc(pc as RegValue, program_state) as usize;
        let target_pc = target.and_then(|target| usize::try_from(target).ok());
        let is_unlikely_or_trap = |index: Option<usize>| {
            // Octets past `c` read as zero (`trap`), as does a target past `usize`
            let opcode_octet = index
                .and_then(|index| program_state.instructions.get(index).copied())
                .unwrap_or(Opcode::TRAP as u8);
            opcode_octet == Opcode::UNLIKELY as u8 || opcode_octet == Opcode::TRAP as u8
        };
        let cycles = if is_unlikely_or_trap(Some(next_pc)) || is_unlikely_or_trap(target_pc) {
            1
        } else {
            20
        };
        Self::new(cycles, 1, ExecutionUnits::ARITHMETIC_LOGIC)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::loader::test_program_blobs::load_program_state;
    use std::error::Error;

    const BRANCH_EQ: u8 = Opcode::BRANCH_EQ as u8;
    const UNLIKELY: u8 = Opcode::UNLIKELY as u8;
    const FALLTHROUGH: u8 = Opcode::FALLTHROUGH as u8;
    const TRAP: u8 = Opcode::TRAP as u8;

    /// Returns the branch latency of the `branch_eq r0, r0` at 0 with the 1-octet offset `target_offset`, followed by `fallthrough` and `tail`.
    fn branch_cycles(target_offset: u8, tail: &[u8]) -> Result<u32, Box<dyn Error>> {
        let mut instruction_data = vec![BRANCH_EQ, 0, target_offset, FALLTHROUGH];
        instruction_data.extend(tail);
        let mut opcode_bitmask = vec![true, false, false, true];
        opcode_bitmask.extend(tail.iter().map(|_| true));
        let program_state = load_program_state(&instruction_data, &opcode_bitmask)?;
        let branch = program_state.instruction_at(0).ok_or("no branch")?;
        Ok(InstructionCost::of(&program_state, 0, branch, branch.register_usage()).cycles)
    }

    #[test]
    fn test_branch_cost_is_low_into_unlikely_or_trap() -> Result<(), Box<dyn Error>> {
        // The next instruction is `fallthrough` at 3, so only the target decides
        assert_eq!(branch_cycles(4, &[UNLIKELY, TRAP])?, 1);
        assert_eq!(branch_cycles(4, &[TRAP])?, 1);
        assert_eq!(branch_cycles(3, &[TRAP])?, 20);
        Ok(())
    }

    #[test]
    fn test_branch_cost_reads_zeta_past_code() -> Result<(), Box<dyn Error>> {
        // A target past `c` reads a zero octet, which is `trap`
        assert_eq!(branch_cycles(100, &[TRAP])?, 1);
        Ok(())
    }

    #[test]
    fn test_branch_cost_reads_raw_octet_inside_instruction() -> Result<(), Box<dyn Error>> {
        // Target 2 is the offset octet of the branch, whose value 2 is the `unlikely` opcode
        assert_eq!(branch_cycles(2, &[TRAP])?, 1);
        Ok(())
    }
}
