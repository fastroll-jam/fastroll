use crate::{
    constants::{
        INIT_PAGE_SIZE, INIT_SIZE, REGION_SIZE, REGISTERS_COUNT, STANDARD_PROGRAM_SIZE_LIMIT,
    },
    program::opcode::*,
    state::memory::MemAddress,
    types::{
        common::RegValue,
        error::{
            PVMError,
            VMCoreError::{InvalidInstructionFormat, InvalidProgram},
        },
    },
    utils::VMUtils,
};
use bit_vec::BitVec;
use rjam_codec::{JamCodecError, JamDecode, JamDecodeFixed, JamInput};
use std::collections::HashSet;

pub struct FormattedProgram {
    pub static_size: u32,      // |o|; length of read-only data of the program
    pub heap_size: u32,        // |w|; length of read-write data of the program
    pub extra_heap_pages: u16, // z; extra heap allocation in pages
    pub stack_size: u32,       // s
    pub static_data: Vec<u8>,  // o
    pub heap_data: Vec<u8>,    // w
    pub code_size: u32,        // |c|
    pub code: Vec<u8>,         // c
}

impl JamDecode for FormattedProgram {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        let static_size = u32::decode_fixed(input, 3)?;
        let heap_size = u32::decode_fixed(input, 3)?;
        let extra_heap_pages = u16::decode_fixed(input, 2)?;
        let stack_size = u32::decode_fixed(input, 3)?;
        let static_data = Vec::<u8>::decode_fixed(input, static_size as usize)?; // no length prefix
        let heap_data = Vec::<u8>::decode_fixed(input, heap_size as usize)?; // no length prefix
        let code_size = u32::decode_fixed(input, 4)?;
        let code = Vec::<u8>::decode_fixed(input, code_size as usize)?; // no length prefix

        Ok(Self {
            static_size,
            heap_size,
            extra_heap_pages,
            stack_size,
            static_data,
            heap_data,
            code_size,
            code,
        })
    }
}

impl FormattedProgram {
    pub fn validate_program_size(&self) -> bool {
        5 * REGION_SIZE
            + VMUtils::region_align(self.static_size as usize)
            + VMUtils::region_align(
                self.heap_size as usize + (self.extra_heap_pages as usize) * INIT_PAGE_SIZE,
            )
            + VMUtils::region_align(self.stack_size as usize)
            + INIT_SIZE
            <= STANDARD_PROGRAM_SIZE_LIMIT
    }
}

/// Immutable VM state (program components)
///
/// Equivalent to `FormattedProgram.code`.
#[derive(Default)]
pub struct ProgramState {
    pub instructions: Vec<u8>, // c; serialized // TODO: define instruction_blob with endless zeroes padding
    pub jump_table: Vec<MemAddress>, // j
    pub opcode_bitmask: BitVec, // k
    pub basic_block_start_indices: HashSet<usize>, // opcode indices that are beginning of basic-blocks
}

impl JamDecode for ProgramState {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        // Decode the length of the jump table (|j|)
        let jump_table_len = usize::decode(input)?;

        // Decode the jump table entry length in octets (z)
        let z = u8::decode_fixed(input, 1)?;

        // Decode the length of the instruction sequence (|c|)
        let instructions_len = usize::decode(input)?;

        // Decode the dynamic jump table (j)
        let mut jump_table = Vec::with_capacity(jump_table_len);
        for _ in 0..jump_table_len {
            jump_table.push(MemAddress::decode_fixed(input, z as usize)?);
        }

        // Decode the instruction sequence (c)
        let instructions = Vec::<u8>::decode_fixed(input, instructions_len)?;

        // Decode the opcode bitmask (k)
        // The length of `k` must be equivalent to the length of `c`, |k| = |c|
        // TODO: add validation for the instruction length limit of 16?
        let opcode_bitmask = BitVec::decode_fixed(input, instructions_len)?;

        Ok(Self {
            instructions,
            jump_table,
            opcode_bitmask,
            basic_block_start_indices: HashSet::from([0]),
        })
    }
}

#[derive(Debug, Default)]
pub struct Instruction {
    pub op: Opcode,             // opcode
    pub r1: Option<usize>,      // first source register index
    pub r2: Option<usize>,      // second source register index
    pub rd: Option<usize>,      // destination register index
    pub imm1: Option<RegValue>, // first immediate value argument
    pub imm2: Option<RegValue>, // second immediate value argument
    pub offset: Option<i64>,    // offset argument
}

impl Instruction {
    fn new(
        op: Opcode,
        r1: Option<usize>,
        r2: Option<usize>,
        rd: Option<usize>,
        imm1: Option<RegValue>,
        imm2: Option<RegValue>,
        offset: Option<i64>,
    ) -> Result<Self, PVMError> {
        // FIXME: move this logic into the decode, since this function will be removed.
        // Validate register indices
        for &reg in [rd, r1, r2].iter().flatten() {
            if reg > (REGISTERS_COUNT - 1) {
                return Err(PVMError::VMCoreError(InvalidInstructionFormat));
            }
        }

        Ok(Self {
            op,
            r1,
            r2,
            rd,
            imm1,
            imm2,
            offset,
        })
    }
}

/// General program decoders used for processing PVM programs.
///
/// Programs executed on the PVM are processed through the following steps:
///
/// 1. A standard program blob is provided to the `Ψ_M`.
///
/// 2. The program is decoded into a `FormattedProgram`, which contains information about memory
///    initialization, including the sizes of various memory regions (e.g., heap, stack, static)
///    and initial data to be loaded in those regions.
///
/// 3. After memory initialization, the `code` from the `FormattedProgram` is loaded into the `PVM` state.
///
/// 4. Internal PVM invocation functions, such as `Ψ_H` and `Ψ`, utilize the `code` stored in the `PVM` state.
///
/// 5. The general invocation function `Ψ` further decodes the `code` into
///    `instructions`, an `opcode_bitmask`, and a `dynamic_jump_table`.
///
/// 6. Finally, the single-step execution functions (`Ψ_1`) use these three components
///    to interpret and execute the program one instruction at a time.
pub struct ProgramDecoder;

impl ProgramDecoder {
    /// Decodes program blob into formatted program. Used by `Ψ_M`.
    pub fn decode_standard_program(program_blob: &[u8]) -> Result<FormattedProgram, PVMError> {
        let mut input = program_blob;
        let formatted_program = FormattedProgram::decode(&mut input)?;
        if !input.is_empty() {
            return Err(PVMError::VMCoreError(InvalidProgram));
        }

        Ok(formatted_program)
    }

    /// Decodes code element of the formatted program code into
    /// instruction sequence (c), opcode bitmask (k) and dynamic jump table (j).
    /// Used by `Ψ`.
    pub fn decode_program_code(
        code: &[u8],
    ) -> Result<(Vec<u8>, BitVec, Vec<MemAddress>), PVMError> {
        let mut input = code;
        let program = ProgramState::decode(&mut input)?;

        if !input.is_empty() {
            return Err(PVMError::VMCoreError(InvalidProgram));
        }

        Ok((
            program.instructions,
            program.opcode_bitmask,
            program.jump_table,
        ))
    }

    /// Extracts and processes an immediate value from the instruction blob.
    fn extract_imm_value(
        inst_blob: &[u8],
        imm_size: usize,
        start_index: usize,
        end_index: usize,
    ) -> Result<RegValue, PVMError> {
        if imm_size > 0 {
            let mut buffer = [0u8; 8];
            buffer[..imm_size].copy_from_slice(&inst_blob[start_index..end_index]);
            Ok(VMUtils::signed_extend(
                u64::decode_fixed(&mut &buffer[..imm_size], imm_size)?,
                imm_size,
            )
            .ok_or(PVMError::VMCoreError(InvalidInstructionFormat))?)
        } else {
            Ok(0)
        }
    }

    /// Extracts and processes an immediate address (pc increment) value from the instruction blob.
    fn extract_imm_address(
        pc: RegValue,
        inst_blob: &[u8],
        imm_size: usize,
        start_index: usize,
        end_index: usize,
    ) -> Result<i64, PVMError> {
        let pc_increment = if imm_size > 0 {
            let mut buffer = [0u8; 4];
            buffer[..imm_size].copy_from_slice(&inst_blob[start_index..end_index]);
            VMUtils::unsigned_to_signed(
                imm_size as u64,
                u64::decode_fixed(&mut &buffer[..imm_size], imm_size)?,
            )
            .ok_or(PVMError::VMCoreError(InvalidInstructionFormat))?
        } else {
            0
        };

        Ok(pc as i64 + pc_increment)
    }

    /// Decodes a single instruction blob into an `Instruction` type.
    ///
    /// This function takes a byte slice representing an instruction and converts it
    /// into a more easily consumable `Instruction` type, which can be used by
    /// single-step PVM state-transition functions.
    ///
    /// The instruction blob should not exceed 16 bytes in length.
    /// The opcode is represented by the first byte of the instruction blob.
    pub fn decode_instruction(
        inst_blob: &[u8],
        current_pc: RegValue,
        skip_distance: usize,
    ) -> Result<Instruction, PVMError> {
        use crate::program::opcode::Opcode::*;
        let op = Opcode::from_u8(inst_blob[0])?;

        match op {
            // Group 1: no arguments
            TRAP | FALLTHROUGH => Ok(Instruction::new(op, None, None, None, None, None, None)?),

            // Group 2: one immediate
            ECALLI => {
                let l_x = 4.min(skip_distance);
                let imm_x = Self::extract_imm_value(inst_blob, l_x, 1, 1 + l_x)?;

                Ok(Instruction::new(
                    op,
                    None,
                    None,
                    None,
                    Some(imm_x),
                    None,
                    None,
                )?)
            }

            // Group 3: one register and one extended width immediate
            LOAD_IMM_64 => {
                // FIXME
                Ok(Instruction::new(op, None, None, None, None, None, None)?)
            }

            // Group 4: two immediates
            STORE_IMM_U8 | STORE_IMM_U16 | STORE_IMM_U32 | STORE_IMM_U64 => {
                let l_x = 4.min(inst_blob[1] % 8) as usize;
                let l_y = 4.min(0.max(skip_distance - l_x - 1));
                let imm_x = Self::extract_imm_value(inst_blob, l_x, 2, 2 + l_x)?;
                let imm_y = Self::extract_imm_value(inst_blob, l_y, 2 + l_x, 2 + l_x + l_y)?;

                Ok(Instruction::new(
                    op,
                    None,
                    None,
                    None,
                    Some(imm_x),
                    Some(imm_y),
                    None,
                )?)
            }

            // Group 5: one offset
            JUMP => {
                let l_x = 4.min(skip_distance);
                let imm_x = Self::extract_imm_address(current_pc, inst_blob, l_x, 1, 1 + l_x)?;

                Ok(Instruction::new(
                    op,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(imm_x),
                )?)
            }

            // Group 6: one register & one immediate
            JUMP_IND | LOAD_IMM | LOAD_U8 | LOAD_I8 | LOAD_U16 | LOAD_I16 | LOAD_U32 | LOAD_I32
            | LOAD_U64 | STORE_U8 | STORE_U16 | STORE_U32 | STORE_U64 => {
                let r_a = 12.min(inst_blob[current_pc as usize + 1] % 16) as usize;
                let l_x = 4.min(0.max(skip_distance - 1));
                let imm_x = Self::extract_imm_value(inst_blob, l_x, 2, 2 + l_x)?;

                Ok(Instruction::new(
                    op,
                    Some(r_a),
                    None,
                    None,
                    Some(imm_x),
                    None,
                    None,
                )?)
            }

            // Group 7: one register & two immediates
            STORE_IMM_IND_U8 | STORE_IMM_IND_U16 | STORE_IMM_IND_U32 | STORE_IMM_IND_U64 => {
                let r_a = 12.min(inst_blob[current_pc as usize + 1] % 16) as usize;
                let l_x = 4
                    .min((inst_blob[current_pc as usize + 1] as f64 / 16.0).floor() as u8 % 8)
                    as usize;
                let l_y = 4.min(0.max(skip_distance - l_x - 1));
                let imm_x = Self::extract_imm_value(inst_blob, l_x, 2, 2 + l_x)?;
                let imm_y = Self::extract_imm_value(inst_blob, l_y, 2 + l_x, 2 + l_x + l_y)?;

                Ok(Instruction::new(
                    op,
                    Some(r_a),
                    None,
                    None,
                    Some(imm_x),
                    Some(imm_y),
                    None,
                )?)
            }

            // Group 8: one register, one immediate and one offset
            LOAD_IMM_JUMP | BRANCH_EQ_IMM | BRANCH_NE_IMM | BRANCH_LT_U_IMM | BRANCH_LE_U_IMM
            | BRANCH_GE_U_IMM | BRANCH_GT_U_IMM | BRANCH_LT_S_IMM | BRANCH_LE_S_IMM
            | BRANCH_GE_S_IMM | BRANCH_GT_S_IMM => {
                let r_a = 12.min(inst_blob[current_pc as usize + 1] % 16) as usize;
                let l_x = 4
                    .min((inst_blob[current_pc as usize + 1] as f64 / 16.0).floor() as u8 % 8)
                    as usize;
                let l_y = 4.min(0.max(skip_distance - l_x - 1));
                let imm_x = Self::extract_imm_value(inst_blob, l_x, 2, 2 + l_x)?;
                let imm_y =
                    Self::extract_imm_address(current_pc, inst_blob, l_y, 2 + l_x, 2 + l_x + l_y)?;

                Ok(Instruction::new(
                    op,
                    Some(r_a),
                    None,
                    None,
                    Some(imm_x),
                    None,
                    Some(imm_y),
                )?)
            }

            // Group 9: two registers
            MOVE_REG | SBRK => {
                let r_d = 12.min(inst_blob[current_pc as usize + 1] % 16) as usize;
                let r_a = 12.min((inst_blob[current_pc as usize + 1] as f64 / 16.0).floor() as u8)
                    as usize;

                Ok(Instruction::new(
                    op,
                    Some(r_a),
                    None,
                    Some(r_d),
                    None,
                    None,
                    None,
                )?)
            }

            // Group 10: two register & one immediate
            STORE_IND_U8 | STORE_IND_U16 | STORE_IND_U32 | STORE_IND_U64 | LOAD_IND_U8
            | LOAD_IND_I8 | LOAD_IND_U16 | LOAD_IND_I16 | LOAD_IND_U32 | LOAD_IND_I32
            | LOAD_IND_U64 | ADD_IMM_32 | AND_IMM | XOR_IMM | OR_IMM | MUL_IMM_32
            | SET_LT_U_IMM | SET_LT_S_IMM | SHLO_L_IMM_32 | SHLO_R_IMM_32 | SHAR_R_IMM_32
            | NEG_ADD_IMM_32 | SET_GT_U_IMM | SET_GT_S_IMM | SHLO_L_IMM_ALT_32
            | SHLO_R_IMM_ALT_32 | SHAR_R_IMM_ALT_32 | CMOV_IZ_IMM | CMOV_NZ_IMM | ADD_IMM_64
            | MUL_IMM_64 | SHLO_L_IMM_64 | SHLO_R_IMM_64 | SHAR_R_IMM_64 | NEG_ADD_IMM_64
            | SHLO_L_IMM_ALT_64 | SHLO_R_IMM_ALT_64 | SHAR_R_IMM_ALT_64 => {
                let r_a = 12.min(inst_blob[current_pc as usize + 1] % 16) as usize;
                let r_b = 12.min((inst_blob[current_pc as usize + 1] as f64 / 16.0).floor() as u8)
                    as usize;
                let l_x = 4.min(0.max(skip_distance - 1));
                let imm_x = Self::extract_imm_value(inst_blob, l_x, 2, 2 + l_x)?;

                Ok(Instruction::new(
                    op,
                    Some(r_a),
                    Some(r_b),
                    None,
                    Some(imm_x),
                    None,
                    None,
                )?)
            }

            // Group 11: two registers & one offset
            BRANCH_EQ | BRANCH_NE | BRANCH_LT_U | BRANCH_LT_S | BRANCH_GE_U | BRANCH_GE_S => {
                let r_a = 12.min(inst_blob[current_pc as usize + 1] % 16) as usize;
                let r_b = 12.min((inst_blob[current_pc as usize + 1] as f64 / 16.0).floor() as u8)
                    as usize;
                let l_x = 4.min(0.max(skip_distance - 1));
                let imm_x = Self::extract_imm_address(current_pc, inst_blob, l_x, 2, 2 + l_x)?;

                Ok(Instruction::new(
                    op,
                    Some(r_a),
                    Some(r_b),
                    None,
                    None,
                    None,
                    Some(imm_x),
                )?)
            }

            // Group 12: two registers & two immediates
            LOAD_IMM_JUMP_IND => {
                let r_a = 12.min(inst_blob[current_pc as usize + 1] % 16) as usize;
                let r_b = 12.min((inst_blob[current_pc as usize + 1] as f64 / 16.0).floor() as u8)
                    as usize;
                let l_x = 4.min(inst_blob[current_pc as usize + 2] % 8) as usize;
                let l_y = 4.min(0.max(skip_distance - l_x - 2));
                let imm_x = Self::extract_imm_value(inst_blob, l_x, 3, 3 + l_x)?;
                let imm_y = Self::extract_imm_value(inst_blob, l_y, 3 + l_x, 3 + l_x + l_y)?;

                Ok(Instruction::new(
                    op,
                    Some(r_a),
                    Some(r_b),
                    None,
                    Some(imm_x),
                    Some(imm_y),
                    None,
                )?)
            }

            // Group 13: three registers
            ADD_32 | SUB_32 | MUL_32 | DIV_U_32 | DIV_S_32 | REM_U_32 | REM_S_32 | SHLO_L_32
            | SHLO_R_32 | SHAR_R_32 | ADD_64 | SUB_64 | MUL_64 | DIV_U_64 | DIV_S_64 | REM_U_64
            | REM_S_64 | SHLO_L_64 | SHLO_R_64 | SHAR_R_64 | AND | XOR | OR | MUL_UPPER_S_S
            | MUL_UPPER_U_U | MUL_UPPER_S_U | SET_LT_U | SET_LT_S | CMOV_IZ | CMOV_NZ => {
                let r_a = 12.min(inst_blob[current_pc as usize + 1] % 16) as usize;
                let r_b = 12.min((inst_blob[current_pc as usize + 1] as f64 / 16.0).floor() as u8)
                    as usize;
                let r_d = 12.min(inst_blob[current_pc as usize + 2]) as usize;

                Ok(Instruction::new(
                    op,
                    Some(r_a),
                    Some(r_b),
                    Some(r_d),
                    None,
                    None,
                    None,
                )?)
            }
        }
    }
}
