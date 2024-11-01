use crate::{
    constants::{
        INPUT_SIZE, PAGE_SIZE, REGISTERS_COUNT, SEGMENT_SIZE, STANDARD_PROGRAM_SIZE_LIMIT,
    },
    program::opcode::*,
    state::memory::MemAddress,
    types::error::{
        PVMError, VMCoreError,
        VMCoreError::{InvalidInstructionFormat, InvalidProgram},
    },
    utils::VMUtils,
};
use bit_vec::BitVec;
use rjam_codec::{JamCodecError, JamDecode, JamDecodeFixed, JamInput};
use rjam_common::Octets;

pub struct FormattedProgram {
    pub read_only_len: u32,      // |o|
    pub read_write_len: u32,     // |w|
    pub extra_heap_pages: u16,   // z
    pub stack_size: u32,         // s
    pub read_only_data: Octets,  // o
    pub read_write_data: Octets, // w
    pub code_len: u32,           // |c|
    pub code: Octets,            // c
}

impl JamDecode for FormattedProgram {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        let read_only_len = u32::decode_fixed(input, 3)?;
        let read_write_len = u32::decode_fixed(input, 3)?;
        let extra_heap_pages = u16::decode_fixed(input, 2)?;
        let stack_size = u32::decode_fixed(input, 3)?;
        let read_only_data = Octets::decode_fixed(input, read_only_len as usize)?;
        let read_write_data = Octets::decode_fixed(input, read_write_len as usize)?;
        let code_len = u32::decode_fixed(input, 4)?;
        let code = Octets::decode_fixed(input, code_len as usize)?;

        Ok(Self {
            read_only_len,
            read_write_len,
            extra_heap_pages,
            stack_size,
            read_only_data,
            read_write_data,
            code_len,
            code,
        })
    }
}

impl FormattedProgram {
    pub fn check_size_limit(&self) -> bool {
        let condition_value = 5 * SEGMENT_SIZE
            + VMUtils::q(self.read_only_len as usize)
            + VMUtils::q(
                self.read_write_len as usize + (self.extra_heap_pages as usize) * PAGE_SIZE,
            )
            + VMUtils::q(self.stack_size as usize)
            + INPUT_SIZE;
        condition_value <= STANDARD_PROGRAM_SIZE_LIMIT
    }
}

#[derive(Debug)]
pub struct Instruction {
    pub op: Opcode,          // opcode
    pub r1: Option<usize>,   // first source register index
    pub r2: Option<usize>,   // second source register index
    pub rd: Option<usize>,   // destination register index
    pub imm1: Option<u32>,   // first immediate value argument
    pub imm2: Option<u32>,   // second immediate value argument
    pub offset: Option<i32>, // offset argument
}

impl Instruction {
    fn new(
        op: Opcode,
        r1: Option<usize>,
        r2: Option<usize>,
        rd: Option<usize>,
        imm1: Option<u32>,
        imm2: Option<u32>,
        offset: Option<i32>,
    ) -> Result<Self, PVMError> {
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

pub struct ProgramDecoder;

impl ProgramDecoder {
    //
    // Program decoding functions
    //

    /// Decode program blob into formatted program
    pub fn decode_standard_program(program: &[u8]) -> Result<FormattedProgram, PVMError> {
        let mut input = program;
        Ok(FormattedProgram::decode(&mut input)?)
    }

    /// Decode program code into instruction sequence, opcode bitmask and dynamic jump table
    pub fn decode_program_code(code: &[u8]) -> Result<(Octets, BitVec, Vec<MemAddress>), PVMError> {
        let mut input = code;

        // Decode the length of the jump table (|j|)
        let jump_table_len = usize::decode(&mut input)?;

        // Decode the jump table entry length in octets (z)
        let z = u8::decode_fixed(&mut input, 1)?;

        // Decode the length of the instruction sequence (|c|)
        let instructions_len = usize::decode(&mut input)?;

        // Decode the dynamic jump table (j)
        let mut jump_table = Vec::with_capacity(jump_table_len);
        for _ in 0..jump_table_len {
            jump_table.push(MemAddress::decode_fixed(&mut input, z as usize)?);
        }

        // Decode the instruction sequence (c)
        let instructions = Octets::decode_fixed(&mut input, instructions_len)?;

        // Decode the opcode bitmask (k)
        // The length of `k` must be equivalent to the length of `c`, |k| = |c|
        let opcode_bitmask = BitVec::decode_fixed(&mut input, instructions_len)?;

        if !input.is_empty() {
            return Err(PVMError::VMCoreError(InvalidProgram));
        }

        Ok((instructions, opcode_bitmask, jump_table))
    }

    /// Extracts and processes an immediate value from the instruction blob.
    pub fn extract_imm_value(
        inst_blob: &[u8],
        l_x: usize,
        start_index: usize,
        end_index: usize,
    ) -> Result<u32, PVMError> {
        if l_x > 0 {
            let mut buffer = [0u8; 4];
            buffer[..l_x].copy_from_slice(&inst_blob[start_index..end_index]);
            Ok(
                VMUtils::signed_extend(l_x as u32, u32::decode_fixed(&mut &buffer[..l_x], l_x)?)
                    .unwrap(),
            )
        } else {
            Ok(0)
        }
    }

    /// Extracts and processes an immediate address (pc increment) value from the instruction blob.
    pub fn extract_imm_address(
        pc: MemAddress,
        inst_blob: &[u8],
        l_y: usize,
        start_index: usize,
        end_index: usize,
    ) -> Result<i32, PVMError> {
        let pc_increment = if l_y > 0 {
            let mut buffer = [0u8; 4];
            buffer[..l_y].copy_from_slice(&inst_blob[start_index..end_index]);
            VMUtils::unsigned_to_signed(l_y as u32, u32::decode_fixed(&mut &buffer[..l_y], l_y)?)
                .unwrap()
        } else {
            0
        };

        Ok(pc as i32 + pc_increment)
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
        current_pc: MemAddress,
        skip_distance: usize,
    ) -> Result<Instruction, PVMError> {
        use crate::program::opcode::Opcode::*;
        let op = Opcode::from_u8(inst_blob[0]).ok_or(VMCoreError::InvalidOpcode)?;

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

            // Group 3: two immediates
            STORE_IMM_U8 | STORE_IMM_U16 | STORE_IMM_U32 => {
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

            // Group 4: one offset
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

            // Group 5: one register & one immediate
            JUMP_IND | LOAD_IMM | LOAD_U8 | LOAD_I8 | LOAD_U16 | LOAD_I16 | LOAD_U32 | STORE_U8
            | STORE_U16 | STORE_U32 => {
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

            // Group 6: one register & two immediates
            STORE_IMM_IND_U8 | STORE_IMM_IND_U16 | STORE_IMM_IND_U32 => {
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

            // Group 7: one register, one immediate and one offset
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

            // Group 8: two registers
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

            // Group 9: two register & one immediate
            STORE_IND_U8 | STORE_IND_U16 | STORE_IND_U32 | LOAD_IND_U8 | LOAD_IND_I8
            | LOAD_IND_U16 | LOAD_IND_I16 | LOAD_IND_U32 | ADD_IMM | AND_IMM | XOR_IMM | OR_IMM
            | MUL_IMM | MUL_UPPER_SS_IMM | MUL_UPPER_UU_IMM | SET_LT_U_IMM | SET_LT_S_IMM
            | SHLO_L_IMM | SHLO_R_IMM | SHAR_R_IMM | NEG_ADD_IMM | SET_GT_U_IMM | SET_GT_S_IMM
            | SHLO_L_IMM_ALT | SHLO_R_IMM_ALT | SHAR_R_IMM_ALT | CMOV_IZ_IMM | CMOV_NZ_IMM => {
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

            // Group 10: two registers & one offset
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

            // Group 11: two registers & two immediates
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

            // Group 12: three registers
            ADD | SUB | AND | XOR | OR | MUL | MUL_UPPER_SS | MUL_UPPER_UU | MUL_UPPER_SU
            | DIV_U | DIV_S | REM_U | REM_S | SET_LT_U | SET_LT_S | SHLO_L | SHLO_R | SHAR_R
            | CMOV_IZ | CMOV_NZ => {
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
