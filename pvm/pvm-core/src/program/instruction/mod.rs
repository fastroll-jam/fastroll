pub mod opcode;
pub mod set;

use crate::{
    error::VMCoreError,
    program::instruction::opcode::Opcode,
    utils::{SextInputSize, VMUtils},
};
use fr_codec::prelude::*;
use fr_pvm_types::{
    common::RegValue,
    constants::{MAX_INST_BLOB_LENGTH, REGISTERS_COUNT},
};

/// Size of immediate value in octets.
pub enum ImmSize {
    Octets0,
    Octets1,
    Octets2,
    Octets3,
    Octets4,
}

impl From<usize> for ImmSize {
    fn from(value: usize) -> Self {
        match value {
            0 => ImmSize::Octets0,
            1 => ImmSize::Octets1,
            2 => ImmSize::Octets2,
            3 => ImmSize::Octets3,
            4 => ImmSize::Octets4,
            _ => panic!("Invalid ImmSize value: {value}"),
        }
    }
}

impl ImmSize {
    pub fn as_usize(&self) -> usize {
        match self {
            Self::Octets0 => 0,
            Self::Octets1 => 1,
            Self::Octets2 => 2,
            Self::Octets3 => 3,
            Self::Octets4 => 4,
        }
    }
}

#[derive(Debug, Default)]
pub struct Instruction {
    /// Opcode
    pub op: Opcode,
    /// First source register index
    pub rs1: Option<usize>,
    /// Second source register index
    pub rs2: Option<usize>,
    /// Destination register index
    pub rd: Option<usize>,
    /// First immediate value argument (value or offset)
    pub imm1: Option<RegValue>,
    /// Second immediate value argument (value or offset)
    pub imm2: Option<RegValue>,
}

impl Instruction {
    fn new(
        op: Opcode,
        rs1: Option<usize>,
        rs2: Option<usize>,
        rd: Option<usize>,
        imm1: Option<RegValue>,
        imm2: Option<RegValue>,
    ) -> Result<Self, VMCoreError> {
        // Validate register indices
        for &reg in [rd, rs1, rs2].iter().flatten() {
            if reg > (REGISTERS_COUNT - 1) {
                return Err(VMCoreError::InvalidInstructionFormat);
            }
        }
        Ok(Self {
            op,
            rs1,
            rs2,
            rd,
            imm1,
            imm2,
        })
    }

    pub fn trap() -> Self {
        Self {
            op: Opcode::TRAP,
            ..Default::default()
        }
    }

    /// Decodes a single instruction blob into an `Instruction` type.
    ///
    /// This function takes a byte slice representing an instruction and converts it
    /// into a more easily consumable `Instruction` type, which can be used by
    /// single-step PVM state-transition functions.
    ///
    /// The instruction blob should not exceed 16 bytes in length.
    /// The opcode is represented by the first byte of the instruction blob.
    pub fn from_inst_blob(
        single_inst_blob: &[u8],
        current_pc: RegValue,
        skip_distance: usize,
    ) -> Result<Self, VMCoreError> {
        use crate::program::instruction::opcode::Opcode::*;
        let op = Opcode::from_u8(single_inst_blob[0]);

        // Note: the `single_inst_blob` is an octet slice that represents a single instruction.
        // Validate instruction blob length
        if single_inst_blob.len() > MAX_INST_BLOB_LENGTH {
            return Err(VMCoreError::InvalidInstructionFormat);
        }

        match op {
            // Group 1: no arguments
            TRAP | FALLTHROUGH => Ok(Self::new(op, None, None, None, None, None)?),

            // Group 2: one immediate
            ECALLI => {
                let l_x = ImmSize::from(4.min(skip_distance));
                let imm_x = Self::extract_imm_value(single_inst_blob, l_x, 1)?;

                Ok(Self::new(op, None, None, None, Some(imm_x), None)?)
            }

            // Group 3: one register and one extended width immediate
            LOAD_IMM_64 => {
                let r_a = 12.min(single_inst_blob[1] % 16) as usize;
                let imm_x = Self::extract_imm_extended_width(single_inst_blob, 2)?;
                Ok(Self::new(op, Some(r_a), None, None, Some(imm_x), None)?)
            }

            // Group 4: two immediates
            STORE_IMM_U8 | STORE_IMM_U16 | STORE_IMM_U32 | STORE_IMM_U64 => {
                let l_x_val = 4.min(single_inst_blob[1] % 8) as usize;
                let l_x = ImmSize::from(l_x_val);
                let l_y = ImmSize::from(4.min(0.max(skip_distance.saturating_sub(l_x_val + 1))));
                let imm_x = Self::extract_imm_value(single_inst_blob, l_x, 2)?;
                let imm_y = Self::extract_imm_value(single_inst_blob, l_y, 2 + l_x_val)?;

                Ok(Self::new(op, None, None, None, Some(imm_x), Some(imm_y))?)
            }

            // Group 5: one offset
            JUMP => {
                let l_x = ImmSize::from(4.min(skip_distance));
                let imm_x = Self::extract_imm_target_address(current_pc, single_inst_blob, l_x, 1)?;

                Ok(Self::new(op, None, None, None, Some(imm_x), None)?)
            }

            // Group 6: one register & one immediate
            JUMP_IND | LOAD_IMM | LOAD_U8 | LOAD_I8 | LOAD_U16 | LOAD_I16 | LOAD_U32 | LOAD_I32
            | LOAD_U64 | STORE_U8 | STORE_U16 | STORE_U32 | STORE_U64 => {
                let r_a = 12.min(single_inst_blob[1] % 16) as usize;
                let l_x = ImmSize::from(4.min(0.max(skip_distance - 1)));
                let imm_x = Self::extract_imm_value(single_inst_blob, l_x, 2)?;

                Ok(Self::new(op, Some(r_a), None, None, Some(imm_x), None)?)
            }

            // Group 7: one register & two immediates
            STORE_IMM_IND_U8 | STORE_IMM_IND_U16 | STORE_IMM_IND_U32 | STORE_IMM_IND_U64 => {
                let r_a = 12.min(single_inst_blob[1] % 16) as usize;
                let l_x_val = 4.min((single_inst_blob[1] / 16) % 8) as usize;
                let l_x = ImmSize::from(l_x_val);
                let l_y = ImmSize::from(4.min(0.max(skip_distance.saturating_sub(l_x_val + 1))));
                let imm_x = Self::extract_imm_value(single_inst_blob, l_x, 2)?;
                let imm_y = Self::extract_imm_value(single_inst_blob, l_y, 2 + l_x_val)?;

                Ok(Self::new(
                    op,
                    Some(r_a),
                    None,
                    None,
                    Some(imm_x),
                    Some(imm_y),
                )?)
            }

            // Group 8: one register, one immediate and one offset
            LOAD_IMM_JUMP | BRANCH_EQ_IMM | BRANCH_NE_IMM | BRANCH_LT_U_IMM | BRANCH_LE_U_IMM
            | BRANCH_GE_U_IMM | BRANCH_GT_U_IMM | BRANCH_LT_S_IMM | BRANCH_LE_S_IMM
            | BRANCH_GE_S_IMM | BRANCH_GT_S_IMM => {
                let r_a = 12.min(single_inst_blob[1] % 16) as usize;
                let l_x_val = 4.min((single_inst_blob[1] / 16) % 8) as usize;
                let l_x = ImmSize::from(l_x_val);
                let l_y = ImmSize::from(4.min(0.max(skip_distance.saturating_sub(l_x_val + 1))));
                let imm_x = Self::extract_imm_value(single_inst_blob, l_x, 2)?;
                let imm_y = Self::extract_imm_target_address(
                    current_pc,
                    single_inst_blob,
                    l_y,
                    2 + l_x_val,
                )?;

                Ok(Self::new(
                    op,
                    Some(r_a),
                    None,
                    None,
                    Some(imm_x),
                    Some(imm_y),
                )?)
            }

            // Group 9: two registers
            MOVE_REG
            | SBRK
            | COUNT_SET_BITS_64
            | COUNT_SET_BITS_32
            | LEADING_ZERO_BITS_64
            | LEADING_ZERO_BITS_32
            | TRAILING_ZERO_BITS_64
            | TRAILING_ZERO_BITS_32
            | SIGN_EXTEND_8
            | SIGN_EXTEND_16
            | ZERO_EXTEND_16
            | REVERSE_BYTES => {
                let r_d = 12.min(single_inst_blob[1] % 16) as usize;
                let r_a = 12.min(single_inst_blob[1] / 16) as usize;

                Ok(Self::new(op, Some(r_a), None, Some(r_d), None, None)?)
            }

            // Group 10: two register & one immediate
            STORE_IND_U8 | STORE_IND_U16 | STORE_IND_U32 | STORE_IND_U64 | LOAD_IND_U8
            | LOAD_IND_I8 | LOAD_IND_U16 | LOAD_IND_I16 | LOAD_IND_U32 | LOAD_IND_I32
            | LOAD_IND_U64 | ADD_IMM_32 | AND_IMM | XOR_IMM | OR_IMM | MUL_IMM_32
            | SET_LT_U_IMM | SET_LT_S_IMM | SHLO_L_IMM_32 | SHLO_R_IMM_32 | SHAR_R_IMM_32
            | NEG_ADD_IMM_32 | SET_GT_U_IMM | SET_GT_S_IMM | SHLO_L_IMM_ALT_32
            | SHLO_R_IMM_ALT_32 | SHAR_R_IMM_ALT_32 | CMOV_IZ_IMM | CMOV_NZ_IMM | ADD_IMM_64
            | MUL_IMM_64 | SHLO_L_IMM_64 | SHLO_R_IMM_64 | SHAR_R_IMM_64 | NEG_ADD_IMM_64
            | SHLO_L_IMM_ALT_64 | SHLO_R_IMM_ALT_64 | SHAR_R_IMM_ALT_64 | ROT_R_64_IMM
            | ROT_R_64_IMM_ALT | ROT_R_32_IMM | ROT_R_32_IMM_ALT => {
                let r_a = 12.min(single_inst_blob[1] % 16) as usize;
                let r_b = 12.min(single_inst_blob[1] / 16) as usize;
                let l_x = ImmSize::from(4.min(0.max(skip_distance - 1)));
                let imm_x = Self::extract_imm_value(single_inst_blob, l_x, 2)?;

                Ok(Self::new(
                    op,
                    Some(r_a),
                    Some(r_b),
                    None,
                    Some(imm_x),
                    None,
                )?)
            }

            // Group 11: two registers & one offset
            BRANCH_EQ | BRANCH_NE | BRANCH_LT_U | BRANCH_LT_S | BRANCH_GE_U | BRANCH_GE_S => {
                let r_a = 12.min(single_inst_blob[1] % 16) as usize;
                let r_b = 12.min(single_inst_blob[1] / 16) as usize;
                let l_x = ImmSize::from(4.min(0.max(skip_distance.saturating_sub(1))));
                let imm_x = Self::extract_imm_target_address(current_pc, single_inst_blob, l_x, 2)?;

                Ok(Self::new(
                    op,
                    Some(r_a),
                    Some(r_b),
                    None,
                    Some(imm_x),
                    None,
                )?)
            }

            // Group 12: two registers & two immediates
            LOAD_IMM_JUMP_IND => {
                let r_a = 12.min(single_inst_blob[1] % 16) as usize;
                let r_b = 12.min(single_inst_blob[1] / 16) as usize;
                let l_x_val = 4.min(single_inst_blob[2] % 8) as usize;
                let l_x = ImmSize::from(l_x_val);
                let l_y = ImmSize::from(4.min(0.max(skip_distance.saturating_sub(l_x_val + 2))));
                let imm_x = Self::extract_imm_value(single_inst_blob, l_x, 3)?;
                let imm_y = Self::extract_imm_value(single_inst_blob, l_y, 3 + l_x_val)?;

                Ok(Self::new(
                    op,
                    Some(r_a),
                    Some(r_b),
                    None,
                    Some(imm_x),
                    Some(imm_y),
                )?)
            }

            // Group 13: three registers
            ADD_32 | SUB_32 | MUL_32 | DIV_U_32 | DIV_S_32 | REM_U_32 | REM_S_32 | SHLO_L_32
            | SHLO_R_32 | SHAR_R_32 | ADD_64 | SUB_64 | MUL_64 | DIV_U_64 | DIV_S_64 | REM_U_64
            | REM_S_64 | SHLO_L_64 | SHLO_R_64 | SHAR_R_64 | AND | XOR | OR | MUL_UPPER_S_S
            | MUL_UPPER_U_U | MUL_UPPER_S_U | SET_LT_U | SET_LT_S | CMOV_IZ | CMOV_NZ
            | ROT_L_64 | ROT_L_32 | ROT_R_64 | ROT_R_32 | AND_INV | OR_INV | XNOR | MAX | MAX_U
            | MIN | MIN_U => {
                let r_a = 12.min(single_inst_blob[1] % 16) as usize;
                let r_b = 12.min(single_inst_blob[1] / 16) as usize;
                let r_d = 12.min(single_inst_blob[2]) as usize;

                Ok(Self::new(op, Some(r_a), Some(r_b), Some(r_d), None, None)?)
            }
        }
    }

    pub fn imm1(&self) -> Result<RegValue, VMCoreError> {
        self.imm1.ok_or(VMCoreError::ImmValNotFound(self.op))
    }

    pub fn imm2(&self) -> Result<RegValue, VMCoreError> {
        self.imm2.ok_or(VMCoreError::ImmValNotFound(self.op))
    }

    pub fn rs1(&self) -> Result<usize, VMCoreError> {
        self.rs1.ok_or(VMCoreError::SourceRegIdxNotFound(self.op))
    }

    pub fn rs2(&self) -> Result<usize, VMCoreError> {
        self.rs2.ok_or(VMCoreError::SourceRegIdxNotFound(self.op))
    }

    pub fn rd(&self) -> Result<usize, VMCoreError> {
        self.rd
            .ok_or(VMCoreError::DestinationRegIdxNotFound(self.op))
    }

    /// Extracts and processes an immediate value from the instruction blob.
    fn extract_imm_value(
        single_inst_blob: &[u8],
        imm_size: ImmSize,
        start_index: usize,
    ) -> Result<RegValue, VMCoreError> {
        // `imm_size_val` is at most 4 by the specification
        let imm_size_val = imm_size.as_usize();
        if imm_size_val > 0 {
            let mut buffer = [0u8; 4];
            buffer[..imm_size_val]
                .copy_from_slice(&single_inst_blob[start_index..(start_index + imm_size_val)]);
            Ok(VMUtils::sext(
                u32::decode_fixed(&mut &buffer[..imm_size_val], imm_size_val)?,
                SextInputSize::from(imm_size),
            ))
        } else {
            Ok(0)
        }
    }

    /// Extracts and processes an immediate offset (pc increment) value from the instruction blob.
    fn extract_imm_target_address(
        current_pc: RegValue,
        single_inst_blob: &[u8],
        imm_size: ImmSize,
        start_index: usize,
    ) -> Result<RegValue, VMCoreError> {
        let imm_size_val = imm_size.as_usize();
        let pc_offset = if imm_size_val > 0 {
            let mut buffer = [0u8; 4];
            buffer[..imm_size_val]
                .copy_from_slice(&single_inst_blob[start_index..(start_index + imm_size_val)]);
            VMUtils::unsigned_to_signed(
                u64::decode_fixed(&mut &buffer[..imm_size_val], imm_size_val)?,
                imm_size_val,
            )
            .ok_or(VMCoreError::InvalidInstructionFormat)?
        } else {
            0
        };

        Ok((current_pc as i64 + pc_offset) as RegValue)
    }

    fn extract_imm_extended_width(
        single_inst_blob: &[u8],
        start_index: usize,
    ) -> Result<RegValue, VMCoreError> {
        let mut buffer = [0u8; 8];
        buffer[..8].copy_from_slice(&single_inst_blob[start_index..(start_index + 8)]);
        let imm = u64::decode_fixed(&mut &buffer[..8], 8)?;
        Ok(imm)
    }
}
