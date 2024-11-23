use crate::types::error::{PVMError, VMCoreError::InvalidOpcode};
use num_enum::TryFromPrimitive;

/// PVM Opcodes
#[repr(u8)]
#[derive(Clone, Copy, Debug, TryFromPrimitive)]
#[allow(non_camel_case_types)]
pub enum Opcode {
    TRAP = 0,
    LOAD_IND_U32 = 1,
    ADD_IMM = 2,
    STORE_IND_U32 = 3,
    LOAD_IMM = 4,
    JUMP = 5,
    LOAD_IMM_JUMP = 6,
    BRANCH_EQ_IMM = 7,
    ADD = 8,
    SHLO_L_IMM = 9,
    LOAD_U32 = 10,
    LOAD_IND_U8 = 11,
    OR = 12,
    STORE_IMM_IND_U32 = 13,
    SHLO_R_IMM = 14,
    BRANCH_NE_IMM = 15,
    STORE_IND_U8 = 16,
    FALLTHROUGH = 17,
    AND_IMM = 18,
    JUMP_IND = 19,
    SUB = 20,
    LOAD_IND_I8 = 21,
    STORE_U32 = 22,
    AND = 23,
    BRANCH_EQ = 24,
    SHAR_R_IMM = 25,
    STORE_IMM_IND_U8 = 26,
    SET_LT_U_IMM = 27,
    XOR = 28,
    STORE_IND_U16 = 29,
    BRANCH_NE = 30,
    XOR_IMM = 31,
    BRANCH_LT_S_IMM = 32,
    LOAD_IND_I16 = 33,
    MUL = 34,
    MUL_IMM = 35,
    SET_LT_U = 36,
    LOAD_IND_U16 = 37,
    STORE_IMM_U32 = 38,
    SET_GT_U_IMM = 39,
    NEG_ADD_IMM = 40,
    BRANCH_GE_U = 41,
    LOAD_IMM_JUMP_IND = 42,
    BRANCH_GE_S = 43,
    BRANCH_LT_U_IMM = 44,
    BRANCH_GE_S_IMM = 45,
    BRANCH_LE_S_IMM = 46,
    BRANCH_LT_U = 47,
    BRANCH_LT_S = 48,
    OR_IMM = 49,
    BRANCH_GT_U_IMM = 50,
    SHLO_R = 51,
    BRANCH_GE_U_IMM = 52,
    BRANCH_GT_S_IMM = 53,
    STORE_IMM_IND_U16 = 54,
    SHLO_L = 55,
    SET_LT_S_IMM = 56,
    MUL_UPPER_UU = 57,
    SET_LT_S = 58,
    BRANCH_LE_U_IMM = 59,
    LOAD_U8 = 60,
    SET_GT_S_IMM = 61,
    STORE_IMM_U8 = 62,
    MUL_UPPER_UU_IMM = 63,
    DIV_S = 64,
    MUL_UPPER_SS_IMM = 65,
    LOAD_I16 = 66,
    MUL_UPPER_SS = 67,
    DIV_U = 68,
    STORE_U16 = 69,
    REM_S = 70,
    STORE_U8 = 71,
    SHLO_R_IMM_ALT = 72,
    REM_U = 73,
    LOAD_I8 = 74,
    SHLO_L_IMM_ALT = 75,
    LOAD_U16 = 76,
    SHAR_R = 77,
    ECALLI = 78,
    STORE_IMM_U16 = 79,
    SHAR_R_IMM_ALT = 80,
    MUL_UPPER_SU = 81,
    MOVE_REG = 82,
    CMOV_IZ = 83,
    CMOV_NZ = 84,
    CMOV_IZ_IMM = 85,
    CMOV_NZ_IMM = 86,
    SBRK = 87,
}

impl Opcode {
    pub fn from_u8(value: u8) -> Result<Self, PVMError> {
        Self::try_from(value).map_err(|_| PVMError::VMCoreError(InvalidOpcode))
    }

    pub fn is_termination_opcode(&self) -> bool {
        use Opcode::*;
        matches!(
            self,
            TRAP | FALLTHROUGH
                | JUMP
                | JUMP_IND
                | LOAD_IMM_JUMP
                | LOAD_IMM_JUMP_IND
                | BRANCH_EQ
                | BRANCH_NE
                | BRANCH_GE_U
                | BRANCH_GE_S
                | BRANCH_LT_U
                | BRANCH_LT_S
                | BRANCH_EQ_IMM
                | BRANCH_NE_IMM
                | BRANCH_LT_U_IMM
                | BRANCH_LT_S_IMM
                | BRANCH_LE_U_IMM
                | BRANCH_LE_S_IMM
                | BRANCH_GE_U_IMM
                | BRANCH_GE_S_IMM
                | BRANCH_GT_U_IMM
                | BRANCH_GT_S_IMM
        )
    }
}
