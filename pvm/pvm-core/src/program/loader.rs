use crate::{
    error::VMCoreError,
    interpreter::Interpreter,
    program::{
        instruction::opcode::Opcode,
        types::program_state::{OpcodeBitmask, ProgramState},
    },
};
use bitvec::prelude::*;
use fr_codec::prelude::*;
use fr_pvm_types::common::MemAddress;

pub struct ProgramLoader;
impl ProgramLoader {
    /// Decodes a program code blob and loads it into the PVM program state components:
    /// instructions, an opcode bitmask, a dynamic jump table and a basic block bitmask.
    pub fn load_program(
        program_code: &[u8],
        program_state: &mut ProgramState,
    ) -> Result<(), VMCoreError> {
        // Decode program code into (instructions blob, opcode bitmask, dynamic jump table)
        let (instructions, opcode_bitmask, jump_table) = Self::deblob_program_code(program_code)?;

        // Initialize immutable PVM states: instructions, opcode_bitmask, jump_table and basic_block_bitmask
        program_state.instructions = instructions;
        program_state.opcode_bitmask = opcode_bitmask;
        program_state.jump_table = jump_table;
        Self::set_basic_block_start_indices(program_state)?;
        tracing::info!("Program loaded.");
        program_state.print_all_opcodes();
        program_state.is_loaded = true;
        Ok(())
    }

    /// Decodes code element of the formatted program code into
    /// instruction sequence (c), opcode bitmask (k) and dynamic jump table (j).
    /// Used by `Ψ`.
    pub fn deblob_program_code(
        mut code: &[u8],
    ) -> Result<(Vec<u8>, OpcodeBitmask, Vec<MemAddress>), VMCoreError> {
        let input = &mut code;

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
        let opcode_bitmask = BitVec::decode_fixed(input, instructions_len)?;

        if !input.is_empty() {
            return Err(VMCoreError::InvalidProgram);
        }

        Ok((instructions, opcode_bitmask, jump_table))
    }

    /// Collects opcode indices that indicate beginning of basic blocks and sets the
    /// `basic_block_start_indices` of the `ProgramState`.
    fn set_basic_block_start_indices(program: &mut ProgramState) -> Result<(), VMCoreError> {
        program.basic_block_start_indices.insert(0);
        let instructions_len = program.instructions.len();
        for n in 1..instructions_len {
            if program
                .opcode_bitmask
                .get(n)
                .map(|bit| *bit)
                .unwrap_or(false)
            {
                if let Some(&op_val) = program.instructions.get(n) {
                    let op = Opcode::from_u8(op_val);
                    if op.is_termination_opcode() {
                        let next_op_index = n + 1 + Interpreter::skip(n, &program.opcode_bitmask);
                        program.basic_block_start_indices.insert(next_op_index);
                    }
                }
            }
        }
        Ok(())
    }
}
