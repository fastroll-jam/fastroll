use crate::{
    interpreter::Interpreter,
    program::{decoder::ProgramDecoder, opcode::Opcode},
    state::program_state::ProgramState,
    types::error::PVMError,
};

pub struct ProgramLoader;
impl ProgramLoader {
    /// Decodes a program code blob and loads it into the PVM program state components:
    /// instructions, an opcode bitmask, a dynamic jump table and a basic block bitmask.
    pub fn load_program(
        program_code: &[u8],
        program_state: &mut ProgramState,
    ) -> Result<(), PVMError> {
        // Decode program code into (instructions blob, opcode bitmask, dynamic jump table)
        let (instructions, opcode_bitmask, jump_table) =
            ProgramDecoder::deblob_program_code(program_code)?;

        // Initialize immutable PVM states: instructions, opcode_bitmask, jump_table and basic_block_bitmask
        program_state.instructions = instructions;
        program_state.opcode_bitmask = opcode_bitmask;
        program_state.jump_table = jump_table;
        Self::set_basic_block_start_indices(program_state)?;
        program_state.is_loaded = true;
        Ok(())
    }

    /// Collects opcode indices that indicate beginning of basic blocks and sets the
    /// `basic_block_start_indices` of the `ProgramState`.
    fn set_basic_block_start_indices(program: &mut ProgramState) -> Result<(), PVMError> {
        program.basic_block_start_indices.insert(0);
        let instructions_len = program.instructions.len();
        for n in 1..instructions_len {
            if let Some(true) = program.opcode_bitmask.get(n) {
                if let Some(&op_val) = program.instructions.get(n) {
                    let op = Opcode::from_u8(op_val)?;
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
