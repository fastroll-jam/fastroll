use crate::{
    error::VMCoreError,
    program::{
        instruction::Instruction,
        types::program_state::{OpcodeBitmask, ProgramState, NOT_INSTRUCTION_INDEX},
    },
};
use bitvec::prelude::*;
use fr_codec::prelude::*;
use fr_pvm_types::{
    common::{MemAddress, RegValue},
    constants::MAX_SKIP_DISTANCE,
};
use tracing::Level;

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

        // Initialize immutable PVM states: instructions, opcode_bitmask, jump_table and basic_block_start_indices.
        // Additionally, decode instructions and precompute skip distances.
        program_state.instructions = instructions;
        program_state.opcode_bitmask = opcode_bitmask;
        program_state.jump_table = jump_table;
        program_state.skip_distances = Self::compute_skip_distances(
            &program_state.opcode_bitmask,
            program_state.instructions.len(),
        );
        let (decoded_instructions, instruction_lookup) = Self::decode_instructions(
            &program_state.instructions,
            &program_state.opcode_bitmask,
            &program_state.skip_distances,
        )?;
        program_state.decoded_instructions = decoded_instructions;
        program_state.instruction_lookup = instruction_lookup;
        Self::set_basic_block_start_indices(program_state)?;
        tracing::info!("Program loaded.");
        if tracing::enabled!(Level::TRACE) {
            program_state.print_all_opcodes();
        }
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
                if let Some(inst) = program.instruction_at(n) {
                    if inst.op.is_termination_opcode() {
                        let skip = program.skip_distance(n).unwrap_or(MAX_SKIP_DISTANCE);
                        let next_op_index = n + 1 + skip;
                        program.basic_block_start_indices.insert(next_op_index);
                    }
                }
            }
        }
        Ok(())
    }

    /// Precomputes the distance to the next opcode start for every byte in the instruction blob.
    ///
    /// The bitmask and instruction blob have the same lengths, so a PC value maps directly
    /// to an index into both. Each entry stores how many bytes beyond `pc + 1`
    /// the next instruction begins, capped at `MAX_SKIP_DISTANCE`.
    fn compute_skip_distances(bitmask: &OpcodeBitmask, inst_len: usize) -> Vec<u8> {
        let mut skip_distances = vec![0u8; inst_len];
        // Keep the next instruction index here to compute the skip distances
        let mut next_inst_idx: Option<usize> = None;
        // Reverse iteration
        for idx in (0..inst_len).rev() {
            let distance = match next_inst_idx {
                Some(next_idx) => next_idx.saturating_sub(idx + 1),
                None => inst_len.saturating_sub(idx + 1), // skip until the end of the blob
            };
            skip_distances[idx] = distance.min(MAX_SKIP_DISTANCE) as u8;
            if bitmask.get(idx).map(|bit| *bit).unwrap_or(false) {
                next_inst_idx = Some(idx);
            }
        }
        skip_distances
    }

    /// Decodes instructions blob and populates a `Vec<Instruction>`.
    fn decode_instructions(
        instructions: &[u8],
        opcode_bitmask: &OpcodeBitmask,
        skip_distances: &[u8],
    ) -> Result<(Vec<Instruction>, Vec<u32>), VMCoreError> {
        let mut decoded_instructions = Vec::new();
        let mut instruction_lookup = vec![NOT_INSTRUCTION_INDEX; instructions.len()];

        for (idx, is_opcode_start) in opcode_bitmask.iter().enumerate() {
            if !is_opcode_start {
                continue;
            }
            let skip = skip_distances
                .get(idx)
                .copied()
                .unwrap_or(MAX_SKIP_DISTANCE as u8) as usize;
            let next_index = idx + 1 + skip;
            let inst = if next_index > instructions.len() {
                Instruction::trap()
            } else {
                Instruction::from_inst_blob(&instructions[idx..next_index], idx as RegValue, skip)?
            };
            decoded_instructions.push(inst);
            let decoded_index = decoded_instructions.len() as u32;
            instruction_lookup[idx] = decoded_index - 1;
        }

        Ok((decoded_instructions, instruction_lookup))
    }
}
