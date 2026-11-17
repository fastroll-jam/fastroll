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
    constants::{
        MAX_INSTRUCTION_DATA_SIZE, MAX_JUMP_TABLE_ENTRY_COUNT, MAX_JUMP_TABLE_ENTRY_SIZE,
        MAX_SKIP_DISTANCE,
    },
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
        program_state.basic_block_start_indices =
            bitvec![u8, Lsb0; 0; program_state.instructions.len() + 1];
        Self::set_basic_block_start_indices(program_state)?;
        tracing::info!("Program loaded.");
        if tracing::enabled!(Level::TRACE) {
            program_state.print_all_opcodes();
        }
        Ok(())
    }

    /// Decodes code element of the formatted program code into instruction data (c), opcode bitmask (k) and dynamic jump table (j).
    /// Used by `Ψ` and the `machine` host call.
    ///
    /// Fails when `|j|` exceeds `Z_J`, `z` exceeds `MAX_JUMP_TABLE_ENTRY_SIZE`, `|c|` exceeds `Z_C`, or the rest of the blob is not exactly `j`, `c` and `k`.
    /// All sizes are checked before any data is read, so a truncated blob cannot reserve the sizes its header claims.
    pub fn deblob_program_code(
        mut code: &[u8],
    ) -> Result<(Vec<u8>, OpcodeBitmask, Vec<MemAddress>), VMCoreError> {
        let input = &mut code;

        // Decode the jump table entry count (|j|)
        let jump_table_entry_count = usize::decode(input)?;
        if jump_table_entry_count > MAX_JUMP_TABLE_ENTRY_COUNT {
            return Err(VMCoreError::JumpTableEntryCountLimitExceeded(
                jump_table_entry_count,
            ));
        }

        // Decode the jump table entry size in octets (z)
        let jump_table_entry_size = u8::decode_fixed(input, 1)?;
        if jump_table_entry_size as usize > MAX_JUMP_TABLE_ENTRY_SIZE {
            return Err(VMCoreError::JumpTableEntrySizeLimitExceeded(
                jump_table_entry_size,
            ));
        }

        // Decode the instruction data size (|c|)
        let instruction_data_size = usize::decode(input)?;
        if instruction_data_size > MAX_INSTRUCTION_DATA_SIZE {
            return Err(VMCoreError::InstructionDataSizeLimitExceeded(
                instruction_data_size,
            ));
        }

        // The rest of the blob is exactly `j`, `c` and `k`, where `|k| = |c|` in bits.
        // The bounds above keep the sum below `2^27`.
        let jump_table_size = jump_table_entry_count * jump_table_entry_size as usize;
        let opcode_bitmask_size = instruction_data_size.div_ceil(8);
        if input.len() != jump_table_size + instruction_data_size + opcode_bitmask_size {
            return Err(VMCoreError::InvalidProgram);
        }

        // Decode the dynamic jump table (j)
        let mut jump_table = Vec::with_capacity(jump_table_entry_count);
        for _ in 0..jump_table_entry_count {
            jump_table.push(MemAddress::decode_fixed(
                input,
                jump_table_entry_size as usize,
            )?);
        }

        // Decode the instruction data (c)
        let instruction_data = Vec::<u8>::decode_fixed(input, instruction_data_size)?;

        // Decode the opcode bitmask (k)
        let opcode_bitmask = BitVec::decode_fixed(input, instruction_data_size)?;

        Ok((instruction_data, opcode_bitmask, jump_table))
    }

    /// Collects opcode indices that indicate beginning of basic blocks and sets the
    /// `basic_block_start_indices` of the `ProgramState`.
    fn set_basic_block_start_indices(program: &mut ProgramState) -> Result<(), VMCoreError> {
        program.basic_block_start_indices.set(0, true);
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
                        if next_op_index < program.basic_block_start_indices.len() {
                            program.basic_block_start_indices.set(next_op_index, true);
                        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::instruction::opcode::Opcode;
    use std::error::Error;

    /// Encodes the length fields `E(|j|) ⌢ E_1(z) ⌢ E(|c|)` that open a program blob.
    fn blob_header(
        jump_table_entry_count: usize,
        jump_table_entry_size: u8,
        instruction_data_size: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut header = jump_table_entry_count.encode()?;
        header.extend(jump_table_entry_size.encode_fixed(1)?);
        header.extend(instruction_data_size.encode()?);
        Ok(header)
    }

    /// Appends instruction data (c) of `trap_count` `trap` instructions and its opcode bitmask (k).
    ///
    /// Each octet starts a `trap`, which also ends a basic block, so the program stays valid under the `v_blob` check of GP #508.
    fn append_traps(blob: &mut Vec<u8>, trap_count: usize) -> Result<(), Box<dyn Error>> {
        blob.resize(blob.len() + trap_count, Opcode::TRAP as u8);
        let opcode_bitmask: OpcodeBitmask = BitVec::repeat(true, trap_count);
        blob.extend(opcode_bitmask.encode_fixed(trap_count)?);
        Ok(())
    }

    #[test]
    fn test_deblob_jump_table_entry_count_limit() -> Result<(), Box<dyn Error>> {
        // Zero-sized entries keep a jump table of `Z_J` entries out of the blob
        let mut blob = blob_header(MAX_JUMP_TABLE_ENTRY_COUNT, 0, 1)?;
        append_traps(&mut blob, 1)?;
        let (_, _, jump_table) = ProgramLoader::deblob_program_code(&blob)?;
        assert_eq!(jump_table.len(), MAX_JUMP_TABLE_ENTRY_COUNT);

        let blob = blob_header(MAX_JUMP_TABLE_ENTRY_COUNT + 1, 0, 1)?;
        assert!(matches!(
            ProgramLoader::deblob_program_code(&blob),
            Err(VMCoreError::JumpTableEntryCountLimitExceeded(count))
                if count == MAX_JUMP_TABLE_ENTRY_COUNT + 1
        ));
        Ok(())
    }

    #[test]
    fn test_deblob_jump_table_entry_size_limit() -> Result<(), Box<dyn Error>> {
        let mut blob = blob_header(1, MAX_JUMP_TABLE_ENTRY_SIZE as u8, 1)?;
        blob.extend(u32::MAX.to_le_bytes());
        append_traps(&mut blob, 1)?;
        let (_, _, jump_table) = ProgramLoader::deblob_program_code(&blob)?;
        assert_eq!(jump_table, vec![u32::MAX]);

        // An empty jump table still fails with an oversized entry size
        let blob = blob_header(0, MAX_JUMP_TABLE_ENTRY_SIZE as u8 + 1, 1)?;
        assert!(matches!(
            ProgramLoader::deblob_program_code(&blob),
            Err(VMCoreError::JumpTableEntrySizeLimitExceeded(size))
                if size as usize == MAX_JUMP_TABLE_ENTRY_SIZE + 1
        ));
        Ok(())
    }

    #[test]
    fn test_deblob_instruction_data_size_limit() -> Result<(), Box<dyn Error>> {
        let mut blob = blob_header(0, 0, MAX_INSTRUCTION_DATA_SIZE)?;
        append_traps(&mut blob, MAX_INSTRUCTION_DATA_SIZE)?;
        let (instruction_data, opcode_bitmask, _) = ProgramLoader::deblob_program_code(&blob)?;
        assert_eq!(instruction_data.len(), MAX_INSTRUCTION_DATA_SIZE);
        assert_eq!(opcode_bitmask.len(), MAX_INSTRUCTION_DATA_SIZE);

        // Fails on the size field alone, before reading or allocating `c`
        let blob = blob_header(0, 0, MAX_INSTRUCTION_DATA_SIZE + 1)?;
        assert!(matches!(
            ProgramLoader::deblob_program_code(&blob),
            Err(VMCoreError::InstructionDataSizeLimitExceeded(size))
                if size == MAX_INSTRUCTION_DATA_SIZE + 1
        ));
        Ok(())
    }

    #[test]
    fn test_deblob_rejects_rest_not_matching_sizes() -> Result<(), Box<dyn Error>> {
        // A header that claims the largest jump table without its data
        let mut blob = blob_header(
            MAX_JUMP_TABLE_ENTRY_COUNT,
            MAX_JUMP_TABLE_ENTRY_SIZE as u8,
            1,
        )?;
        append_traps(&mut blob, 1)?;
        assert!(matches!(
            ProgramLoader::deblob_program_code(&blob),
            Err(VMCoreError::InvalidProgram)
        ));

        // A trailing octet after `k`
        let mut blob = blob_header(0, 0, 1)?;
        append_traps(&mut blob, 1)?;
        blob.push(0);
        assert!(matches!(
            ProgramLoader::deblob_program_code(&blob),
            Err(VMCoreError::InvalidProgram)
        ));
        Ok(())
    }
}
