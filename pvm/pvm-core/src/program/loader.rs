use crate::{
    error::VMCoreError,
    program::{
        instruction::{opcode::Opcode, Instruction},
        types::program_state::{OpcodeBitmask, ProgramState, NOT_INSTRUCTION_INDEX},
    },
};
use bitvec::prelude::*;
use fr_codec::prelude::*;
use fr_pvm_types::{
    common::{MemAddress, RegValue},
    constants::{
        MAX_INSTRUCTION_DATA_SIZE, MAX_INST_BLOB_LENGTH, MAX_JUMP_TABLE_ENTRY_COUNT,
        MAX_JUMP_TABLE_ENTRY_SIZE, MAX_SKIP_DISTANCE,
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
        program_state.skip_distances = Self::compute_skip_distances(&program_state.opcode_bitmask);
        let (decoded_instructions, instruction_lookup) = Self::decode_instructions(
            &program_state.instructions,
            &program_state.opcode_bitmask,
            &program_state.skip_distances,
        )?;
        program_state.decoded_instructions = decoded_instructions;
        program_state.instruction_lookup = instruction_lookup;
        Self::set_basic_block_start_indices(program_state);
        tracing::info!("Program loaded.");
        if tracing::enabled!(Level::TRACE) {
            program_state.print_all_opcodes();
        }
        Ok(())
    }

    /// Decodes code element of the formatted program code into instruction data (c), opcode bitmask (k) and dynamic jump table (j).
    /// Used by `Ψ` and the `machine` host call.
    ///
    /// Fails when `|j|` exceeds `Z_J`, `z` exceeds `MAX_JUMP_TABLE_ENTRY_SIZE`, `|c|` exceeds `Z_C`, or the rest of the blob is not exactly `j`, `c` and `k` with zero padding bits.
    /// All sizes are checked before any data is read, so a truncated blob cannot reserve the sizes its header claims.
    /// Also fails when the instruction sequence is invalid by `v_blob`.
    /// The check of the start PC by `v_inst` is left to the caller, e.g. `instruction_at` in `Ψ`.
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

        // Decode the opcode bitmask (k). Its padding bits must be zero, since only then the blob encodes `k`.
        let padding_bit_count = opcode_bitmask_size * 8 - instruction_data_size;
        if padding_bit_count > 0 && input[opcode_bitmask_size - 1] >> (8 - padding_bit_count) != 0 {
            return Err(VMCoreError::InvalidProgram);
        }
        let opcode_bitmask = BitVec::decode_fixed(input, instruction_data_size)?;

        if !Self::is_valid_instruction_sequence(&instruction_data, &opcode_bitmask) {
            return Err(VMCoreError::InvalidInstructionSequence);
        }

        Ok((instruction_data, opcode_bitmask, jump_table))
    }

    /// Checks `v_blob` of the GP. Walking from index 0, every instruction has a valid opcode and the last one ends a basic block.
    ///
    /// An empty `c` or a gap of more than `MAX_SKIP_DISTANCE` octets between opcodes is invalid.
    fn is_valid_instruction_sequence(
        instruction_data: &[u8],
        opcode_bitmask: &OpcodeBitmask,
    ) -> bool {
        let instruction_data_size = instruction_data.len();
        let mut index = 0;
        loop {
            if index > 0 && index == instruction_data_size {
                return true;
            }
            if !Self::is_valid_instruction_start(instruction_data, opcode_bitmask, index) {
                return false;
            }
            let next_index = index + 1 + Self::skip_distance(opcode_bitmask, index);
            let is_termination = Opcode::from_u8(instruction_data[index])
                .is_some_and(|opcode| opcode.is_termination_opcode());
            if next_index == instruction_data_size && !is_termination {
                return false;
            }
            index = next_index;
        }
    }

    /// Checks `v_inst` of the GP, whether `index` (0-based, in octets) is the opcode of an instruction with a valid opcode.
    pub fn is_valid_instruction_start(
        instruction_data: &[u8],
        opcode_bitmask: &OpcodeBitmask,
        index: usize,
    ) -> bool {
        opcode_bitmask.len() == instruction_data.len()
            && opcode_bitmask.get(index).is_some_and(|bit| *bit)
            && Opcode::from_u8(instruction_data[index]).is_some()
    }

    /// Computes `skip(index)` of the GP from `k` extended with set bits.
    fn skip_distance(opcode_bitmask: &OpcodeBitmask, index: usize) -> usize {
        (0..MAX_SKIP_DISTANCE)
            .find(|distance| {
                opcode_bitmask
                    .get(index + 1 + distance)
                    .is_none_or(|bit| *bit)
            })
            .unwrap_or(MAX_SKIP_DISTANCE)
    }

    /// Marks the basic block starts (`ϖ`) in `basic_block_start_indices` of the `ProgramState`.
    ///
    /// They are index 0 and each instruction that follows a block-terminating instruction, as 0-based octet indices.
    fn set_basic_block_start_indices(program: &mut ProgramState) {
        let instruction_data_size = program.instructions.len();
        program.basic_block_start_indices = bitvec![u8, Lsb0; 0; instruction_data_size];
        if program.instruction_at(0).is_some() {
            program.basic_block_start_indices.set(0, true);
        }
        for index in 0..instruction_data_size {
            let Some(instruction) = program.instruction_at(index) else {
                continue;
            };
            if !instruction.op.is_termination_opcode() {
                continue;
            }
            let skip = program.skip_distance(index).unwrap_or(MAX_SKIP_DISTANCE);
            let next_index = index + 1 + skip;
            if program.instruction_at(next_index).is_some() {
                program.basic_block_start_indices.set(next_index, true);
            }
        }
    }

    /// Precomputes `skip` for every octet index of the instruction data.
    fn compute_skip_distances(opcode_bitmask: &OpcodeBitmask) -> Vec<u8> {
        (0..opcode_bitmask.len())
            .map(|index| Self::skip_distance(opcode_bitmask, index) as u8)
            .collect()
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
            // Octets past `c` read as zero
            let mut instruction_octets = [0u8; MAX_INST_BLOB_LENGTH];
            let available_octets =
                &instructions[idx..(idx + MAX_INST_BLOB_LENGTH).min(instructions.len())];
            instruction_octets[..available_octets.len()].copy_from_slice(available_octets);
            let inst = Instruction::from_inst_blob(&instruction_octets, idx as RegValue, skip)?;
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

    /// Encodes a program blob with an empty jump table, the instruction data `c` and the opcode bitmask `k`.
    fn program_blob(
        instruction_data: &[u8],
        opcode_bitmask: &[bool],
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut blob = blob_header(0, 0, instruction_data.len())?;
        blob.extend(instruction_data);
        let opcode_bitmask: OpcodeBitmask = opcode_bitmask.iter().collect();
        blob.extend(opcode_bitmask.encode_fixed(instruction_data.len())?);
        Ok(blob)
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

    mod instruction_sequence_tests {
        use super::*;

        const UNLIKELY: u8 = Opcode::UNLIKELY as u8;
        const TRAP: u8 = Opcode::TRAP as u8;

        fn assert_invalid_instruction_sequence(blob: &[u8]) {
            assert!(matches!(
                ProgramLoader::deblob_program_code(blob),
                Err(VMCoreError::InvalidInstructionSequence)
            ));
        }

        #[test]
        fn test_deblob_accepts_sequence_ending_with_termination() -> Result<(), Box<dyn Error>> {
            let blob = program_blob(&[UNLIKELY, TRAP], &[true, true])?;
            ProgramLoader::deblob_program_code(&blob)?;
            Ok(())
        }

        #[test]
        fn test_deblob_accepts_opcode_gap_of_max_skip_distance() -> Result<(), Box<dyn Error>> {
            // The next opcode is 25 octets after the first, which `skip` of 24 reaches
            let mut instruction_data = vec![0; MAX_SKIP_DISTANCE + 2];
            instruction_data[0] = UNLIKELY;
            let mut opcode_bitmask = vec![false; instruction_data.len()];
            opcode_bitmask[0] = true;
            opcode_bitmask[MAX_SKIP_DISTANCE + 1] = true;
            ProgramLoader::deblob_program_code(&program_blob(&instruction_data, &opcode_bitmask)?)?;
            Ok(())
        }

        #[test]
        fn test_deblob_accepts_argument_octets_after_last_instruction() -> Result<(), Box<dyn Error>>
        {
            // `skip` of the last `trap` reaches the end of `c` through `k` extended with set bits
            let blob = program_blob(&[TRAP, 0, 0], &[true, false, false])?;
            ProgramLoader::deblob_program_code(&blob)?;
            Ok(())
        }

        #[test]
        fn test_deblob_rejects_nonzero_bitmask_padding() -> Result<(), Box<dyn Error>> {
            let mut blob = program_blob(&[TRAP], &[true])?;
            // Bit 1 of the only `k` octet is padding past `|c| = 1`
            *blob.last_mut().ok_or("empty blob")? |= 0b10;
            assert!(matches!(
                ProgramLoader::deblob_program_code(&blob),
                Err(VMCoreError::InvalidProgram)
            ));
            Ok(())
        }

        #[test]
        fn test_deblob_rejects_empty_instruction_data() -> Result<(), Box<dyn Error>> {
            assert_invalid_instruction_sequence(&program_blob(&[], &[])?);
            Ok(())
        }

        #[test]
        fn test_deblob_rejects_last_instruction_without_termination() -> Result<(), Box<dyn Error>>
        {
            assert_invalid_instruction_sequence(&program_blob(&[UNLIKELY], &[true])?);
            Ok(())
        }

        #[test]
        fn test_deblob_rejects_unknown_opcode() -> Result<(), Box<dyn Error>> {
            // Opcode 3 is outside `U`
            assert_invalid_instruction_sequence(&program_blob(&[3, TRAP], &[true, true])?);
            Ok(())
        }

        #[test]
        fn test_deblob_rejects_first_octet_without_opcode() -> Result<(), Box<dyn Error>> {
            assert_invalid_instruction_sequence(&program_blob(&[TRAP, TRAP], &[false, true])?);
            Ok(())
        }

        #[test]
        fn test_deblob_rejects_opcode_gap_beyond_max_skip_distance() -> Result<(), Box<dyn Error>> {
            // The next opcode is 26 octets after the first, but `skip` stops at 24
            let mut instruction_data = vec![0; MAX_SKIP_DISTANCE + 3];
            instruction_data[0] = UNLIKELY;
            let mut opcode_bitmask = vec![false; instruction_data.len()];
            opcode_bitmask[0] = true;
            opcode_bitmask[MAX_SKIP_DISTANCE + 2] = true;
            assert_invalid_instruction_sequence(&program_blob(&instruction_data, &opcode_bitmask)?);
            Ok(())
        }

        #[test]
        fn test_basic_block_starts_follow_terminations() -> Result<(), Box<dyn Error>> {
            // `trap` at 0 starts the block at 1. `trap` at 2 ends the code, which is not a block start.
            let blob = program_blob(&[TRAP, UNLIKELY, TRAP], &[true, true, true])?;
            let mut program_state = ProgramState::default();
            ProgramLoader::load_program(&blob, &mut program_state)?;
            let basic_block_starts: Vec<usize> = program_state
                .basic_block_start_indices
                .iter_ones()
                .collect();
            assert_eq!(basic_block_starts, vec![0, 1]);
            Ok(())
        }
    }

    #[test]
    fn test_decode_reads_arguments_past_next_opcode() -> Result<(), Box<dyn Error>> {
        // `load_imm` has `skip` 0, so its `r_A` is the next opcode `move_reg` (100) mod 16
        let instruction_data = [
            Opcode::LOAD_IMM as u8,
            Opcode::MOVE_REG as u8,
            0,
            Opcode::TRAP as u8,
        ];
        let blob = program_blob(&instruction_data, &[true, true, false, true])?;
        let mut program_state = ProgramState::default();
        ProgramLoader::load_program(&blob, &mut program_state)?;
        let load_imm = program_state
            .instruction_at(0)
            .ok_or("no instruction at 0")?;
        assert_eq!(load_imm.rs1, Some(4));
        assert_eq!(load_imm.imm1, Some(0));
        Ok(())
    }
}
