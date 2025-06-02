use crate::program::instruction::opcode::Opcode;
use bit_vec::BitVec;
use fr_codec::prelude::*;
use fr_pvm_types::common::MemAddress;
use std::collections::HashSet;

/// Immutable VM state (program components)
///
/// Represents `code` of `FormattedProgram` decoded.
#[derive(Debug, Default)]
pub struct ProgramState {
    /// `c`: Serialized instructions blob.
    pub instructions: Vec<u8>, // TODO: define instruction_blob with endless zeroes padding
    /// `j`: Dynamic jump table.
    pub jump_table: Vec<MemAddress>,
    /// `k`: Opcode bitmask.
    pub opcode_bitmask: BitVec,
    /// Opcode indices that are beginning of basic-blocks.
    pub basic_block_start_indices: HashSet<usize>,
    /// Boolean flag indicating whether program is loaded.
    pub is_loaded: bool,
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
        let opcode_bitmask = BitVec::decode_fixed(input, instructions_len)?;

        Ok(Self {
            instructions,
            jump_table,
            opcode_bitmask,
            basic_block_start_indices: HashSet::from([0]),
            is_loaded: false,
        })
    }
}

impl ProgramState {
    pub fn print_all_opcodes(&self) {
        tracing::trace!("All Opcodes");
        self.instructions
            .iter()
            .zip(self.opcode_bitmask.iter())
            .for_each(|(byte, opcode)| {
                if opcode {
                    tracing::trace!("Op: {:?}", Opcode::from_u8(*byte));
                }
            })
    }
}
