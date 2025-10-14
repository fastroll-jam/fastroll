use crate::program::instruction::opcode::Opcode;
use bitvec::prelude::*;
use fr_pvm_types::common::MemAddress;
use std::collections::HashSet;

pub type OpcodeBitmask = BitVec<u8, Lsb0>;

/// Immutable VM state (program components)
///
/// Represents `code` of `FormattedProgram` decoded.
#[derive(Debug, Default)]
pub struct ProgramState {
    /// `c`: Serialized instructions blob.
    pub instructions: Vec<u8>,
    /// `j`: Dynamic jump table.
    pub jump_table: Vec<MemAddress>,
    /// `k`: Opcode bitmask.
    pub opcode_bitmask: OpcodeBitmask,
    /// Opcode indices that are beginning of basic-blocks.
    pub basic_block_start_indices: HashSet<usize>,
    /// Boolean flag indicating whether program is loaded.
    pub is_loaded: bool,
}

impl ProgramState {
    pub fn print_all_opcodes(&self) {
        tracing::trace!("All Opcodes");
        self.instructions
            .iter()
            .zip(self.opcode_bitmask.iter())
            .for_each(|(byte, opcode)| {
                if *opcode {
                    tracing::trace!("Op: {:?}", Opcode::from_u8(*byte));
                }
            })
    }
}
