use crate::program::instruction::{opcode::Opcode, Instruction};
use bitvec::prelude::*;
use fr_pvm_types::common::MemAddress;
use std::collections::HashSet;

pub(crate) const NOT_INSTRUCTION_INDEX: u32 = u32::MAX;

pub type OpcodeBitmask = BitVec<u8, Lsb0>;

pub type InstructionIndex = u32;

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
    /// Decoded instructions indexed by instruction order.
    pub decoded_instructions: Vec<Instruction>,
    /// Lookup from program counter (byte index) to decoded instruction index.
    pub instruction_lookup: Vec<InstructionIndex>,
    /// Lookup from program counter (byte index) to precomputed skip distances.
    pub skip_distances: Vec<u8>,
    /// Boolean flag indicating whether the program is loaded.
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

    pub fn skip_distance(&self, pc: usize) -> Option<usize> {
        self.skip_distances
            .get(pc)
            .map(|&distance| distance as usize)
    }

    pub fn instruction_at(&self, pc: usize) -> Option<&Instruction> {
        let idx = *self.instruction_lookup.get(pc)?;
        if idx == NOT_INSTRUCTION_INDEX {
            return None;
        }
        self.decoded_instructions.get(idx as usize)
    }
}
