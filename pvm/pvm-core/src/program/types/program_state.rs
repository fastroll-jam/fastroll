use crate::program::instruction::{opcode::Opcode, Instruction};
use bitvec::prelude::*;
use fr_pvm_types::common::MemAddress;

pub(crate) const NOT_INSTRUCTION_INDEX: u32 = u32::MAX;

pub type OpcodeBitmask = BitVec<u8, Lsb0>;
pub type BasicBlockBitMask = BitVec<u8, Lsb0>;

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
    pub basic_block_start_indices: BasicBlockBitMask,
    /// Decoded instructions indexed by instruction order.
    pub decoded_instructions: Vec<Instruction>,
    /// Lookup from program counter (byte index) to decoded instruction index.
    pub instruction_lookup: Vec<InstructionIndex>,
    /// Lookup from program counter (byte index) to precomputed skip distances.
    pub skip_distances: Vec<u8>,
}

impl ProgramState {
    pub fn print_all_opcodes(&self) {
        tracing::trace!("All Opcodes");
        self.instructions
            .iter()
            .zip(self.opcode_bitmask.iter())
            .filter(|(_, is_opcode)| **is_opcode)
            .filter_map(|(byte, _)| Opcode::from_u8(*byte))
            .for_each(|opcode| tracing::trace!("Op: {opcode:?}"))
    }

    pub fn skip_distance(&self, pc: usize) -> Option<usize> {
        self.skip_distances
            .get(pc)
            .map(|&distance| distance as usize)
    }

    /// Checks whether `index` (0-based, in octets) starts a basic block.
    pub fn is_basic_block_start(&self, index: usize) -> bool {
        self.basic_block_start_indices
            .get(index)
            .is_some_and(|bit| *bit)
    }

    pub fn instruction_at(&self, pc: usize) -> Option<&Instruction> {
        let idx = *self.instruction_lookup.get(pc)?;
        if idx == NOT_INSTRUCTION_INDEX {
            return None;
        }
        self.decoded_instructions.get(idx as usize)
    }
}
