//! Gas cost of a basic block, from a simulation of a simplified out-of-order CPU.
//!
//! Unlike the GP, the reorder buffer drops retired entries. A retired entry never starts again and a dependency on it is always met, so dropping it changes no cost.
//! It keeps each step bounded by the buffer capacity instead of the block length.

use crate::{
    error::VMCoreError,
    gas::{
        gas_cost_tables::{ExecutionUnits, InstructionCost},
        register_usage::{RegisterSet, RegisterUsage},
    },
    interpreter::Interpreter,
    program::{
        instruction::{opcode::Opcode, Instruction},
        types::program_state::ProgramState,
    },
};
use fr_common::UnsignedGas;
use fr_pvm_types::common::RegValue;
use std::collections::VecDeque;

/// Decode slots that each cycle starts with.
const MAX_DECODE_SLOTS_PER_CYCLE: u8 = 4;

/// Instructions that may start execution in each cycle.
const MAX_STARTS_PER_CYCLE: u8 = 5;

/// Most entries the reorder buffer holds.
const REORDER_BUFFER_CAPACITY: usize = 32;

/// Execution units of the virtual CPU, all available at the start of a basic block.
const INITIAL_EXECUTION_UNITS: ExecutionUnits = ExecutionUnits::new(4, 4, 4, 1, 1);

/// Most dependencies an entry has. Each register is clobbered by at most one entry, so an entry depends on at most one entry per source register, and `cmov_iz` reads three.
const MAX_DEPENDENCY_COUNT: usize = 3;

/// Computes the gas cost (`g^Δ`) of the basic block that starts at `block_start` (0-based, in octets).
///
/// It is the cycles until every instruction retires, minus 3 and at least 1.
pub fn basic_block_gas_cost(
    program_state: &ProgramState,
    block_start: usize,
) -> Result<UnsignedGas, VMCoreError> {
    let mut gas_simulation_state = GasSimulationState::new(block_start);
    gas_simulation_state.run(program_state)?;
    Ok(gas_simulation_state.cycle_count.saturating_sub(3).max(1))
}

/// Position of an entry in decode order (0-based), unchanged by retirement.
type ReorderBufferEntryId = u32;

/// Pipeline stage of a reorder buffer entry (`s` of `ℝ`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReorderBufferEntryState {
    /// `DEC`
    Decoding,
    /// `WAIT`
    Waiting,
    /// `EXE`
    Executing,
    /// `FIN`
    Finished,
}

/// Instruction in flight in the reorder buffer (`ℝ`).
#[derive(Clone, Debug)]
struct ReorderBufferEntry {
    state: ReorderBufferEntryState,
    /// `c`
    cycles_left: u32,
    /// `p`: Entries whose results the instruction reads
    dependencies: [Option<ReorderBufferEntryId>; MAX_DEPENDENCY_COUNT],
    /// `r`: Registers whose latest value this entry produces
    clobbered_registers: RegisterSet,
    /// `t`
    execution_units: ExecutionUnits,
}

/// Next instruction to decode, with its register usage and cost computed once.
struct InstructionToDecode<'a> {
    pc: usize,
    instruction: &'a Instruction,
    register_usage: RegisterUsage,
    instruction_cost: InstructionCost,
}

impl<'a> InstructionToDecode<'a> {
    fn at(program_state: &'a ProgramState, pc: usize) -> Result<Self, VMCoreError> {
        let instruction = program_state
            .instruction_at(pc)
            .ok_or(VMCoreError::InvalidPCVal(pc as RegValue))?;
        let register_usage = instruction.register_usage();
        Ok(Self {
            pc,
            instruction,
            register_usage,
            instruction_cost: InstructionCost::of(program_state, pc, instruction, register_usage),
        })
    }
}

/// State of the gas simulation of one basic block (`𝕊`).
struct GasSimulationState {
    /// `ı`: Next instruction to decode, or `None` after the block's last instruction
    next_instruction_pc: Option<usize>,
    /// `c`
    cycle_count: UnsignedGas,
    /// `d`
    remaining_decode_slots: u8,
    /// `e`
    remaining_starts_in_cycle: u8,
    /// `t`
    available_execution_units: ExecutionUnits,
    /// `r` without retired entries
    reorder_buffer: VecDeque<ReorderBufferEntry>,
    /// Count of dropped retired entries, which is also the id of the front entry
    retired_entry_count: ReorderBufferEntryId,
}

impl GasSimulationState {
    fn new(block_start: usize) -> Self {
        Self {
            next_instruction_pc: Some(block_start),
            cycle_count: 0,
            remaining_decode_slots: MAX_DECODE_SLOTS_PER_CYCLE,
            remaining_starts_in_cycle: MAX_STARTS_PER_CYCLE,
            available_execution_units: INITIAL_EXECUTION_UNITS,
            reorder_buffer: VecDeque::with_capacity(REORDER_BUFFER_CAPACITY),
            retired_entry_count: 0,
        }
    }

    /// Runs the simulation until the block is decoded and every instruction retires (`𝔛`).
    fn run(&mut self, program_state: &ProgramState) -> Result<(), VMCoreError> {
        let mut instruction_to_decode = self.instruction_to_decode(program_state)?;
        loop {
            if let Some(instruction) = &instruction_to_decode {
                if instruction.instruction_cost.decode_slots <= self.remaining_decode_slots
                    && self.reorder_buffer.len() < REORDER_BUFFER_CAPACITY
                {
                    self.decode_next_instruction(program_state, instruction);
                    instruction_to_decode = self.instruction_to_decode(program_state)?;
                    continue;
                }
            }
            if self.remaining_starts_in_cycle > 0 {
                if let Some(ready_entry_index) = self.find_ready_entry() {
                    self.start_entry(ready_entry_index);
                    continue;
                }
            }
            if self.next_instruction_pc.is_none() && self.reorder_buffer.is_empty() {
                return Ok(());
            }
            self.advance_cycle();
        }
    }

    fn instruction_to_decode<'a>(
        &self,
        program_state: &'a ProgramState,
    ) -> Result<Option<InstructionToDecode<'a>>, VMCoreError> {
        self.next_instruction_pc
            .map(|pc| InstructionToDecode::at(program_state, pc))
            .transpose()
    }

    /// Decodes the next instruction (`𝔛'`). `move_reg` only renames registers (`𝔛^mov`), and others add a reorder buffer entry (`𝔛^dec`).
    fn decode_next_instruction(
        &mut self,
        program_state: &ProgramState,
        instruction_to_decode: &InstructionToDecode,
    ) {
        let InstructionToDecode {
            pc,
            instruction,
            register_usage,
            instruction_cost,
        } = instruction_to_decode;
        let next_pc = Interpreter::next_pc(*pc as RegValue, program_state) as usize;
        self.remaining_decode_slots -= instruction_cost.decode_slots;

        if instruction.op == Opcode::MOVE_REG {
            // The destination now holds the source's value, so it moves to the entry that produces the source
            for entry in &mut self.reorder_buffer {
                entry.clobbered_registers = if entry
                    .clobbered_registers
                    .intersects(register_usage.source_registers)
                {
                    entry.clobbered_registers | register_usage.destination_registers
                } else {
                    entry.clobbered_registers - register_usage.destination_registers
                };
            }
            self.next_instruction_pc = Some(next_pc);
            return;
        }

        let mut dependencies = [None; MAX_DEPENDENCY_COUNT];
        let dependency_ids = (self.retired_entry_count..)
            .zip(&self.reorder_buffer)
            .filter(|(_, entry)| {
                entry
                    .clobbered_registers
                    .intersects(register_usage.source_registers)
            })
            .map(|(entry_id, _)| entry_id);
        for (dependency_index, entry_id) in dependency_ids.enumerate() {
            debug_assert!(
                dependency_index < MAX_DEPENDENCY_COUNT,
                "a register is clobbered by more than one entry"
            );
            if let Some(dependency) = dependencies.get_mut(dependency_index) {
                *dependency = Some(entry_id);
            }
        }
        for entry in &mut self.reorder_buffer {
            entry.clobbered_registers =
                entry.clobbered_registers - register_usage.destination_registers;
        }
        self.reorder_buffer.push_back(ReorderBufferEntry {
            state: ReorderBufferEntryState::Decoding,
            cycles_left: instruction_cost.cycles,
            dependencies,
            clobbered_registers: register_usage.destination_registers,
            execution_units: instruction_cost.execution_units,
        });
        self.next_instruction_pc = if instruction.op.is_termination_opcode() {
            None
        } else {
            Some(next_pc)
        };
    }

    /// Finds the oldest waiting entry whose execution units are free and whose dependencies are done (`𝔖`).
    fn find_ready_entry(&self) -> Option<usize> {
        self.reorder_buffer.iter().position(|entry| {
            entry.state == ReorderBufferEntryState::Waiting
                && entry
                    .execution_units
                    .fits_within(&self.available_execution_units)
                && entry
                    .dependencies
                    .iter()
                    .flatten()
                    .all(|&dependency_id| self.has_result(dependency_id))
        })
    }

    /// Checks whether entry `entry_id` has no cycles left. A retired entry always does.
    fn has_result(&self, entry_id: ReorderBufferEntryId) -> bool {
        entry_id
            .checked_sub(self.retired_entry_count)
            .and_then(|index| self.reorder_buffer.get(index as usize))
            .is_none_or(|entry| entry.cycles_left == 0)
    }

    /// Starts executing the entry at `entry_index` of `reorder_buffer` (`𝔛''`).
    fn start_entry(&mut self, entry_index: usize) {
        let entry = &mut self.reorder_buffer[entry_index];
        entry.state = ReorderBufferEntryState::Executing;
        self.available_execution_units = self.available_execution_units - entry.execution_units;
        self.remaining_starts_in_cycle -= 1;
    }

    /// Moves the pipeline by one cycle (`𝔛'''`).
    ///
    /// Each new state follows from the states before the cycle, so an entry that finishes now retires in the next cycle.
    fn advance_cycle(&mut self) {
        self.remaining_decode_slots = MAX_DECODE_SLOTS_PER_CYCLE;
        self.remaining_starts_in_cycle = MAX_STARTS_PER_CYCLE;
        self.cycle_count += 1;

        let retiring_entry_count = self
            .reorder_buffer
            .iter()
            .take_while(|entry| entry.state == ReorderBufferEntryState::Finished)
            .count();
        for entry in &mut self.reorder_buffer {
            match entry.state {
                ReorderBufferEntryState::Decoding => entry.state = ReorderBufferEntryState::Waiting,
                ReorderBufferEntryState::Executing if entry.cycles_left == 0 => {
                    entry.state = ReorderBufferEntryState::Finished
                }
                ReorderBufferEntryState::Executing => {
                    if entry.cycles_left == 1 {
                        self.available_execution_units =
                            self.available_execution_units + entry.execution_units;
                    }
                    entry.cycles_left -= 1;
                }
                ReorderBufferEntryState::Waiting | ReorderBufferEntryState::Finished => {}
            }
        }
        self.reorder_buffer.drain(..retiring_entry_count);
        self.retired_entry_count += retiring_entry_count as ReorderBufferEntryId;
    }
}
