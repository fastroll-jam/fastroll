use crate::error::PVMError;
use fr_pvm_core::{
    error::VMCoreError::*,
    program::types::{formatted_program::FormattedProgram, program_state::ProgramState},
    state::{
        memory::{AccessType, Memory},
        vm_state::VMState,
    },
    utils::VMUtils,
};
use fr_pvm_types::{
    common::{MemAddress, RegValue},
    constants::{INIT_INPUT_SIZE, INIT_ZONE_SIZE, MEMORY_SIZE, PAGE_SIZE},
};
use std::sync::Arc;

/// Main stateful PVM struct.
#[derive(Default)]
pub struct PVM {
    /// The mutable VM state
    pub state: VMState,
    /// The static program state initialized in the `Ψ_M` invocation.
    pub program_state: Arc<ProgramState>,
}

impl PVM {
    /// Initialize memory and registers of PVM with provided program and arguments.
    pub(crate) fn new_with_formatted_program(
        formatted_program: &FormattedProgram,
        program_state: Arc<ProgramState>,
        args: &[u8],
    ) -> Result<Self, PVMError> {
        let mut pvm = Self {
            state: VMState::default(),
            program_state,
        };

        // Check argument data size limit
        if args.len() > INIT_INPUT_SIZE {
            return Err(PVMError::VMCoreError(ProgramArgsSizeLimitExceeded));
        }

        if !formatted_program.is_program_size_valid() {
            return Err(PVMError::VMCoreError(InvalidProgram));
        }

        pvm.setup_memory_layout(formatted_program, args)?;
        tracing::info!("PVM memory setup.");
        pvm.initialize_registers(args.len());
        tracing::info!("PVM registers setup.");

        tracing::info!("PVM initialized.");
        Ok(pvm)
    }

    fn setup_memory_layout(&mut self, fp: &FormattedProgram, args: &[u8]) -> Result<(), PVMError> {
        let mut memory = Memory::new(MEMORY_SIZE, PAGE_SIZE);

        // Program-specific read-only static data (o)
        let o_start = INIT_ZONE_SIZE as MemAddress;
        let o_padding_end = o_start + VMUtils::page_align(fp.static_size as usize) as MemAddress;
        memory.set_address_range_access(o_start..o_padding_end, AccessType::ReadWrite)?;
        memory.write_bytes(o_start, &fp.static_data)?;
        memory.set_address_range_access(o_start..o_padding_end, AccessType::ReadOnly)?;

        // Read-write heap data (w)
        let w_start =
            (2 * INIT_ZONE_SIZE + VMUtils::zone_align(fp.static_size as usize)) as MemAddress;
        let w_padding_end = w_start
            + VMUtils::page_align(fp.heap_size as usize) as MemAddress
            + fp.extra_heap_pages as MemAddress * PAGE_SIZE as MemAddress;
        memory.set_address_range_access(w_start..w_padding_end, AccessType::ReadWrite)?;
        memory.write_bytes(w_start, &fp.heap_data)?;
        memory.heap_start = w_start;
        memory.heap_end = w_padding_end;

        // Stack (s)
        let s_start = ((1 << 32)
            - 2 * INIT_ZONE_SIZE
            - INIT_INPUT_SIZE
            - VMUtils::page_align(fp.stack_size as usize)) as MemAddress;
        let s_end = ((1 << 32) - 2 * INIT_ZONE_SIZE - INIT_INPUT_SIZE) as MemAddress;
        memory.set_address_range_access(s_start..s_end, AccessType::ReadWrite)?;
        memory.stack_start = s_start;

        // Arguments (a)
        let a_start = ((1 << 32) - INIT_ZONE_SIZE - INIT_INPUT_SIZE) as MemAddress;
        let a_padding_end = a_start + VMUtils::page_align(args.len()) as MemAddress;
        memory.set_address_range_access(a_start..a_padding_end, AccessType::ReadWrite)?;
        memory.write_bytes(a_start, args)?;
        memory.set_address_range_access(a_start..a_padding_end, AccessType::ReadOnly)?;

        // Other addresses are inaccessible by default

        tracing::info!("----------------- Memory Layout -----------------");
        tracing::info!(
            "Static    (o) page range: {}..{}",
            memory.get_page_and_offset(o_start).0,
            memory.get_page_and_offset(o_padding_end).0
        );
        tracing::info!(
            "Heap      (w) page range: {}..{}",
            memory.get_page_and_offset(w_start).0,
            memory.get_page_and_offset(w_padding_end).0
        );
        tracing::info!(
            "Stack     (s) page range: {}..{}",
            memory.get_page_and_offset(s_start).0,
            memory.get_page_and_offset(s_end).0
        );
        tracing::info!(
            "Arguments (a) page range: {}..{}",
            memory.get_page_and_offset(a_start).0,
            memory.get_page_and_offset(a_padding_end).0
        );
        tracing::info!("-------------------------------------------------");
        self.state.memory = memory;
        Ok(())
    }

    pub fn initialize_registers(&mut self, args_len: usize) {
        self.state.regs[0] = (1 << 32) - (1 << 16);
        self.state.regs[1] = (1 << 32) - (2 * INIT_ZONE_SIZE + INIT_INPUT_SIZE) as RegValue;
        self.state.regs[7] = (1 << 32) - (INIT_ZONE_SIZE + INIT_INPUT_SIZE) as RegValue;
        self.state.regs[8] = args_len as RegValue;
    }

    /// Reads a specified number of bytes from memory starting at the given address
    pub(crate) fn read_memory_bytes(
        &self,
        address: MemAddress,
        length: usize,
    ) -> Result<Vec<u8>, PVMError> {
        Ok(self.state.memory.read_bytes(address, length)?)
    }
}
