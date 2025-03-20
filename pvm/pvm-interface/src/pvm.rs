use crate::error::PVMError;
use rjam_pvm_core::{
    error::VMCoreError::*,
    program::types::{formatted_program::FormattedProgram, program_state::ProgramState},
    state::{
        memory::{AccessType, Memory},
        vm_state::VMState,
    },
    utils::VMUtils,
};
use rjam_pvm_types::{
    common::{MemAddress, RegValue},
    constants::{INIT_INPUT_SIZE, INIT_ZONE_SIZE, MEMORY_SIZE, PAGE_SIZE},
};

/// Main stateful PVM struct.
#[derive(Default)]
pub struct PVM {
    /// The mutable VM state
    pub state: VMState,
    /// The static program state initialized in the general invocation `Ψ`
    pub program_state: ProgramState,
    /// Equivalent to `code` of `FormattedProgram`
    pub program_blob: Vec<u8>,
}

impl PVM {
    /// Initialize memory and registers of PVM with provided program and arguments
    ///
    /// Represents `Y` of the GP
    pub(crate) fn new_with_standard_program(
        standard_program: &[u8],
        args: &[u8],
    ) -> Result<Self, PVMError> {
        let mut pvm = Self::default();

        // Check argument data size limit
        if args.len() > INIT_INPUT_SIZE {
            return Err(PVMError::VMCoreError(ProgramArgsSizeLimitExceeded));
        }

        // Decode program and check program size limit
        let formatted_program = FormattedProgram::from_standard_program(standard_program)?;
        if !formatted_program.is_program_size_valid() {
            return Err(PVMError::VMCoreError(InvalidProgram));
        }

        pvm.setup_memory_layout(&formatted_program, args)?;
        pvm.initialize_registers(args.len());
        pvm.program_blob = formatted_program.code;

        Ok(pvm)
    }

    fn setup_memory_layout(&mut self, fp: &FormattedProgram, args: &[u8]) -> Result<(), PVMError> {
        let mut memory = Memory::new(MEMORY_SIZE, PAGE_SIZE);

        // Program-specific read-only static data (o)
        let o_start = INIT_ZONE_SIZE as MemAddress; // Z_Z
        let o_padding_end = o_start + VMUtils::page_align(fp.static_size as usize) as MemAddress;
        memory.set_address_range_access(o_start..o_padding_end, AccessType::ReadOnly)?;
        memory.write_bytes(o_start, &fp.static_data)?;

        // Read-write heap data (w)
        let w_start =
            (2 * INIT_ZONE_SIZE + VMUtils::zone_align(fp.static_size as usize)) as MemAddress;
        let w_padding_end = w_start
            + VMUtils::page_align(fp.heap_size as usize) as MemAddress
            + fp.extra_heap_pages as MemAddress * PAGE_SIZE as MemAddress;
        memory.set_address_range_access(w_start..w_padding_end, AccessType::ReadWrite)?;
        memory.write_bytes(w_start, &fp.heap_data)?;
        memory.heap_start = w_start;

        // Stack (s)
        let s_start = ((1 << 32)
            - 2 * INIT_ZONE_SIZE
            - INIT_INPUT_SIZE
            - VMUtils::page_align(fp.stack_size as usize)) as MemAddress;
        let s_end = ((1 << 32) - 2 * INIT_ZONE_SIZE - INIT_INPUT_SIZE) as MemAddress;
        memory.set_address_range_access(s_start..s_end, AccessType::ReadWrite)?;

        // Arguments (a)
        let a_start = ((1 << 32) - INIT_ZONE_SIZE - INIT_INPUT_SIZE) as MemAddress;
        let a_padding_end = a_start + VMUtils::page_align(args.len()) as MemAddress;
        memory.set_address_range_access(a_start..a_padding_end, AccessType::ReadOnly)?;
        memory.write_bytes(a_start, args)?;

        // Other addresses are inaccessible
        memory.set_address_range_access(0..o_start, AccessType::Inaccessible)?;
        memory.set_address_range_access(o_padding_end..w_start, AccessType::Inaccessible)?;
        memory.set_address_range_access(w_padding_end..s_start, AccessType::Inaccessible)?;
        memory.set_address_range_access(s_end..a_start, AccessType::Inaccessible)?;
        memory
            .set_address_range_access(a_padding_end..MemAddress::MAX, AccessType::Inaccessible)?;

        self.state.memory = memory;
        Ok(())
    }

    pub fn initialize_registers(&mut self, args_len: usize) {
        self.state.regs[0].value = (1 << 32) - (1 << 16);
        self.state.regs[1].value = (1 << 32) - (2 * INIT_ZONE_SIZE + INIT_INPUT_SIZE) as RegValue;
        self.state.regs[7].value = (1 << 32) - (INIT_ZONE_SIZE + INIT_INPUT_SIZE) as RegValue;
        self.state.regs[8].value = args_len as RegValue;
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
