use fr_pvm_core::{
    error::VMCoreError,
    program::{loader::ProgramLoader, types::program_state::ProgramState},
    state::memory::Memory,
};
use fr_pvm_types::common::RegValue;
use std::sync::Arc;

/// Inner PVM instance of the refine context (`m`), created by `machine` and run by `invoke`.
#[derive(Clone)]
pub(crate) struct InnerPVM {
    /// **`p`**: Program of the inner PVM, decoded once with its basic block gas costs
    pub(crate) program_state: Arc<ProgramState>,
    /// **`u`**: RAM of the inner PVM
    pub(crate) memory: Memory,
    /// `i`: Program counter
    pub(crate) pc: RegValue,
    /// `g̃`: Gas-charged flag, kept between `invoke` calls so that resuming inside a basic block charges no gas again
    pub(crate) is_basic_block_gas_charged: bool,
}

impl InnerPVM {
    /// Loads `program_code` for `machine`, which fails like `deblob(p, i)` when the blob is invalid or `pc` is not an instruction.
    pub(crate) fn load(program_code: &[u8], pc: RegValue) -> Result<Self, VMCoreError> {
        let mut program_state = ProgramState::default();
        ProgramLoader::load_program(program_code, &mut program_state)?;
        let is_instruction =
            usize::try_from(pc).is_ok_and(|pc| program_state.instruction_at(pc).is_some());
        if !is_instruction {
            return Err(VMCoreError::InvalidPCVal(pc));
        }
        Ok(Self {
            program_state: Arc::new(program_state),
            memory: Memory::default(),
            pc,
            is_basic_block_gas_charged: false,
        })
    }
}
