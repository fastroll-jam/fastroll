use fr_pvm_core::state::memory::Memory;
use fr_pvm_types::common::RegValue;

#[derive(Clone)]
pub(crate) struct InnerPVM {
    /// **`p`**: Program code blob to run on the inner PVM
    pub(crate) program_code: Vec<u8>,
    /// **`u`**: RAM of the inner PVM
    pub(crate) memory: Memory,
    /// `i`: Program counter
    pub(crate) pc: RegValue,
    /// `g̃`: Gas-charged flag, kept between `invoke` calls so that resuming inside a basic block charges no gas again
    pub(crate) is_basic_block_gas_charged: bool,
}

impl InnerPVM {
    pub(crate) fn new(program_code: Vec<u8>, pc: RegValue) -> Self {
        Self {
            program_code,
            memory: Memory::default(),
            pc,
            is_basic_block_gas_charged: false,
        }
    }
}
