use rjam_pvm_core::{state::memory::Memory, types::common::RegValue};

#[derive(Clone)]
pub(crate) struct InnerPVM {
    /// **`p`**: Program code blob to run on the inner PVM
    pub(crate) program_code: Vec<u8>,
    /// **`u`**: RAM of the inner PVM
    pub(crate) memory: Memory,
    /// `i`: Program counter
    pub(crate) pc: RegValue,
}

impl InnerPVM {
    pub(crate) fn new(program_code: Vec<u8>, pc: RegValue) -> Self {
        Self {
            program_code,
            memory: Memory::default(),
            pc,
        }
    }
}
