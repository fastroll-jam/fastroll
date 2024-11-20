use rjam_pvm_core::{state::memory::Memory, types::common::RegValue};

#[derive(Clone)]
pub(crate) struct InnerPVM {
    pub(crate) program_code: Vec<u8>, // p
    pub(crate) memory: Memory,        // u
    pub(crate) pc: RegValue,          // i
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
