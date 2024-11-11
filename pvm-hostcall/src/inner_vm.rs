use rjam_pvm_core::state::memory::{MemAddress, Memory};

#[derive(Clone)]
pub(crate) struct InnerPVM {
    pub(crate) program_code: Vec<u8>, // p
    pub(crate) memory: Memory,        // u
    pub(crate) pc: MemAddress,        // i
}

impl InnerPVM {
    pub(crate) fn new(program_code: Vec<u8>, pc: MemAddress) -> Self {
        Self {
            program_code,
            memory: Memory::default(),
            pc,
        }
    }
}
