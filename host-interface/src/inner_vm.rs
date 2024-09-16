use jam_common::Octets;
use jam_pvm_core::memory::{MemAddress, Memory};

#[derive(Clone)]
pub(crate) struct InnerPVM {
    pub(crate) program_code: Octets, // p
    pub(crate) memory: Memory,       // u
    pub(crate) pc: MemAddress,       // i
}

impl InnerPVM {
    pub(crate) fn new(program_code: Octets, pc: MemAddress) -> Self {
        Self {
            program_code,
            memory: Memory::default(),
            pc,
        }
    }
}
