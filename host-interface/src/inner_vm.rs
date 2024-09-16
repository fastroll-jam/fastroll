use jam_common::Octets;
use jam_pvm_core::memory::{MemAddress, Memory};

#[repr(u32)]
pub enum InnerPVMInvocationResult {
    HALT = 0,
    PANIC = u32::MAX - 11,
    FAULT = u32::MAX - 12,
    HOST = u32::MAX - 13,
}

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