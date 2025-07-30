use fr_common::SignedGas;
use fr_pvm_core::state::{memory::Memory, register::Register, vm_state::VMState};
use fr_pvm_types::constants::REGISTERS_COUNT;

pub(crate) fn create_vm_state(gas_counter: SignedGas) -> VMState {
    VMState {
        regs: [Register::default(); REGISTERS_COUNT],
        memory: Memory::default(),
        pc: 0,
        gas_counter,
    }
}
