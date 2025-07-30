use crate::context::{AccumulateHostContext, AccumulateHostContextPair};
use fr_common::{ServiceId, SignedGas};
use fr_pvm_core::state::{
    memory::{AccessType, Memory},
    register::Register,
    vm_state::VMState,
};
use fr_pvm_types::{
    common::{MemAddress, RegValue},
    constants::{MEMORY_SIZE, PAGE_SIZE, REGISTERS_COUNT},
};
use std::{error::Error, ops::Range};

pub(crate) fn mock_empty_vm_state(gas_counter: SignedGas) -> VMState {
    VMState {
        regs: [Register::default(); REGISTERS_COUNT],
        memory: Memory::default(),
        pc: 0,
        gas_counter,
    }
}

pub(crate) fn mock_vm_state(
    gas_counter: SignedGas,
    pc: RegValue,
    regs: [Register; REGISTERS_COUNT],
    memory: Memory,
) -> VMState {
    VMState {
        regs,
        memory,
        pc,
        gas_counter,
    }
}

pub(crate) fn mock_accumulate_host_context(
    accumulate_host: ServiceId,
) -> AccumulateHostContextPair {
    let context = AccumulateHostContext {
        accumulate_host,
        ..Default::default()
    };
    AccumulateHostContextPair {
        x: Box::new(context.clone()),
        y: Box::new(context),
    }
}

pub(crate) fn mock_memory(
    readable_range: Range<MemAddress>,
    writable_range: Range<MemAddress>,
) -> Result<Memory, Box<dyn Error>> {
    let mut mem = Memory::new(MEMORY_SIZE, PAGE_SIZE);
    mem.set_address_range_access(readable_range, AccessType::ReadOnly)?;
    mem.set_address_range_access(writable_range, AccessType::ReadWrite)?;
    Ok(mem)
}
