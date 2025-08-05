use crate::{error::HostCallError, host_functions::HostCallResult};
use fr_pvm_core::state::{state_change::HostCallVMStateChange, vm_state::VMState};
use fr_pvm_types::{common::RegValue, exit_reason::ExitReason};

#[repr(u8)]
#[derive(Debug)]
enum LogLevel {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
    Invalid = u8::MAX,
}

impl LogLevel {
    fn from_reg_val(reg_val: RegValue) -> Self {
        match reg_val {
            0 => Self::Error,
            1 => Self::Warn,
            2 => Self::Info,
            3 => Self::Debug,
            4 => Self::Trace,
            _ => Self::Invalid,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
struct PVMHostLog {
    level: LogLevel,
    target: Option<String>,
    message: String,
}

fn log_message(log: PVMHostLog) {
    // TODO: properly handle logging
    tracing::info!("--- PVM LOG: {log:?}");
}

/// Delivers debugging message from service/authorizer to the host environment.
///
/// Reference: [JIP-1](https://hackmd.io/@polkadot/jip1)
pub fn host_log(vm: &VMState) -> Result<HostCallResult, HostCallError> {
    tracing::debug!("Hostcall invoked: LOG");

    // no side effect
    let result = HostCallResult {
        exit_reason: ExitReason::Continue,
        vm_change: HostCallVMStateChange {
            gas_charge: 0,
            ..Default::default()
        },
    };

    let level = LogLevel::from_reg_val(vm.regs[7].value());
    let Ok(target_offset) = vm.regs[8].as_mem_address() else {
        return Ok(result);
    };
    let Ok(target_read_size) = vm.regs[9].as_usize() else {
        return Ok(result);
    };
    if !vm
        .memory
        .is_address_range_readable(target_offset, target_read_size)
    {
        return Ok(result);
    }
    let Ok(message_offset) = vm.regs[10].as_mem_address() else {
        return Ok(result);
    };
    let Ok(message_size) = vm.regs[11].as_usize() else {
        return Ok(result);
    };
    if !vm
        .memory
        .is_address_range_readable(message_offset, message_size)
    {
        return Ok(result);
    }

    let target = if target_offset == 0 && target_read_size == 0 {
        None
    } else {
        let Ok(target_data) = vm.memory.read_bytes(target_offset, target_read_size) else {
            return Ok(result);
        };
        Some(String::from_utf8_lossy(&target_data).to_string())
    };

    let message = if let Ok(message_data) = vm.memory.read_bytes(message_offset, message_size) {
        String::from_utf8_lossy(&message_data).to_string()
    } else {
        return Ok(result);
    };

    log_message(PVMHostLog {
        level,
        target,
        message,
    });

    Ok(result)
}
