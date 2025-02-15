//! PVM host call util functions and macros

// Zero-padding function for octet sequences
pub(crate) fn zero_pad_as_array<const BLOCK_SIZE: usize>(
    mut input: Vec<u8>,
) -> Option<Box<[u8; BLOCK_SIZE]>> {
    if input.len() > BLOCK_SIZE {
        return None;
    }
    let padding_len = BLOCK_SIZE - input.len();
    input.extend(vec![0; padding_len]);
    input.try_into().ok()
}

#[macro_export]
macro_rules! gas_or_default {
    () => {
        BASE_GAS_CHARGE
    };
    ($gas:expr) => {
        $gas as UnsignedGas
    };
}

#[macro_export]
macro_rules! continue_with_vm_change {
    ($(gas: $gas:expr,)? r7: $r7:expr) => {
        Ok(HostCallResult::continue_with_vm_change(
            HostCallVMStateChange {
                gas_charge: $crate::gas_or_default!($($gas)?),
                r7_write: Some($r7 as RegValue),
                r8_write: None,
                memory_write: None,
            },
        ))
    };
    ($(gas: $gas:expr,)? r7: $r7:expr, r8: $r8:expr) => {
        Ok(HostCallResult::continue_with_vm_change(
            HostCallVMStateChange {
                gas_charge: $crate::gas_or_default!($($gas)?),
                r7_write: Some($r7 as RegValue),
                r8_write: Some($r8 as RegValue),
                memory_write: None,
            },
        ))
    };
    ($(gas: $gas:expr,)? r7: $r7:expr, mem_offset: $mem_offset:expr, mem_size: $mem_size:expr, mem_data: $mem_data:expr) => {
        Ok(HostCallResult::continue_with_vm_change(
            HostCallVMStateChange {
                gas_charge: $crate::gas_or_default!($($gas)?),
                r7_write: Some($r7 as RegValue),
                r8_write: None,
                memory_write: Some(MemWrite::new($mem_offset, $mem_size as u32, $mem_data)),
            },
        ))
    };
    ($(gas: $gas:expr,)? r7: $r7:expr, r8: $r8:expr, mem_offset: $mem_offset:expr, mem_size: $mem_size:expr, mem_data: $mem_data:expr) => {
        Ok(HostCallResult::continue_with_vm_change(
            HostCallVMStateChange {
                gas_charge: $crate::gas_or_default!($($gas)?),
                r7_write: Some($r7 as RegValue),
                r8_write: Some($r8 as RegValue),
                memory_write: Some(MemWrite::new($mem_offset, $mem_size as u32, $mem_data)),
            },
        ))
    };
}

#[macro_export]
macro_rules! continue_with_code {
    ($code:ident) => {
        Ok(HostCallResult::continue_with_return_code(
            HostCallReturnCode::$code,
        ))
    };
    ($code:ident, $gas:expr) => {
        Ok(HostCallResult::continue_with_return_code_and_gas(
            HostCallReturnCode::$code,
            $gas,
        ))
    };
}

#[macro_export]
macro_rules! continue_none {
    () => {
        $crate::continue_with_code!(NONE)
    };
    ($gas:expr) => {
        $crate::continue_with_code!(NONE, $gas)
    };
}

#[macro_export]
macro_rules! continue_oob {
    () => {
        $crate::continue_with_code!(OOB)
    };
    ($gas:expr) => {
        $crate::continue_with_code!(OOB, $gas)
    };
}

#[macro_export]
macro_rules! continue_who {
    () => {
        $crate::continue_with_code!(WHO)
    };
    ($gas:expr) => {
        $crate::continue_with_code!(WHO, $gas)
    };
}

#[macro_export]
macro_rules! continue_full {
    () => {
        $crate::continue_with_code!(FULL)
    };
    ($gas:expr) => {
        $crate::continue_with_code!(FULL, $gas)
    };
}

#[macro_export]
macro_rules! continue_core {
    () => {
        $crate::continue_with_code!(CORE)
    };
    ($gas:expr) => {
        $crate::continue_with_code!(CORE, $gas)
    };
}

#[macro_export]
macro_rules! continue_cash {
    () => {
        $crate::continue_with_code!(CASH)
    };
    ($gas:expr) => {
        $crate::continue_with_code!(CASH, $gas)
    };
}

#[macro_export]
macro_rules! continue_low {
    () => {
        $crate::continue_with_code!(LOW)
    };
    ($gas:expr) => {
        $crate::continue_with_code!(LOW, $gas)
    };
}

#[macro_export]
macro_rules! continue_what {
    () => {
        $crate::continue_with_code!(WHAT)
    };
    ($gas:expr) => {
        $crate::continue_with_code!(WHAT, $gas)
    };
}

#[macro_export]
macro_rules! continue_huh {
    () => {
        $crate::continue_with_code!(HUH)
    };
    ($gas:expr) => {
        $crate::continue_with_code!(HUH, $gas)
    };
}

#[macro_export]
macro_rules! continue_ok {
    () => {
        $crate::continue_with_code!(OK)
    };
    ($gas:expr) => {
        $crate::continue_with_code!(OK, $gas)
    };
}

#[macro_export]
macro_rules! host_call_panic {
    () => {
        Ok(HostCallResult::panic())
    };
    ($gas:expr) => {
        Ok(HostCallResult::panic_with_gas($gas))
    };
}
