//! PVM host call util functions and macros

use fr_common::utils::zero_pad::zero_pad;
use fr_limited_vec::FixedVec;

/// Zero-pads input octet sequence into a fixed length of `BLOCK_SIZE`. Returns `None` if the input
/// length exceeds `BLOCK_SIZE`.
pub(crate) fn zero_pad_single_block<const BLOCK_SIZE: usize>(
    input: Vec<u8>,
) -> Option<FixedVec<u8, BLOCK_SIZE>> {
    if input.len() > BLOCK_SIZE {
        return None;
    }
    let padded = zero_pad::<BLOCK_SIZE>(input);
    if padded.len() != BLOCK_SIZE {
        // Double-check
        return None;
    }
    FixedVec::<u8, BLOCK_SIZE>::try_from(padded).ok()
}

#[macro_export]
macro_rules! get_mut_accounts_sandbox {
    ($ctx:expr) => {
        match $ctx.get_mut_accounts_sandbox() {
            Some(sandbox) => sandbox,
            None => continue_what!(),
        }
    };
}

#[macro_export]
macro_rules! get_mut_accumulate_x {
    ($ctx:expr) => {
        match $ctx.get_mut_accumulate_x() {
            Some(x) => x,
            None => continue_what!(),
        }
    };
}

#[macro_export]
macro_rules! get_refine_x {
    ($ctx:expr) => {
        match $ctx.get_refine_x() {
            Some(x) => x,
            None => continue_what!(),
        }
    };
}

#[macro_export]
macro_rules! get_mut_refine_x {
    ($ctx:expr) => {
        match $ctx.get_mut_refine_x() {
            Some(x) => x,
            None => continue_what!(),
        }
    };
}

#[macro_export]
macro_rules! gas_or_default {
    () => {
        HOSTCALL_BASE_GAS_CHARGE
    };
    ($gas:expr) => {
        $gas as UnsignedGas
    };
}

#[macro_export]
macro_rules! continue_with_vm_change {
    ($(gas: $gas:expr,)? r7: $r7:expr) => {{
        tracing::debug!("Hostcall result: VMChange(r7={})", $r7 as RegValue);
        Ok(HostCallResult::continue_with_vm_change(
            HostCallVMStateChange {
                gas_charge: $crate::gas_or_default!($($gas)?),
                r7_write: Some($r7 as RegValue),
                r8_write: None,
                memory_write: None,
            },
        ))
    }};
    ($(gas: $gas:expr,)? r7: $r7:expr, r8: $r8:expr) => {{
        tracing::debug!("Hostcall result: VMChange(r7={} r8={})", $r7 as RegValue, $r8 as RegValue);
        Ok(HostCallResult::continue_with_vm_change(
            HostCallVMStateChange {
                gas_charge: $crate::gas_or_default!($($gas)?),
                r7_write: Some($r7 as RegValue),
                r8_write: Some($r8 as RegValue),
                memory_write: None,
            },
        ))
    }};
    ($(gas: $gas:expr,)? r7: $r7:expr, mem_offset: $mem_offset:expr, mem_data: $mem_data:expr) => {{
        tracing::debug!("Hostcall result: VMChange(r7={} moffset={})", $r7 as RegValue, $mem_offset);
        Ok(HostCallResult::continue_with_vm_change(
            HostCallVMStateChange {
                gas_charge: $crate::gas_or_default!($($gas)?),
                r7_write: Some($r7 as RegValue),
                r8_write: None,
                memory_write: Some($crate::MemWrite::new($mem_offset, $mem_data)),
            },
        ))
    }};
    ($(gas: $gas:expr,)? r7: $r7:expr, r8: $r8:expr, mem_offset: $mem_offset:expr, mem_data: $mem_data:expr) => {{
        tracing::debug!("Hostcall result: VMChange(r7={} r8={} moffset={})", $r7 as RegValue, $r8 as RegValue, $mem_offset);
        Ok(HostCallResult::continue_with_vm_change(
            HostCallVMStateChange {
                gas_charge: $crate::gas_or_default!($($gas)?),
                r7_write: Some($r7 as RegValue),
                r8_write: Some($r8 as RegValue),
                memory_write: Some($crate::MemWrite::new($mem_offset, $mem_data)),
            },
        ))
    }};
}

#[macro_export]
macro_rules! continue_with_code {
    ($code:ident) => {{
        tracing::debug!("Hostcall result: {:?}", HostCallReturnCode::$code);
        return Ok(HostCallResult::continue_with_return_code(
            HostCallReturnCode::$code,
        ));
    }};
    ($code:ident, $gas:expr) => {{
        tracing::debug!("Hostcall result: {:?}", HostCallReturnCode::$code);
        return Ok(HostCallResult::continue_with_return_code_and_gas(
            HostCallReturnCode::$code,
            $gas,
        ));
    }};
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
        return Ok(HostCallResult::panic())
    };
    ($gas:expr) => {
        return Ok(HostCallResult::panic_with_gas($gas))
    };
}

#[macro_export]
macro_rules! check_out_of_gas {
    ($gas_counter:expr) => {
        if $gas_counter < HOSTCALL_BASE_GAS_CHARGE as SignedGas {
            $crate::out_of_gas!()
        }
    };
    ($gas_counter:expr, $gas:expr) => {
        let gas_signed: SignedGas = $gas
            .try_into()
            .expect("Gas charge should fit in `SignedGas`");
        if $gas_counter < gas_signed {
            $crate::out_of_gas!($gas)
        }
    };
}

#[macro_export]
macro_rules! out_of_gas {
    () => {
        return Ok(HostCallResult::out_of_gas())
    };
    ($gas:expr) => {
        return Ok(HostCallResult::out_of_gas_with_gas($gas))
    };
}
