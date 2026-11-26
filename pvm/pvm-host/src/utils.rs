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
        $ctx.get_mut_accounts_sandbox()
            .ok_or(HostCallError::AccountsSandboxNotInitialized)?
    };
}

#[macro_export]
macro_rules! get_accumulate_x {
    ($ctx:expr) => {
        $ctx.get_accumulate_x()
            .ok_or(HostCallError::AccumulateContextNotInitialized)?
    };
}

#[macro_export]
macro_rules! get_mut_accumulate_x {
    ($ctx:expr) => {
        $ctx.get_mut_accumulate_x()
            .ok_or(HostCallError::AccumulateContextNotInitialized)?
    };
}

#[macro_export]
macro_rules! get_mut_accumulate_y {
    ($ctx:expr) => {
        $ctx.get_mut_accumulate_y()
            .ok_or(HostCallError::AccumulateContextNotInitialized)?
    };
}

#[macro_export]
macro_rules! get_refine_x {
    ($ctx:expr) => {
        $ctx.get_refine_x()
            .ok_or(HostCallError::RefineContextNotInitialized)?
    };
}

#[macro_export]
macro_rules! get_mut_refine_x {
    ($ctx:expr) => {
        $ctx.get_mut_refine_x()
            .ok_or(HostCallError::RefineContextNotInitialized)?
    };
}

#[macro_export]
macro_rules! continue_with_vm_change {
    (gas: $gas:expr, r7: $r7:expr) => {{
        tracing::debug!("Hostcall result: VMChange(r7={})", $r7 as RegValue);
        Ok(HostCallResult::continue_with_vm_change(
            HostCallVMStateChange {
                gas_charge: $gas,
                r7_write: Some($r7 as RegValue),
                r8_write: None,
                memory_write: None,
                writable_pages: None,
            },
        ))
    }};
    (gas: $gas:expr, r7: $r7:expr, r8: $r8:expr) => {{
        tracing::debug!(
            "Hostcall result: VMChange(r7={} r8={})",
            $r7 as RegValue,
            $r8 as RegValue
        );
        Ok(HostCallResult::continue_with_vm_change(
            HostCallVMStateChange {
                gas_charge: $gas,
                r7_write: Some($r7 as RegValue),
                r8_write: Some($r8 as RegValue),
                memory_write: None,
                writable_pages: None,
            },
        ))
    }};
    (gas: $gas:expr, r7: $r7:expr, mem_offset: $mem_offset:expr, mem_data: $mem_data:expr) => {{
        tracing::debug!(
            "Hostcall result: VMChange(r7={} moffset={})",
            $r7 as RegValue,
            $mem_offset
        );
        Ok(HostCallResult::continue_with_vm_change(
            HostCallVMStateChange {
                gas_charge: $gas,
                r7_write: Some($r7 as RegValue),
                r8_write: None,
                memory_write: Some($crate::MemWrite::new($mem_offset, $mem_data)),
                writable_pages: None,
            },
        ))
    }};
    (gas: $gas:expr, r7: $r7:expr, r8: $r8:expr, mem_offset: $mem_offset:expr, mem_data: $mem_data:expr) => {{
        tracing::debug!(
            "Hostcall result: VMChange(r7={} r8={} moffset={})",
            $r7 as RegValue,
            $r8 as RegValue,
            $mem_offset
        );
        Ok(HostCallResult::continue_with_vm_change(
            HostCallVMStateChange {
                gas_charge: $gas,
                r7_write: Some($r7 as RegValue),
                r8_write: Some($r8 as RegValue),
                memory_write: Some($crate::MemWrite::new($mem_offset, $mem_data)),
                writable_pages: None,
            },
        ))
    }};
}

#[macro_export]
macro_rules! continue_with_code {
    ($code:ident, $gas:expr) => {{
        tracing::debug!(
            "Hostcall result: {:?}",
            $crate::host_functions::HostCallReturnCode::$code
        );
        return Ok(HostCallResult::continue_with_return_code_and_gas(
            $crate::host_functions::HostCallReturnCode::$code,
            $gas,
        ));
    }};
}

#[macro_export]
macro_rules! continue_none {
    ($gas:expr) => {
        $crate::continue_with_code!(NONE, $gas)
    };
}

#[macro_export]
macro_rules! continue_oob {
    ($gas:expr) => {
        $crate::continue_with_code!(OOB, $gas)
    };
}

#[macro_export]
macro_rules! continue_who {
    ($gas:expr) => {
        $crate::continue_with_code!(WHO, $gas)
    };
}

#[macro_export]
macro_rules! continue_full {
    ($gas:expr) => {
        $crate::continue_with_code!(FULL, $gas)
    };
}

#[macro_export]
macro_rules! continue_core {
    ($gas:expr) => {
        $crate::continue_with_code!(CORE, $gas)
    };
}

#[macro_export]
macro_rules! continue_cash {
    ($gas:expr) => {
        $crate::continue_with_code!(CASH, $gas)
    };
}

#[macro_export]
macro_rules! continue_low {
    ($gas:expr) => {
        $crate::continue_with_code!(LOW, $gas)
    };
}

#[macro_export]
macro_rules! continue_what {
    ($gas:expr) => {
        $crate::continue_with_code!(WHAT, $gas)
    };
}

#[macro_export]
macro_rules! continue_huh {
    ($gas:expr) => {
        $crate::continue_with_code!(HUH, $gas)
    };
}

#[macro_export]
macro_rules! continue_ok {
    ($gas:expr) => {
        $crate::continue_with_code!(OK, $gas)
    };
}

#[macro_export]
macro_rules! host_call_panic {
    ($gas:expr) => {
        return Ok(HostCallResult::panic_with_gas($gas))
    };
}

#[macro_export]
macro_rules! out_of_gas {
    ($gas:expr) => {
        return Ok(HostCallResult::out_of_gas_with_gas($gas))
    };
}

#[macro_export]
macro_rules! check_out_of_gas {
    // Returns out-of-gas when the gas counter cannot cover the gas usage `g`, which consumes all the remaining gas
    ($gas_counter:expr, $gas:expr) => {
        let remaining_gas = $gas_counter.max(0) as UnsignedGas;
        if remaining_gas < $gas {
            $crate::out_of_gas!(remaining_gas)
        }
    };
}
