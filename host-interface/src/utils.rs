use crate::host_functions::{HostCallResultConstant, HostCallVMStateChange};
use rjam_common::{Octets, UnsignedGas};

// Zero-padding function for octet sequences
pub fn zero_pad(mut input: Octets, block_size: usize) -> Octets {
    let padding_len = block_size - (((input.len() + block_size - 1) % block_size) + 1);
    input.extend(vec![0; padding_len]);
    input
}

// Convenience function for `HostCallVMStateChange` construction
fn create_host_call_state_change(
    constant: HostCallResultConstant,
    gas_usage: UnsignedGas,
) -> HostCallVMStateChange {
    HostCallVMStateChange {
        gas_usage,
        r7_write: Some(constant as u32),
        ..Default::default()
    }
}

macro_rules! define_host_call_state_change_function {
    ($func_name:ident, $constant:ident) => {
        pub fn $func_name(gas_usage: UnsignedGas) -> HostCallVMStateChange {
            create_host_call_state_change(HostCallResultConstant::$constant, gas_usage)
        }
    };
}

// Functions that return VM state changes corresponding to host call result codes
define_host_call_state_change_function!(none_change, NONE);
define_host_call_state_change_function!(oob_change, OOB);
define_host_call_state_change_function!(who_change, WHO);
define_host_call_state_change_function!(full_change, FULL);
define_host_call_state_change_function!(core_change, CORE);
define_host_call_state_change_function!(cash_change, CASH);
define_host_call_state_change_function!(low_change, LOW);
define_host_call_state_change_function!(high_change, HIGH);
// define_host_call_state_change_function!(what_change, WHAT);
define_host_call_state_change_function!(huh_change, HUH);
define_host_call_state_change_function!(ok_change, OK);
