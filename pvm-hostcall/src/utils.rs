use crate::host_functions::{HostCallResultConstant, HostCallVMStateChange};
use rjam_common::UnsignedGas;
use rjam_pvm_core::types::common::RegValue;

// Zero-padding function for octet sequences
pub fn zero_pad_as_array<const BLOCK_SIZE: usize>(
    mut input: Vec<u8>,
) -> Option<Box<[u8; BLOCK_SIZE]>> {
    if input.len() > BLOCK_SIZE {
        return None;
    }
    let padding_len = BLOCK_SIZE - input.len();
    input.extend(vec![0; padding_len]);
    input.try_into().ok()
}

// Convenience function for `HostCallVMStateChange` construction
fn create_host_call_state_change(
    constant: HostCallResultConstant,
    gas_charge: UnsignedGas,
) -> HostCallVMStateChange {
    HostCallVMStateChange {
        gas_charge,
        r7_write: Some(constant as RegValue),
        ..Default::default()
    }
}

macro_rules! define_host_call_state_change_function {
    ($func_name:ident, $constant:ident) => {
        pub fn $func_name(gas_charge: UnsignedGas) -> HostCallVMStateChange {
            create_host_call_state_change(HostCallResultConstant::$constant, gas_charge)
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
