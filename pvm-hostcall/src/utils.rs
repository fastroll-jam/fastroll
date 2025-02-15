//! PVM host call util functions and macros

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

#[macro_export]
macro_rules! continue_with {
    ($code:ident) => {
        HostCallResult::continue_with_return_code(HostCallReturnCode::$code)
    };
    ($code:ident, $gas:expr) => {
        HostCallResult::continue_with_return_code_and_gas(HostCallReturnCode::$code, $gas)
    };
}

#[macro_export]
macro_rules! continue_none {
    () => {
        $crate::continue_with!(NONE)
    };
    ($gas:expr) => {
        $crate::continue_with!(NONE, $gas)
    };
}

#[macro_export]
macro_rules! continue_oob {
    () => {
        $crate::continue_with!(OOB)
    };
    ($gas:expr) => {
        $crate::continue_with!(OOB, $gas)
    };
}

#[macro_export]
macro_rules! continue_who {
    () => {
        $crate::continue_with!(WHO)
    };
    ($gas:expr) => {
        $crate::continue_with!(WHO, $gas)
    };
}

#[macro_export]
macro_rules! continue_full {
    () => {
        $crate::continue_with!(FULL)
    };
    ($gas:expr) => {
        $crate::continue_with!(FULL, $gas)
    };
}

#[macro_export]
macro_rules! continue_core {
    () => {
        $crate::continue_with!(CORE)
    };
    ($gas:expr) => {
        $crate::continue_with!(CORE, $gas)
    };
}

#[macro_export]
macro_rules! continue_cash {
    () => {
        $crate::continue_with!(CASH)
    };
    ($gas:expr) => {
        $crate::continue_with!(CASH, $gas)
    };
}

#[macro_export]
macro_rules! continue_low {
    () => {
        $crate::continue_with!(LOW)
    };
    ($gas:expr) => {
        $crate::continue_with!(LOW, $gas)
    };
}

#[macro_export]
macro_rules! continue_what {
    () => {
        $crate::continue_with!(WHAT)
    };
    ($gas:expr) => {
        $crate::continue_with!(WHAT, $gas)
    };
}

#[macro_export]
macro_rules! continue_huh {
    () => {
        $crate::continue_with!(HUH)
    };
    ($gas:expr) => {
        $crate::continue_with!(HUH, $gas)
    };
}

#[macro_export]
macro_rules! continue_ok {
    () => {
        $crate::continue_with!(OK)
    };
    ($gas:expr) => {
        $crate::continue_with!(OK, $gas)
    };
}

#[macro_export]
macro_rules! host_call_panic {
    () => {
        HostCallResult::panic()
    };
    ($gas:expr) => {
        HostCallResult::panic_with_gas($gas)
    };
}
