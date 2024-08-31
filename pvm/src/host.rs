use crate::{
    constants::REGISTERS_COUNT,
    vm::{ExitReason, MemAddress, Register, VMError},
};
use jam_common::{Octets, UnsignedGas};

//
// Enums
//

#[repr(u8)]
#[allow(non_camel_case_types)]
pub(crate) enum HostCallType {
    // General Functions
    GAS = 0,
    LOOKUP = 1,
    READ = 2,
    WRITE = 3,
    INFO = 4,
    // Accumulate Functions
    EMPOWER = 5,
    ASSIGN = 21, // TODO: check value
    DESIGNATE = 6,
    CHECKPOINT = 7,
    NEW = 22, // TODO: check value
    UPGRADE = 8,
    TRANSFER = 9,
    QUIT = 10,
    SOLICIT = 11,
    FORGET = 12,
    // Refine Functions
    HISTORICAL_LOOKUP = 13,
    IMPORT = 14,
    EXPORT = 15,
    MACHINE = 16,
    PEEK = 17,
    POKE = 18,
    INVOKE = 19,
    EXPUNGE = 20,
}

#[repr(u32)]
pub(crate) enum HostCallResult {
    NONE = u32::MAX,
    OOB = u32::MAX - 1,
    WHO = u32::MAX - 2,
    FULL = u32::MAX - 3,
    CORE = u32::MAX - 4,
    CASH = u32::MAX - 5,
    LOW = u32::MAX - 6,
    HIGH = u32::MAX - 7,
    WHAT = u32::MAX - 8,
    HUH = u32::MAX - 9,
    OK = 0,
}

#[repr(u32)]
pub(crate) enum InnerPVMInvocationResult {
    HALT = 0,
    PANIC = u32::MAX - 11,
    FAULT = u32::MAX - 12,
    HOST = u32::MAX - 13,
}

// TODO: add service accounts context
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub(crate) enum InvocationContext {
    X_G, // General Functions
    X_I, // Is-Authorized
    X_R, // Refine
    X_A, // Accumulate
    X_T, // On-Transfer
}

//
// Structs
//

struct ServiceAccountChange;

pub(crate) struct HostCallStateChange {
    pub(crate) gas_change: UnsignedGas,
    pub(crate) r0_change: Option<u32>,
    pub(crate) r1_change: Option<u32>,
    pub(crate) memory_change: (MemAddress, Octets, u32), // (start_address, data, data_len)
    pub(crate) service_accounts_changes: Vec<(u32, ServiceAccountChange)>, // u32 for service account index; TODO: better data handling
    pub(crate) exit_reason: ExitReason, // TODO: check if necessary
}

impl Default for HostCallStateChange {
    fn default() -> Self {
        Self {
            gas_change: 0,
            r0_change: None,
            r1_change: None,
            memory_change: (0, vec![], 0),
            service_accounts_changes: vec![],
            exit_reason: ExitReason::Continue,
        }
    }
}

//
// Invocation Contexts
//

struct AccumulateContext {}

//
// Host functions
//

pub(crate) struct HostFunction;

impl HostFunction {
    pub(crate) fn host_gas(
        gas: UnsignedGas,
        _registers: &[Register; REGISTERS_COUNT],
        _context: InvocationContext,
    ) -> Result<HostCallStateChange, VMError> {
        let gas_remaining = gas.wrapping_sub(10);
        Ok(HostCallStateChange {
            r0_change: Some((gas_remaining & 0xFFFFFFFF) as u32),
            r1_change: Some((gas_remaining >> 32) as u32),
            ..Default::default()
        })
    }
}
