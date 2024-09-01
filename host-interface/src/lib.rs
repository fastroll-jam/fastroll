use jam_codec::{JamDecodeFixed, JamEncode};
use jam_common::{AccountAddress, Hash32, Octets, UnsignedGas};
use jam_crypto::utils::blake2b_256;
use jam_pvm_types::{
    accumulation::DeferredTransfer, constants::REGISTERS_COUNT, memory::MemAddress,
    register::Register, types::ExitReason,
};
use jam_types::state::{
    authorizer::AuthorizerQueue,
    privileged::PrivilegedServices,
    services::{ServiceAccountState, ServiceAccounts},
    timeslot::Timeslot,
    validators::StagingValidatorSet,
};
use thiserror::Error;

//
// Enums
//

// FIXME: move
#[derive(Debug, Error)]
pub enum HostCallError {}

#[repr(u32)]
pub enum HostCallResult {
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
pub enum InnerPVMInvocationResult {
    HALT = 0,
    PANIC = u32::MAX - 11,
    FAULT = u32::MAX - 12,
    HOST = u32::MAX - 13,
}

// TODO: add service accounts context
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub enum InvocationContext {
    X_G,                                             // General Functions
    X_I,                                             // Is-Authorized
    X_R,                                             // Refine
    X_A((AccumulationContext, AccumulationContext)), // Accumulate
    X_T,                                             // On-Transfer
}

//
// Invocation Contexts
//

#[derive(Clone)]
pub struct AccumulationContext {
    service_account: Option<ServiceAccountState>, // current service account
    authorizer_queue: AuthorizerQueue,
    staging_validator_set: StagingValidatorSet,
    new_service_index: AccountAddress,
    deferred_transfers: Vec<DeferredTransfer>,
    new_accounts: ServiceAccounts,
    privileged_services: PrivilegedServices,
}

impl AccumulationContext {
    pub fn initialize_context_pair(
        service_accounts: &ServiceAccounts,
        invoker_account: ServiceAccountState,
        invoker_account_address: AccountAddress,
        privileged_services: PrivilegedServices,
        authorizer_queue: AuthorizerQueue,
        staging_validator_set: StagingValidatorSet,
        entropy: Hash32,
        timeslot: Timeslot,
    ) -> (Self, Self) {
        let context = Self {
            service_account: Some(invoker_account),
            deferred_transfers: vec![],
            new_service_index: Self::new_account_address(
                service_accounts,
                invoker_account_address,
                entropy,
                timeslot,
            ),
            privileged_services,
            authorizer_queue,
            staging_validator_set,
            new_accounts: ServiceAccounts::default(),
        };

        (context.clone(), context)
    }

    fn new_account_address(
        service_accounts_state: &ServiceAccounts,
        invoker_account_address: AccountAddress,
        entropy: Hash32,
        timeslot: Timeslot,
    ) -> AccountAddress {
        // TODO: check return type
        // TODO: confirm how to deal with hash of a tuple; H(address, entropy, timestamp)
        // TODO: check GP appendix B.4.
        let mut buf = vec![];
        invoker_account_address.encode_to(&mut buf).unwrap();
        entropy.encode_to(&mut buf).unwrap();
        timeslot.0.encode_to(&mut buf).unwrap();

        let mut source_hash = blake2b_256(&buf[..]).unwrap();
        let initial_check_address = (u32::decode_fixed(&mut &source_hash[..], 4).unwrap() as u64
            & ((1 << 32) - (1 << 9)) + (1 << 8))
            as AccountAddress;

        service_accounts_state.check(initial_check_address)
    }
}

//
// Invocation Results
//

pub enum AccumulationResult {
    Unchanged(ServiceAccountState),
    Result(AccumulationContext, Option<Hash32>), // (context, result_hash)
}

struct ServiceAccountChange; // TODO: impl

pub struct HostCallStateChange {
    pub gas_change: UnsignedGas,
    pub r0_change: Option<u32>,
    pub r1_change: Option<u32>,
    pub memory_change: (MemAddress, Octets, u32), // (start_address, data, data_len)
    pub service_accounts_changes: Vec<(u32, ServiceAccountChange)>, // u32 for service account index; TODO: better data handling
    pub exit_reason: ExitReason,                                    // TODO: check if necessary
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
// Host functions
//

// TODO: pass these functions as callback arguments to the invocation functions

pub struct HostFunction;

impl HostFunction {
    pub fn host_gas(
        gas: UnsignedGas,
        _registers: &[Register; REGISTERS_COUNT],
        _context: &InvocationContext,
    ) -> Result<HostCallStateChange, HostCallError> {
        let gas_remaining = gas.wrapping_sub(10);
        Ok(HostCallStateChange {
            r0_change: Some((gas_remaining & 0xFFFFFFFF) as u32),
            r1_change: Some((gas_remaining >> 32) as u32),
            ..Default::default()
        })
    }
}
