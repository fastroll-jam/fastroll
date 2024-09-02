use jam_codec::{JamDecodeFixed, JamEncode};
use jam_common::{AccountAddress, Hash32, Octets, UnsignedGas};
use jam_crypto::utils::blake2b_256;
use jam_pvm_types::{
    accumulation::DeferredTransfer, constants::REGISTERS_COUNT, memory::MemAddress,
    register::Register, types::ExitReason,
};
use jam_state::{global_state::GlobalStateError, state_retriever::StateRetriever};
use jam_types::state::{
    authorizer::AuthorizerQueue,
    privileged::PrivilegedServices,
    services::{ServiceAccountState, ServiceAccounts},
    timeslot::Timeslot,
    validators::StagingValidatorSet,
};
use thiserror::Error;

//
// Constants
//

const HOST_CALL_INPUT_REGISTERS_COUNT: usize = 6;
const HOST_CALL_OUTPUT_REGISTERS_COUNT: usize = 2;

//
// Enums
//

#[derive(Debug, Error)]
pub enum HostCallError {
    #[error("Invalid host call invocation context")]
    InvalidContext,
    #[error("Invalid register indices")]
    InvalidRegisters,
    #[error("GlobalStateError: {0}")]
    GlobalStateError(#[from] GlobalStateError),
}

#[repr(u32)]
pub enum HostCallResultConstant {
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

#[derive(Clone)]
#[allow(non_camel_case_types)]
pub enum InvocationContext {
    X_G,                                             // General Functions
    X_I,                                             // Is-Authorized
    X_R,                                             // Refine
    X_A((AccumulationContext, AccumulationContext)), // Accumulate
    X_T,                                             // On-Transfer
}

pub enum HostCallResult {
    General(HostCallStateChange),
    IsAuthorized,
    Refinement,
    Accumulation(AccumulationHostCallResult),
    OnTransfer,
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
    ) -> Result<(Self, Self), HostCallError> {
        // Get current global state components
        let state_retriever = StateRetriever::new();
        let privileged_services = state_retriever.get_privileged_services()?;
        let authorizer_queue = state_retriever.get_authorizer_queue()?;
        let staging_validator_set = state_retriever.get_staging_validator_set()?;
        let entropy_0 = state_retriever.get_entropy_accumulator()?.current();
        let timeslot = state_retriever.get_recent_timeslot()?;

        let context = Self {
            service_account: Some(invoker_account),
            deferred_transfers: vec![],
            new_service_index: Self::new_account_address(
                service_accounts,
                invoker_account_address,
                entropy_0,
                timeslot,
            ),
            privileged_services,
            authorizer_queue,
            staging_validator_set,
            new_accounts: ServiceAccounts::default(),
        };

        Ok((context.clone(), context))
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

pub struct HostCallStateChange {
    pub gas_change: UnsignedGas,
    pub r0_change: Option<u32>,
    pub r1_change: Option<u32>,
    pub memory_change: (MemAddress, Octets, u32), // (start_address, data, data_len)
    pub exit_reason: ExitReason,                  // TODO: check if necessary
}

impl Default for HostCallStateChange {
    fn default() -> Self {
        Self {
            gas_change: 0,
            r0_change: None,
            r1_change: None,
            memory_change: (0, vec![], 0),
            exit_reason: ExitReason::Continue,
        }
    }
}

//
// Host Call Results
//

struct AccumulationHostCallResult {
    vm_state_change: HostCallStateChange,
    post_context: AccumulationContext,
}

//
// Host Functions
//

pub struct HostFunction;

impl HostFunction {
    pub fn host_gas(
        gas: UnsignedGas,
        _registers: &[Register; REGISTERS_COUNT],
        _context: &InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        let gas_remaining = gas.wrapping_sub(10);

        Ok(HostCallResult::General(HostCallStateChange {
            r0_change: Some((gas_remaining & 0xFFFFFFFF) as u32),
            r1_change: Some((gas_remaining >> 32) as u32),
            ..Default::default()
        }))
    }

    // Accumulation host functions mutate: gas, registers, contexts
    pub fn host_empower(
        gas: UnsignedGas,
        registers: &[Register; REGISTERS_COUNT],
        context: &InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        if let InvocationContext::X_A((x, _y)) = context {
            let mut post_x = x.clone();
            let [empower, assign, designate] = registers[..3] else {
                return Err(HostCallError::InvalidRegisters);
            };

            post_x.privileged_services.empower_service_index = empower.value;
            post_x.privileged_services.assign_service_index = assign.value;
            post_x.privileged_services.designate_service_index = designate.value;

            Ok(HostCallResult::Accumulation(AccumulationHostCallResult {
                vm_state_change: HostCallStateChange::default(),
                post_context: post_x,
            }))
        } else {
            Err(HostCallError::InvalidContext)
        }
    }
}
