use jam_codec::{JamCodecError, JamDecodeFixed, JamEncode, JamEncodeFixed};
use jam_common::{AccountAddress, Hash32, Octets, UnsignedGas};
use jam_crypto::utils::{blake2b_256, CryptoError};
use jam_pvm_types::{
    accumulation::DeferredTransfer,
    memory::{MemAddress, Memory, MemoryError},
    register::Register,
    types::{ExitReason, ExitReason::HostCall},
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

pub const HOST_CALL_INPUT_REGISTERS_COUNT: usize = 6;
pub const HOST_CALL_OUTPUT_REGISTERS_COUNT: usize = 2;
const BASE_GAS_USAGE: UnsignedGas = 10;

//
// Enums
//

#[derive(Debug, Error)]
pub enum HostCallError {
    #[error("Invalid host call invocation context")]
    InvalidContext,
    #[error("Invalid register indices")]
    InvalidRegisters,
    #[error("Account not found from the global account state")]
    AccountNotFound,
    #[error("GlobalStateError: {0}")]
    GlobalStateError(#[from] GlobalStateError),
    #[error("MemoryError: {0}")]
    MemoryError(#[from] MemoryError),
    #[error("CryptoError: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
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
    PageFault(MemAddress), // TODO: properly apply page fault exit reason for host call results
    General(HostCallVMStateChange),
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

pub struct HostCallVMStateChange {
    pub gas_usage: UnsignedGas,
    pub r0_write: Option<u32>,
    pub r1_write: Option<u32>,
    pub memory_write: (MemAddress, Octets, u32), // (start_address, data, data_len)
    pub exit_reason: ExitReason,                 // TODO: check if necessary
}

impl Default for HostCallVMStateChange {
    fn default() -> Self {
        Self {
            gas_usage: BASE_GAS_USAGE,
            r0_write: None,
            r1_write: None,
            memory_write: (0, vec![], 0),
            exit_reason: ExitReason::Continue,
        }
    }
}

//
// Host Call Results
//

pub struct AccumulationHostCallResult {
    pub vm_state_change: HostCallVMStateChange,
    pub post_contexts: (AccumulationContext, AccumulationContext), // context_x, context_y
}

//
// Util Functions
//

fn create_host_call_state_change(constant: HostCallResultConstant) -> HostCallVMStateChange {
    HostCallVMStateChange {
        gas_usage: BASE_GAS_USAGE,
        r0_write: Some(constant as u32),
        ..Default::default()
    }
}

macro_rules! define_host_call_state_change_function {
    ($func_name:ident, $constant:ident) => {
        pub fn $func_name() -> HostCallVMStateChange {
            create_host_call_state_change(HostCallResultConstant::$constant)
        }
    };
}

define_host_call_state_change_function!(none_change, NONE);
define_host_call_state_change_function!(oob_change, OOB);
define_host_call_state_change_function!(who_change, WHO);
define_host_call_state_change_function!(full_change, FULL);
define_host_call_state_change_function!(core_change, CORE);
define_host_call_state_change_function!(cash_change, CASH);
define_host_call_state_change_function!(low_change, LOW);
define_host_call_state_change_function!(high_change, HIGH);
define_host_call_state_change_function!(what_change, WHAT);
define_host_call_state_change_function!(huh_change, HUH);

//
// Host Functions
//

pub struct HostFunction;

impl HostFunction {
    //
    // General Functions
    //

    pub fn host_gas(
        gas: UnsignedGas,
        _registers: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        _context: &InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        let gas_remaining = gas.wrapping_sub(10);

        Ok(HostCallResult::General(HostCallVMStateChange {
            r0_write: Some((gas_remaining & 0xFFFFFFFF) as u32),
            r1_write: Some((gas_remaining >> 32) as u32),
            ..Default::default()
        }))
    }

    pub fn host_lookup(
        _gas: UnsignedGas,
        registers: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        invoker_account: &ServiceAccountState,
        invoker_account_address: AccountAddress,
        service_accounts: &ServiceAccounts,
    ) -> Result<HostCallResult, HostCallError> {
        let account_address = registers[0].value as AccountAddress;
        let [hash_offset, buffer_offset] = [registers[1].value, registers[2].value];
        let buffer_size = registers[3].value as usize;

        let account = if account_address == u32::MAX || account_address == invoker_account_address {
            invoker_account
        } else {
            service_accounts
                .0
                .get(&account_address)
                .ok_or(HostCallError::AccountNotFound)?
        };

        if !memory.is_range_readable(hash_offset, 32).unwrap() {
            return Ok(HostCallResult::General(oob_change()));
        }

        let hash = blake2b_256(&memory.read_bytes(hash_offset as MemAddress, 32)?)?;
        let preimage = account.preimages.get(&hash).cloned();

        match preimage {
            Some(data) => {
                let write_data_size = buffer_size.min(data.len());

                if !memory.is_range_writable(buffer_offset, buffer_size)? {
                    return Ok(HostCallResult::General(oob_change()));
                }

                Ok(HostCallResult::General(HostCallVMStateChange {
                    gas_usage: BASE_GAS_USAGE,
                    r0_write: Some(data.len() as u32),
                    memory_write: (
                        buffer_offset,
                        data[..write_data_size].to_vec(),
                        write_data_size as u32,
                    ),
                    ..Default::default()
                }))
            }
            None => Ok(HostCallResult::General(none_change())),
        }
    }

    pub fn host_read(
        _gas: UnsignedGas,
        registers: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        invoker_account: &ServiceAccountState,
        invoker_account_address: AccountAddress,
        service_accounts: &ServiceAccounts,
    ) -> Result<HostCallResult, HostCallError> {
        let account_address = registers[0].value as AccountAddress;
        let [key_offset, key_size, buffer_offset] =
            [registers[1].value, registers[2].value, registers[3].value];
        let buffer_size = registers[4].value as usize;

        let account = if account_address == u32::MAX || account_address == invoker_account_address {
            invoker_account
        } else {
            match service_accounts.0.get(&account_address) {
                Some(account) => account,
                None => return Ok(HostCallResult::General(none_change())),
            }
        };

        if !memory.is_range_readable(key_offset, key_size as usize)? {
            return Ok(HostCallResult::General(oob_change()));
        }

        let mut key = vec![];
        key.extend(invoker_account_address.encode_fixed(4)?);
        key.extend(memory.read_bytes(key_offset, key_size as usize)?);
        let storage_key = blake2b_256(&key)?;

        let value = account.storage.get(&storage_key).cloned();

        match value {
            Some(data) => {
                let write_data_size = buffer_size.min(data.len());

                if !memory.is_range_writable(buffer_offset, buffer_size)? {
                    return Ok(HostCallResult::General(oob_change()));
                }

                Ok(HostCallResult::General(HostCallVMStateChange {
                    gas_usage: BASE_GAS_USAGE,
                    r0_write: Some(data.len() as u32),
                    memory_write: (
                        buffer_offset,
                        data[..write_data_size].to_vec(),
                        write_data_size as u32,
                    ),
                    ..Default::default()
                }))
            }
            None => Ok(HostCallResult::General(none_change())),
        }
    }

    pub fn host_write(
        _gas: UnsignedGas,
        registers: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        invoker_account: &mut ServiceAccountState,
        invoker_account_address: AccountAddress, // TODO: check this param - not specified in the GP definition.
    ) -> Result<HostCallResult, HostCallError> {
        let [key_offset, value_offset] = [registers[0].value, registers[2].value];
        let [key_size, value_size] = [registers[1].value as usize, registers[3].value as usize];

        if !memory.is_range_readable(key_offset, key_size)?
            || !memory.is_range_readable(value_offset, value_size)?
        {
            return Ok(HostCallResult::General(oob_change()));
        }

        let mut key = vec![];
        key.extend(invoker_account_address.encode_fixed(4)?);
        key.extend(memory.read_bytes(key_offset, key_size)?);
        let storage_key = blake2b_256(&key)?;

        // create a local copy of the invoker service account and mutate the account storage
        let mut account = invoker_account.clone();

        let previous_size = if let Some(value) = account.storage.get(&storage_key) {
            value.len()
        } else {
            HostCallResultConstant::NONE as usize
        };

        if value_size == 0 {
            account.storage.remove(&storage_key);
        } else {
            let data = memory.read_bytes(value_offset, value_size)?;
            account.storage.insert(storage_key, data);
        }

        let result = if account.get_threshold_balance() > account.balance {
            Ok(HostCallResult::General(full_change()))
        } else {
            Ok(HostCallResult::General(HostCallVMStateChange {
                gas_usage: BASE_GAS_USAGE,
                r0_write: Some(previous_size as u32),
                ..Default::default()
            }))
        };

        *invoker_account = account; // update the service account state with the mutated local copy

        result
    }

    pub fn host_info(
        _gas: UnsignedGas,
        registers: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        invoker_account: &ServiceAccountState,
        invoker_account_address: AccountAddress,
        service_accounts: &ServiceAccounts,
    ) -> Result<HostCallResult, HostCallError> {
        let account_address = registers[0].value as AccountAddress;
        let buffer_offset = registers[1].value;

        let account = if account_address == u32::MAX || account_address == invoker_account_address {
            invoker_account
        } else {
            // TODO: find the account from the service accounts dictionary "and" the new accounts
            // TODO: of provided invocation context, which is currently not specified in the GP
            match service_accounts.0.get(&account_address) {
                Some(account) => account,
                None => return Ok(HostCallResult::General(none_change())),
            }
        };

        // Encode account fields with JAM Codec
        let mut info = vec![];
        account.code_hash.encode_to(&mut info)?; // c
        account.balance.encode_to(&mut info)?; // b
        account.get_threshold_balance().encode_to(&mut info)?; // t
        account.gas_limit_accumulate.encode_to(&mut info)?; // g
        account.gas_limit_on_transfer.encode_to(&mut info)?; // m
        account.get_total_octets_footprint().encode_to(&mut info)?; // l
        account.get_item_counts_footprint().encode_to(&mut info)?; // i

        if !memory.is_range_writable(buffer_offset, info.len())? {
            return Ok(HostCallResult::General(oob_change()));
        }

        Ok(HostCallResult::General(HostCallVMStateChange {
            gas_usage: BASE_GAS_USAGE,
            r0_write: Some(HostCallResultConstant::OK as u32),
            memory_write: (buffer_offset, info.clone(), info.len() as u32),
            ..Default::default()
        }))
    }

    //
    // Accumulate Functions
    //

    // Accumulation host functions mutate: gas, registers, contexts
    pub fn host_empower(
        _gas: UnsignedGas,
        registers: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        context: &InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        if let InvocationContext::X_A((x, y)) = context {
            let mut post_x = x.clone();
            let [empower, assign, designate] = registers[..3] else {
                return Err(HostCallError::InvalidRegisters);
            };

            post_x.privileged_services.empower_service_index = empower.value;
            post_x.privileged_services.assign_service_index = assign.value;
            post_x.privileged_services.designate_service_index = designate.value;

            Ok(HostCallResult::Accumulation(AccumulationHostCallResult {
                vm_state_change: HostCallVMStateChange::default(),
                post_contexts: (post_x, y.clone()),
            }))
        } else {
            Err(HostCallError::InvalidContext)
        }
    }

    pub fn host_assign(
        _gas: UnsignedGas,
        registers: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        context: &InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        todo!()
    }

    //
    // Refine Functions
    //
}
