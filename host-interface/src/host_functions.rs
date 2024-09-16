use crate::{
    contexts::{AccumulationContext, InvocationContext, RefinementContext},
    host_functions::InnerPVMResultConstant::{FAULT, HALT, HOST, PANIC},
    inner_vm::InnerPVM,
    utils::*,
};
use jam_codec::{JamDecode, JamDecodeFixed, JamEncode, JamEncodeFixed};
use jam_common::{
    AccountAddress, Hash32, Octets, TokenBalance, UnsignedGas, ValidatorKey, CORE_COUNT,
    HASH32_DEFAULT, HASH_SIZE, MAX_AUTH_QUEUE_SIZE, VALIDATOR_COUNT,
};
use jam_crypto::utils::blake2b_256;
use jam_pvm_core::{
    accumulation::{DeferredTransfer, TRANSFER_MEMO_SIZE},
    constants::{
        BASE_GAS_USAGE, DATA_SEGMENTS_SIZE, HOST_CALL_INPUT_REGISTERS_COUNT,
        PREIMAGE_EXPIRATION_PERIOD, REGISTERS_COUNT,
    },
    memory::{AccessType, MemAddress, Memory},
    register::Register,
    types::{ExitReason, ExportDataSegment, HostCallError},
    vm_core::{PVMCore, Program, VMState},
};
use jam_types::state::{
    services::{ServiceAccountState, ServiceAccounts, B_S},
    timeslot::Timeslot,
    validators::StagingValidatorSet,
};
use std::collections::{btree_map::Entry, BTreeMap};
//
// Enums
//

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
pub enum InnerPVMResultConstant {
    HALT = 0,
    PANIC = 1,
    FAULT = 2,
    HOST = 3,
}

pub enum HostCallResult {
    VMHalt(HostCallVMStateChange),
    PageFault(MemAddress), // TODO: properly apply page fault exit reason for host call results
    General(HostCallVMStateChange),
    IsAuthorized,
    Refinement(RefinementHostCallResult),
    Accumulation(AccumulationHostCallResult),
    OnTransfer,
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
    pub memory_write: (MemAddress, u32, Octets), // (start_address, data_len, data)
    pub exit_reason: ExitReason,                 // TODO: check if necessary
}

impl Default for HostCallVMStateChange {
    fn default() -> Self {
        Self {
            gas_usage: BASE_GAS_USAGE,
            r0_write: None,
            r1_write: None,
            memory_write: (0, 0, vec![]),
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

pub struct RefinementHostCallResult {
    pub vm_state_change: HostCallVMStateChange,
    pub post_context: RefinementContext,
}

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
        context: &InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        let x = match context {
            InvocationContext::X_G(x) => x.clone(),
            _ => return Err(HostCallError::InvalidContext),
        };

        let account_address = registers[0].value as AccountAddress;
        let [hash_offset, buffer_offset] = [registers[1].value, registers[2].value];
        let buffer_size = registers[3].value as usize;

        let account = if account_address == u32::MAX || account_address == x.invoker_address {
            x.invoker_account
        } else {
            x.service_accounts
                .unwrap()
                .0
                .get(&account_address)
                .cloned()
                .ok_or(HostCallError::AccountNotFound)?
        };

        if !memory.is_range_readable(hash_offset, 32).unwrap() {
            return Ok(HostCallResult::General(oob_change(BASE_GAS_USAGE)));
        }

        let hash = blake2b_256(&memory.read_bytes(hash_offset as MemAddress, 32)?)?;
        let preimage = account.preimages.get(&hash).cloned();

        match preimage {
            Some(data) => {
                let write_data_size = buffer_size.min(data.len());

                if !memory.is_range_writable(buffer_offset, buffer_size)? {
                    return Ok(HostCallResult::General(oob_change(BASE_GAS_USAGE)));
                }

                Ok(HostCallResult::General(HostCallVMStateChange {
                    gas_usage: BASE_GAS_USAGE,
                    r0_write: Some(data.len() as u32),
                    memory_write: (
                        buffer_offset,
                        write_data_size as u32,
                        data[..write_data_size].to_vec(),
                    ),
                    ..Default::default()
                }))
            }
            None => Ok(HostCallResult::General(none_change(BASE_GAS_USAGE))),
        }
    }

    pub fn host_read(
        _gas: UnsignedGas,
        registers: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        context: &InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        let x = match context {
            InvocationContext::X_G(x) => x.clone(),
            _ => return Err(HostCallError::InvalidContext),
        };

        let account_address = registers[0].value as AccountAddress;
        let [key_offset, key_size, buffer_offset] =
            [registers[1].value, registers[2].value, registers[3].value];
        let buffer_size = registers[4].value as usize;

        let account = if account_address == u32::MAX || account_address == x.invoker_address {
            x.invoker_account
        } else {
            match x.service_accounts.unwrap().0.get(&account_address).cloned() {
                Some(account) => account,
                None => return Ok(HostCallResult::General(none_change(BASE_GAS_USAGE))),
            }
        };

        if !memory.is_range_readable(key_offset, key_size as usize)? {
            return Ok(HostCallResult::General(oob_change(BASE_GAS_USAGE)));
        }

        let mut key = vec![];
        key.extend(x.invoker_address.encode_fixed(4)?);
        key.extend(memory.read_bytes(key_offset, key_size as usize)?);
        let storage_key = blake2b_256(&key)?;

        if let Some(data) = account.storage.get(&storage_key).cloned() {
            let write_data_size = buffer_size.min(data.len());

            if !memory.is_range_writable(buffer_offset, buffer_size)? {
                return Ok(HostCallResult::General(oob_change(BASE_GAS_USAGE)));
            }

            Ok(HostCallResult::General(HostCallVMStateChange {
                gas_usage: BASE_GAS_USAGE,
                r0_write: Some(data.len() as u32),
                memory_write: (
                    buffer_offset,
                    write_data_size as u32,
                    data[..write_data_size].to_vec(),
                ),
                ..Default::default()
            }))
        } else {
            Ok(HostCallResult::General(none_change(BASE_GAS_USAGE)))
        }
    }

    pub fn host_write(
        _gas: UnsignedGas,
        registers: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        context: &InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        // TODO: check if `invoker_address` is provided as an arg - not specified in the GP
        let mut x = match context {
            InvocationContext::X_G(x) => x.clone(),
            _ => return Err(HostCallError::InvalidContext),
        };

        let [key_offset, value_offset] = [registers[0].value, registers[2].value];
        let [key_size, value_size] = [registers[1].value as usize, registers[3].value as usize];

        if !memory.is_range_readable(key_offset, key_size)?
            || !memory.is_range_readable(value_offset, value_size)?
        {
            return Ok(HostCallResult::General(oob_change(BASE_GAS_USAGE)));
        }

        let mut key = vec![];
        key.extend(x.invoker_address.encode_fixed(4)?);
        key.extend(memory.read_bytes(key_offset, key_size)?);
        let storage_key = blake2b_256(&key)?;

        // create a local copy of the invoker service account and mutate the account storage
        let mut account = x.invoker_account.clone();

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
            Ok(HostCallResult::General(full_change(BASE_GAS_USAGE)))
        } else {
            Ok(HostCallResult::General(HostCallVMStateChange {
                gas_usage: BASE_GAS_USAGE,
                r0_write: Some(previous_size as u32),
                ..Default::default()
            }))
        };

        x.invoker_account = account; // update the service account state with the mutated local copy

        result
    }

    pub fn host_info(
        _gas: UnsignedGas,
        registers: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        context: &InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        let x = match context {
            InvocationContext::X_G(x) => x.clone(),
            _ => return Err(HostCallError::InvalidContext),
        };

        let account_address = registers[0].value as AccountAddress;
        let buffer_offset = registers[1].value;

        let account = if account_address == u32::MAX || account_address == x.invoker_address {
            x.invoker_account
        } else {
            // TODO: find the account from the service accounts dictionary "and" the new accounts
            // TODO: of provided invocation context, which is currently not specified in the GP
            match x.service_accounts.unwrap().0.get(&account_address).cloned() {
                Some(account) => account,
                None => return Ok(HostCallResult::General(none_change(BASE_GAS_USAGE))),
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
            return Ok(HostCallResult::General(oob_change(BASE_GAS_USAGE)));
        }

        Ok(HostCallResult::General(HostCallVMStateChange {
            gas_usage: BASE_GAS_USAGE,
            r0_write: Some(HostCallResultConstant::OK as u32),
            memory_write: (buffer_offset, info.len() as u32, info.clone()),
            ..Default::default()
        }))
    }

    //
    // Accumulate Functions
    //

    // TODO: delete unnecessary clones of `x` and `y`

    // Accumulation host functions mutate: gas, registers, contexts
    pub fn host_empower(
        _gas: UnsignedGas,
        registers: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        _memory: &Memory,
        context: &InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        let (mut x, y) = match context {
            InvocationContext::X_A((x, y)) => (x.clone(), y.clone()),
            _ => return Err(HostCallError::InvalidContext),
        };
        let [empower, assign, designate] = registers[..3] else {
            return Err(HostCallError::InvalidRegisters);
        };

        x.privileged_services.empower_service_index = empower.value;
        x.privileged_services.assign_service_index = assign.value;
        x.privileged_services.designate_service_index = designate.value;

        Ok(HostCallResult::Accumulation(AccumulationHostCallResult {
            vm_state_change: HostCallVMStateChange::default(),
            post_contexts: (x, y),
        }))
    }

    pub fn host_assign(
        _gas: UnsignedGas,
        registers: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        context: &InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        let (mut x, y) = match context {
            InvocationContext::X_A((x, y)) => (x.clone(), y.clone()),
            _ => return Err(HostCallError::InvalidContext),
        };

        let core_index = registers[0].value as usize;
        let offset = registers[1].value as MemAddress;

        if !memory.is_range_readable(offset, HASH_SIZE * MAX_AUTH_QUEUE_SIZE)? {
            return Ok(HostCallResult::Accumulation(AccumulationHostCallResult {
                vm_state_change: oob_change(BASE_GAS_USAGE),
                post_contexts: (x, y),
            }));
        }

        if core_index >= CORE_COUNT {
            return Ok(HostCallResult::Accumulation(AccumulationHostCallResult {
                vm_state_change: core_change(BASE_GAS_USAGE),
                post_contexts: (x, y),
            }));
        }

        let mut queue_assignment = [HASH32_DEFAULT; MAX_AUTH_QUEUE_SIZE];
        for i in 0..MAX_AUTH_QUEUE_SIZE {
            if let Ok(slice) = memory.read_bytes(offset + (HASH_SIZE * i) as MemAddress, HASH_SIZE)
            {
                queue_assignment[i] = Hash32::decode(&mut &slice[..])?;
            }
        }

        x.authorizer_queue.0[core_index] = queue_assignment;

        Ok(HostCallResult::Accumulation(AccumulationHostCallResult {
            vm_state_change: ok_change(BASE_GAS_USAGE),
            post_contexts: (x, y),
        }))
    }

    pub fn host_designate(
        _gas: UnsignedGas,
        registers: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        context: &InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        let (mut x, y) = match context {
            InvocationContext::X_A((x, y)) => (x.clone(), y.clone()),
            _ => return Err(HostCallError::InvalidContext),
        };

        let offset = registers[0].value as MemAddress;

        // FIXME: check the public key blob length - the PVM spec describes as 176 but public key blob is 336 bytes in general
        const PUBLIC_KEY_SIZE: usize = 336;
        if !memory.is_range_readable(offset, PUBLIC_KEY_SIZE * VALIDATOR_COUNT)? {
            return Ok(HostCallResult::Accumulation(AccumulationHostCallResult {
                vm_state_change: oob_change(BASE_GAS_USAGE),
                post_contexts: (x, y),
            }));
        }

        let mut new_staging_set = StagingValidatorSet::default();
        for i in 0..VALIDATOR_COUNT {
            if let Ok(slice) = memory.read_bytes(
                offset + (PUBLIC_KEY_SIZE * i) as MemAddress,
                PUBLIC_KEY_SIZE,
            ) {
                let validator_key = ValidatorKey::decode(&mut &slice[..])?;
                new_staging_set.0[i] = validator_key;
            }
        }

        x.staging_validator_set = new_staging_set;

        Ok(HostCallResult::Accumulation(AccumulationHostCallResult {
            vm_state_change: ok_change(BASE_GAS_USAGE),
            post_contexts: (x, y),
        }))
    }

    pub fn host_checkpoint(
        gas: UnsignedGas,
        _registers: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        _memory: &Memory,
        context: &InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        let x = match context {
            InvocationContext::X_A((x, _)) => x.clone(),
            _ => return Err(HostCallError::InvalidContext),
        };

        let post_gas = gas.saturating_sub(BASE_GAS_USAGE); // TODO: gas management

        Ok(HostCallResult::Accumulation(AccumulationHostCallResult {
            vm_state_change: HostCallVMStateChange {
                gas_usage: BASE_GAS_USAGE,
                r0_write: Some(post_gas as u32),
                r1_write: Some((post_gas >> 32) as u32),
                ..Default::default()
            },
            post_contexts: (x.clone(), x),
        }))
    }

    pub fn host_new(
        _gas: UnsignedGas,
        registers: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        context: &InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        let (mut x, y) = match context {
            InvocationContext::X_A((x, y)) => (x.clone(), y.clone()),
            _ => return Err(HostCallError::InvalidContext),
        };

        let [offset, lookup_len, gas_limit_g_low, gas_limit_g_high, gas_limit_m_low, gas_limit_m_high] =
            registers.map(|r| r.value);

        if !memory.is_range_readable(offset as MemAddress, HASH_SIZE)? {
            return Ok(HostCallResult::Accumulation(AccumulationHostCallResult {
                vm_state_change: oob_change(BASE_GAS_USAGE),
                post_contexts: (x, y),
            }));
        }

        let code_hash = Hash32::decode(
            &mut memory
                .read_bytes(offset as MemAddress, HASH_SIZE)?
                .as_slice(),
        )?;
        let gas_limit_g = ((gas_limit_g_high as u64) << 32 | gas_limit_g_low as u64) as UnsignedGas;
        let gas_limit_m = ((gas_limit_m_high as u64) << 32 | gas_limit_m_low as u64) as UnsignedGas;

        let mut new_account = ServiceAccountState {
            code_hash,
            storage: Default::default(),
            preimages: Default::default(),
            lookups: BTreeMap::from([((code_hash, lookup_len), vec![])]),
            balance: 0,
            gas_limit_accumulate: gas_limit_g,
            gas_limit_on_transfer: gas_limit_m,
        };

        let new_threshold_balance = new_account.get_threshold_balance();
        new_account.balance = new_threshold_balance; // set initial account balance
        let context_account_balance = x
            .service_account
            .as_ref()
            .unwrap()
            .balance
            .saturating_sub(new_threshold_balance);

        if context_account_balance < x.service_account.as_ref().unwrap().get_threshold_balance() {
            return Ok(HostCallResult::Accumulation(AccumulationHostCallResult {
                vm_state_change: cash_change(BASE_GAS_USAGE),
                post_contexts: (x, y), // TODO: check - should return x_T
            }));
        }

        let new_service_index = x.new_service_index;

        let bump = |a: AccountAddress| -> AccountAddress {
            ((a as u64 - (1u64 << 8) + 42) % ((1u64 << 32) - (1u64 << 9)) + (1u64 << 8))
                as AccountAddress
        };

        // FIXME: this operation needs global service account state for `check`
        x.new_service_index = bump(new_service_index); // bump new service index for the next account generation
        x.new_accounts.0.insert(new_service_index, new_account);
        x.service_account
            .as_mut()
            .ok_or(HostCallError::InvalidContext)?
            .balance = context_account_balance;

        Ok(HostCallResult::Accumulation(AccumulationHostCallResult {
            vm_state_change: HostCallVMStateChange {
                gas_usage: BASE_GAS_USAGE,
                r0_write: Some(new_service_index),
                ..Default::default()
            },
            post_contexts: (x, y),
        }))
    }

    pub fn host_upgrade(
        _gas: UnsignedGas,
        registers: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        context: &InvocationContext,
        _invoker_address: AccountAddress,
    ) -> Result<HostCallResult, HostCallError> {
        let (mut x, y) = match context {
            InvocationContext::X_A((x, y)) => (x.clone(), y.clone()),
            _ => return Err(HostCallError::InvalidContext),
        };

        let [offset, gas_limit_g_low, gas_limit_g_high, gas_limit_m_low, gas_limit_m_high, ..] =
            registers.map(|r| r.value);

        if !memory.is_range_readable(offset, HASH_SIZE)? {
            return Ok(HostCallResult::Accumulation(AccumulationHostCallResult {
                vm_state_change: oob_change(BASE_GAS_USAGE),
                post_contexts: (x, y),
            }));
        }

        let code_hash = Hash32::decode(
            &mut memory
                .read_bytes(offset as MemAddress, HASH_SIZE)?
                .as_slice(),
        )?;
        let gas_limit_g = ((gas_limit_g_high as u64) << 32 | gas_limit_g_low as u64) as UnsignedGas;
        let gas_limit_m = ((gas_limit_m_high as u64) << 32 | gas_limit_m_low as u64) as UnsignedGas;

        let context_account = x
            .service_account
            .as_mut()
            .ok_or(HostCallError::InvalidContext)?;
        context_account.code_hash = code_hash;
        context_account.gas_limit_accumulate = gas_limit_g;
        context_account.gas_limit_on_transfer = gas_limit_m;

        Ok(HostCallResult::Accumulation(AccumulationHostCallResult {
            vm_state_change: ok_change(BASE_GAS_USAGE),
            post_contexts: (x, y),
        }))
    }

    pub fn host_transfer(
        gas: UnsignedGas,
        registers: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        context: &InvocationContext,
        invoker_address: AccountAddress,
        service_accounts: &ServiceAccounts,
    ) -> Result<HostCallResult, HostCallError> {
        let (mut x, y) = match context {
            InvocationContext::X_A((x, y)) => (x.clone(), y.clone()),
            _ => return Err(HostCallError::InvalidContext),
        };

        let [destination, amount_low, amount_high, gas_limit_low, gas_limit_high, offset] =
            registers.map(|r| r.value);

        let amount = ((amount_high as u64) << 32 | amount_low as u64) as TokenBalance;
        let gas_limit = ((gas_limit_high as u64) << 32 | gas_limit_low as u64) as UnsignedGas;

        if !memory.is_range_readable(offset, TRANSFER_MEMO_SIZE)? {
            return Ok(HostCallResult::Accumulation(AccumulationHostCallResult {
                vm_state_change: oob_change(BASE_GAS_USAGE),
                post_contexts: (x, y),
            }));
        }

        let transfer_memo =
            JamDecode::decode(&mut &memory.read_bytes(offset, TRANSFER_MEMO_SIZE)?[..])?;

        let transfer = DeferredTransfer {
            from: invoker_address,
            to: destination as AccountAddress,
            amount,
            memo: transfer_memo,
            gas_limit,
        };

        let post_balance = x.service_account.as_ref().unwrap().balance - amount;

        if !service_accounts.0.contains_key(&destination)
            && !x.new_accounts.0.contains_key(&destination)
        {
            return Ok(HostCallResult::Accumulation(AccumulationHostCallResult {
                vm_state_change: who_change(BASE_GAS_USAGE + amount),
                post_contexts: (x, y),
            }));
        }

        let destination_gas_limit_m = service_accounts
            .0
            .get(&destination)
            .or_else(|| x.new_accounts.0.get(&destination))
            .unwrap()
            .gas_limit_on_transfer;

        if gas_limit < destination_gas_limit_m {
            return Ok(HostCallResult::Accumulation(AccumulationHostCallResult {
                vm_state_change: low_change(BASE_GAS_USAGE + amount),
                post_contexts: (x, y),
            }));
        }

        if gas < gas_limit {
            return Ok(HostCallResult::Accumulation(AccumulationHostCallResult {
                vm_state_change: high_change(BASE_GAS_USAGE + amount),
                post_contexts: (x, y),
            }));
        }

        if post_balance < x.service_account.as_ref().unwrap().get_threshold_balance() {
            return Ok(HostCallResult::Accumulation(AccumulationHostCallResult {
                vm_state_change: cash_change(BASE_GAS_USAGE + amount),
                post_contexts: (x, y),
            }));
        }

        // context states update
        x.deferred_transfers.push(transfer);
        x.service_account
            .as_mut()
            .ok_or(HostCallError::InvalidContext)?
            .balance = post_balance;

        Ok(HostCallResult::Accumulation(AccumulationHostCallResult {
            vm_state_change: oob_change(BASE_GAS_USAGE + amount),
            post_contexts: (x, y),
        }))
    }

    pub fn host_quit(
        gas: UnsignedGas,
        registers: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        context: &InvocationContext,
        invoker_address: AccountAddress,
        service_accounts: &ServiceAccounts, // TODO: check - not included in the GP
    ) -> Result<HostCallResult, HostCallError> {
        let (mut x, y) = match context {
            InvocationContext::X_A((x, y)) => (x.clone(), y.clone()),
            _ => return Err(HostCallError::InvalidContext),
        };

        let [destination, offset, ..] = registers.map(|r| r.value);

        let context_account = x.service_account.as_ref().unwrap();
        let amount = context_account
            .balance
            .wrapping_sub(context_account.get_threshold_balance())
            + B_S;

        if destination == u32::MAX || destination == invoker_address {
            return Ok(HostCallResult::VMHalt(ok_change(BASE_GAS_USAGE))); // TODO: check gas usage from the GP
        }

        if !memory.is_range_readable(offset, TRANSFER_MEMO_SIZE)? {
            return Ok(HostCallResult::Accumulation(AccumulationHostCallResult {
                vm_state_change: oob_change(BASE_GAS_USAGE),
                post_contexts: (x, y),
            }));
        }

        let transfer_memo =
            JamDecode::decode(&mut &memory.read_bytes(offset, TRANSFER_MEMO_SIZE)?[..])?;

        let transfer = DeferredTransfer {
            from: invoker_address,
            to: destination as AccountAddress,
            amount,
            memo: transfer_memo,
            gas_limit: gas,
        };

        if !service_accounts.0.contains_key(&destination)
            && !x.new_accounts.0.contains_key(&destination)
        {
            return Ok(HostCallResult::Accumulation(AccumulationHostCallResult {
                vm_state_change: who_change(BASE_GAS_USAGE + amount),
                post_contexts: (x, y),
            }));
        }

        let destination_gas_limit_m = service_accounts
            .0
            .get(&destination)
            .or_else(|| x.new_accounts.0.get(&destination))
            .unwrap()
            .gas_limit_on_transfer;

        if gas < destination_gas_limit_m {
            return Ok(HostCallResult::Accumulation(AccumulationHostCallResult {
                vm_state_change: low_change(BASE_GAS_USAGE + amount),
                post_contexts: (x, y),
            }));
        }

        x.deferred_transfers.push(transfer);
        Ok(HostCallResult::VMHalt(ok_change(BASE_GAS_USAGE)))
    }

    pub fn host_solicit(
        _gas: UnsignedGas,
        registers: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        context: &InvocationContext,
        timeslot: Timeslot, // TODO: check - not included in the GP
    ) -> Result<HostCallResult, HostCallError> {
        let (mut x, y) = match context {
            InvocationContext::X_A((x, y)) => (x.clone(), y.clone()),
            _ => return Err(HostCallError::InvalidContext),
        };

        let [offset, lookup_len, ..] = registers.map(|r| r.value);

        if !memory.is_range_readable(offset, HASH_SIZE)? {
            return Ok(HostCallResult::Accumulation(AccumulationHostCallResult {
                vm_state_change: oob_change(BASE_GAS_USAGE),
                post_contexts: (x, y),
            }));
        }

        let lookup_hash = Hash32::decode(
            &mut memory
                .read_bytes(offset as MemAddress, HASH_SIZE)?
                .as_slice(),
        )?;

        let account = x
            .service_account
            .as_mut()
            .ok_or(HostCallError::InvalidContext)?;
        if account.balance < account.get_threshold_balance() {
            return Ok(HostCallResult::Accumulation(AccumulationHostCallResult {
                vm_state_change: full_change(BASE_GAS_USAGE),
                post_contexts: (x, y),
            }));
        }

        // Insert current timeslot if the entry exists.
        // If the key doesn't exist, insert a new empty Vec<Timeslot> with the key.
        // If the entry's timeslot vector length is not equal to 2, return with result constant `HUH`.
        match account.lookups.entry((lookup_hash, lookup_len)) {
            Entry::Vacant(vacant_entry) => {
                vacant_entry.insert(vec![timeslot]);
            }
            Entry::Occupied(mut entry) => {
                let timeslots = entry.get_mut();
                if timeslots.len() == 2 {
                    timeslots.push(timeslot);
                } else {
                    return Ok(HostCallResult::Accumulation(AccumulationHostCallResult {
                        vm_state_change: huh_change(BASE_GAS_USAGE),
                        post_contexts: (x, y),
                    }));
                }
            }
        }

        Ok(HostCallResult::Accumulation(AccumulationHostCallResult {
            vm_state_change: ok_change(BASE_GAS_USAGE),
            post_contexts: (x, y),
        }))
    }

    pub fn host_forget(
        _gas: UnsignedGas,
        registers: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        context: &InvocationContext,
        timeslot: Timeslot,
    ) -> Result<HostCallResult, HostCallError> {
        let (mut x, y) = match context {
            InvocationContext::X_A((x, y)) => (x.clone(), y.clone()),
            _ => return Err(HostCallError::InvalidContext),
        };

        let [offset, lookup_len, ..] = registers.map(|r| r.value);

        if !memory.is_range_readable(offset, HASH_SIZE)? {
            return Ok(HostCallResult::Accumulation(AccumulationHostCallResult {
                vm_state_change: oob_change(BASE_GAS_USAGE),
                post_contexts: (x, y),
            }));
        }

        let lookup_hash = Hash32::decode(
            &mut memory
                .read_bytes(offset as MemAddress, HASH_SIZE)?
                .as_slice(),
        )?;

        let account = x
            .service_account
            .as_mut()
            .ok_or(HostCallError::InvalidContext)?;

        let vm_state_change = match account.lookups.entry((lookup_hash, lookup_len)) {
            Entry::Vacant(_) => huh_change(BASE_GAS_USAGE),
            Entry::Occupied(mut entry) => {
                let timeslots = entry.get_mut();
                match timeslots.len() {
                    0 => {
                        entry.remove(); // remove the entry from the lookup dictionary
                        account.storage.remove(&lookup_hash); // remove an entry from the storage
                        ok_change(BASE_GAS_USAGE)
                    }
                    1 => {
                        timeslots.push(timeslot);
                        ok_change(BASE_GAS_USAGE)
                    }
                    2 | 3 if timeslots[1].0 < timeslot.0 - PREIMAGE_EXPIRATION_PERIOD => {
                        if timeslots.len() == 2 {
                            entry.remove(); // remove the entry from the lookup dictionary
                            account.storage.remove(&lookup_hash); // remove an entry from the storage
                        } else {
                            timeslots.clear();
                            timeslots.extend(vec![timeslots[2], timeslot]);
                        }
                        ok_change(BASE_GAS_USAGE)
                    }
                    _ => huh_change(BASE_GAS_USAGE),
                }
            }
        };

        Ok(HostCallResult::Accumulation(AccumulationHostCallResult {
            vm_state_change,
            post_contexts: (x, y),
        }))
    }

    //
    // Refine Functions
    //

    pub fn host_historical_lookup(
        _gas: UnsignedGas,
        registers: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        context: &InvocationContext,
        invoker_address: AccountAddress,
        service_accounts: &ServiceAccounts,
        timeslot: Timeslot,
    ) -> Result<HostCallResult, HostCallError> {
        let x = match context {
            InvocationContext::X_R(m) => m.clone(),
            _ => return Err(HostCallError::InvalidContext),
        };

        let [account_address, lookup_hash_offset, buffer_offset, buffer_size, ..] =
            registers.map(|r| r.value);

        let account =
            if account_address == u32::MAX || service_accounts.0.contains_key(&invoker_address) {
                service_accounts.0.get(&invoker_address).unwrap()
            } else if service_accounts.0.contains_key(&account_address) {
                service_accounts.0.get(&account_address).unwrap()
            } else {
                return Ok(HostCallResult::Refinement(RefinementHostCallResult {
                    vm_state_change: none_change(BASE_GAS_USAGE),
                    post_context: x,
                }));
            };

        if !memory.is_range_readable(lookup_hash_offset as MemAddress, HASH_SIZE)? {
            return Ok(HostCallResult::Refinement(RefinementHostCallResult {
                vm_state_change: oob_change(BASE_GAS_USAGE),
                post_context: x,
            }));
        }

        let lookup_hash = Hash32::decode(
            &mut memory
                .read_bytes(lookup_hash_offset as MemAddress, HASH_SIZE)?
                .as_slice(),
        )?;

        if let Some(preimage) = account.lookup_history(timeslot, lookup_hash) {
            let write_data_size = (buffer_size as usize).min(preimage.len());

            if !memory.is_range_writable(buffer_offset, buffer_size as usize)? {
                return Ok(HostCallResult::Refinement(RefinementHostCallResult {
                    vm_state_change: oob_change(BASE_GAS_USAGE),
                    post_context: x,
                }));
            }

            Ok(HostCallResult::Refinement(RefinementHostCallResult {
                vm_state_change: HostCallVMStateChange {
                    gas_usage: BASE_GAS_USAGE,
                    r0_write: Some(preimage.len() as u32),
                    memory_write: (
                        buffer_offset,
                        write_data_size as u32,
                        preimage[..write_data_size].to_vec(),
                    ),
                    ..Default::default()
                },
                post_context: x,
            }))
        } else {
            Ok(HostCallResult::Refinement(RefinementHostCallResult {
                vm_state_change: none_change(BASE_GAS_USAGE),
                post_context: x,
            }))
        }
    }

    pub fn host_import(
        _gas: UnsignedGas,
        registers: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        context: &InvocationContext,
        import_segments: Vec<ExportDataSegment>,
    ) -> Result<HostCallResult, HostCallError> {
        // TODO: the context is not used, there's room for optimization.
        let x = match context {
            InvocationContext::X_R(m) => m.clone(),
            _ => return Err(HostCallError::InvalidContext),
        };

        let [segment_index, offset, segments_len, ..] = registers.map(|r| r.value);

        if segments_len as usize >= DATA_SEGMENTS_SIZE {
            return Ok(HostCallResult::Refinement(RefinementHostCallResult {
                vm_state_change: none_change(BASE_GAS_USAGE),
                post_context: x,
            }));
        }

        let import_segment = import_segments[segment_index as usize];
        let segment_len = segments_len.min(DATA_SEGMENTS_SIZE as u32);

        if !memory.is_range_writable(offset as MemAddress, segment_len as usize)? {
            return Ok(HostCallResult::Refinement(RefinementHostCallResult {
                vm_state_change: oob_change(BASE_GAS_USAGE),
                post_context: x,
            }));
        }

        Ok(HostCallResult::Refinement(RefinementHostCallResult {
            vm_state_change: HostCallVMStateChange {
                gas_usage: BASE_GAS_USAGE,
                r0_write: Some(HostCallResultConstant::OK as u32),
                memory_write: (offset, segment_len, import_segment.to_vec()),
                ..Default::default()
            },
            post_context: x,
        }))
    }

    pub fn host_export(
        _gas: UnsignedGas,
        registers: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        context: &InvocationContext,
        export_segment_offset: usize,
    ) -> Result<HostCallResult, HostCallError> {
        let mut x = match context {
            InvocationContext::X_R(m) => m.clone(),
            _ => return Err(HostCallError::InvalidContext),
        };

        let [offset, size, ..] = registers.map(|r| r.value);

        let size = size.min(DATA_SEGMENTS_SIZE as u32);

        if !memory.is_range_readable(offset as MemAddress, size as usize)? {
            return Ok(HostCallResult::Refinement(RefinementHostCallResult {
                vm_state_change: oob_change(BASE_GAS_USAGE),
                post_context: x,
            }));
        }

        let data = zero_pad(
            memory.read_bytes(offset as MemAddress, size as usize)?,
            DATA_SEGMENTS_SIZE,
        );

        let export_segment_limit = export_segment_offset + data.len();
        // TODO: check the size limit - definition of the constant `W_X` in the GP isn't clear
        if export_segment_limit >= DATA_SEGMENTS_SIZE {
            return Ok(HostCallResult::Refinement(RefinementHostCallResult {
                vm_state_change: full_change(BASE_GAS_USAGE),
                post_context: x,
            }));
        }

        x.exported_segments.extend(vec![data]);

        Ok(HostCallResult::Refinement(RefinementHostCallResult {
            vm_state_change: HostCallVMStateChange {
                gas_usage: BASE_GAS_USAGE,
                r0_write: Some((export_segment_limit) as u32),
                ..Default::default()
            },
            post_context: x,
        }))
    }

    pub fn host_machine(
        _gas: UnsignedGas,
        registers: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        context: &InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        let mut x = match context {
            InvocationContext::X_R(m) => m.clone(),
            _ => return Err(HostCallError::InvalidContext),
        };

        let [program_offset, program_size, initial_pc, ..] = registers.map(|r| r.value);

        if !memory.is_range_readable(program_offset as MemAddress, program_size as usize)? {
            return Ok(HostCallResult::Refinement(RefinementHostCallResult {
                vm_state_change: oob_change(BASE_GAS_USAGE),
                post_context: x,
            }));
        }

        let program = memory.read_bytes(program_offset as MemAddress, program_size as usize)?;
        let inner_vm = InnerPVM::new(program, initial_pc as MemAddress);
        let inner_vm_id = x.add_pvm_instance(inner_vm);

        Ok(HostCallResult::Refinement(RefinementHostCallResult {
            vm_state_change: HostCallVMStateChange {
                gas_usage: BASE_GAS_USAGE,
                r0_write: Some(inner_vm_id as u32),
                ..Default::default()
            },
            post_context: x,
        }))
    }

    pub fn host_peek(
        _gas: UnsignedGas,
        registers: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        _memory: &Memory,
        context: &InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        let x = match context {
            InvocationContext::X_R(m) => m.clone(),
            _ => return Err(HostCallError::InvalidContext),
        };

        let [inner_vm_id, memory_offset, inner_memory_offset, data_len, ..] =
            registers.map(|r| r.value);

        if !x.pvm_instances.contains_key(&(inner_vm_id as usize)) {
            return Ok(HostCallResult::Refinement(RefinementHostCallResult {
                vm_state_change: who_change(BASE_GAS_USAGE),
                post_context: x,
            }));
        }
        let inner_memory = &x.pvm_instances.get(&(inner_vm_id as usize)).unwrap().memory;

        if !inner_memory.is_range_readable(inner_memory_offset as MemAddress, data_len as usize)? {
            return Ok(HostCallResult::Refinement(RefinementHostCallResult {
                vm_state_change: oob_change(BASE_GAS_USAGE),
                post_context: x,
            }));
        }
        let data = inner_memory.read_bytes(inner_memory_offset as MemAddress, data_len as usize)?;

        Ok(HostCallResult::Refinement(RefinementHostCallResult {
            vm_state_change: HostCallVMStateChange {
                gas_usage: BASE_GAS_USAGE,
                r0_write: Some(HostCallResultConstant::OK as u32),
                memory_write: (memory_offset, data_len, data),
                ..Default::default()
            },
            post_context: x,
        }))
    }

    pub fn host_poke(
        _gas: UnsignedGas,
        registers: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        context: &InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        let mut x = match context {
            InvocationContext::X_R(m) => m.clone(),
            _ => return Err(HostCallError::InvalidContext),
        };

        let [inner_vm_id, memory_offset, inner_memory_offset, data_len, ..] =
            registers.map(|r| r.value);

        if !x.pvm_instances.contains_key(&(inner_vm_id as usize)) {
            return Ok(HostCallResult::Refinement(RefinementHostCallResult {
                vm_state_change: who_change(BASE_GAS_USAGE),
                post_context: x,
            }));
        }
        let inner_memory = &mut x
            .pvm_instances
            .get_mut(&(inner_vm_id as usize))
            .unwrap()
            .memory;

        if !memory.is_range_readable(memory_offset as MemAddress, data_len as usize)? {
            return Ok(HostCallResult::Refinement(RefinementHostCallResult {
                vm_state_change: oob_change(BASE_GAS_USAGE),
                post_context: x,
            }));
        }
        let data = memory.read_bytes(memory_offset as MemAddress, data_len as usize)?;

        inner_memory.set_range(inner_memory_offset as usize, &data, AccessType::ReadWrite);
        // TODO: set `CellStatus` for the range

        Ok(HostCallResult::Refinement(RefinementHostCallResult {
            vm_state_change: ok_change(BASE_GAS_USAGE),
            post_context: x,
        }))
    }

    pub fn host_invoke(
        _gas: UnsignedGas,
        registers: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        context: &InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        let mut x = match context {
            InvocationContext::X_R(m) => m.clone(),
            _ => return Err(HostCallError::InvalidContext),
        };

        let [inner_vm_id, memory_offset, ..] = registers.map(|r| r.value);

        if !memory.is_range_writable(memory_offset, 60)? {
            return Ok(HostCallResult::Refinement(RefinementHostCallResult {
                vm_state_change: oob_change(BASE_GAS_USAGE),
                post_context: x,
            }));
        }

        if !x.pvm_instances.contains_key(&(inner_vm_id as usize)) {
            return Ok(HostCallResult::Refinement(RefinementHostCallResult {
                vm_state_change: who_change(BASE_GAS_USAGE),
                post_context: x,
            }));
        }

        let gas = UnsignedGas::decode_fixed(
            &mut &memory.read_bytes(memory_offset as MemAddress, 8)?[..],
            8,
        )?;

        let mut registers = [Register::default(); REGISTERS_COUNT];
        for (i, register) in registers.iter_mut().enumerate() {
            register.value = u32::decode_fixed(
                &mut &memory.read_bytes(
                    (memory_offset as MemAddress)
                        .wrapping_add(8)
                        .wrapping_add(4 * i as MemAddress),
                    4,
                )?[..],
                4,
            )?;
        }

        let inner_vm = x.pvm_instances.get_mut(&(inner_vm_id as usize)).unwrap();

        // Construct a new `VMState` and `Program` for the general invocation function.
        let mut inner_vm_state = VMState {
            registers,
            memory: inner_vm.memory.clone(), // FIXME: remove `clone`
            pc: inner_vm.pc,
            gas_counter: gas,
        };
        let mut inner_vm_program = Program {
            program_code: inner_vm.program_code.clone(), // FIXME: remove `clone`
            ..Default::default()
        };

        let exit_reason = PVMCore::general_invocation(&mut inner_vm_state, &mut inner_vm_program)?;

        // TODO: update the InnerVM pc

        let mut buf = vec![];
        inner_vm_state.gas_counter.encode_to_fixed(&mut buf, 8)?;
        for reg in inner_vm_state.registers {
            reg.value.encode_to_fixed(&mut buf, 4)?;
        }

        match exit_reason {
            ExitReason::HostCall(host_call_type) => {
                inner_vm_state.pc += 1;

                Ok(HostCallResult::Refinement(RefinementHostCallResult {
                    vm_state_change: HostCallVMStateChange {
                        gas_usage: BASE_GAS_USAGE,
                        r0_write: Some(HOST as u32),
                        r1_write: Some(host_call_type.clone() as u32),
                        memory_write: (memory_offset as MemAddress, 60, buf),
                        exit_reason: ExitReason::HostCall(host_call_type), // TODO: check if necessary
                    },
                    post_context: x,
                }))
            }
            ExitReason::PageFault(address) => {
                Ok(HostCallResult::Refinement(RefinementHostCallResult {
                    vm_state_change: HostCallVMStateChange {
                        gas_usage: BASE_GAS_USAGE,
                        r0_write: Some(FAULT as u32),
                        r1_write: Some(address as u32),
                        memory_write: (memory_offset as MemAddress, 60, buf),
                        exit_reason: ExitReason::PageFault(address),
                    },
                    post_context: x,
                }))
            }
            ExitReason::Panic => Ok(HostCallResult::Refinement(RefinementHostCallResult {
                vm_state_change: HostCallVMStateChange {
                    gas_usage: BASE_GAS_USAGE,
                    r0_write: Some(PANIC as u32),
                    r1_write: None,
                    memory_write: (memory_offset as MemAddress, 60, buf),
                    exit_reason: ExitReason::Panic,
                },
                post_context: x,
            })),
            ExitReason::RegularHalt => Ok(HostCallResult::Refinement(RefinementHostCallResult {
                vm_state_change: HostCallVMStateChange {
                    gas_usage: BASE_GAS_USAGE,
                    r0_write: Some(HALT as u32),
                    r1_write: None,
                    memory_write: (memory_offset as MemAddress, 60, buf),
                    exit_reason: ExitReason::RegularHalt,
                },
                post_context: x,
            })),
            _ => Err(HostCallError::InvalidExitReason),
        }
    }

    pub fn host_expunge(
        _gas: UnsignedGas,
        registers: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        _memory: &Memory,
        context: &InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        let mut x = match context {
            InvocationContext::X_R(m) => m.clone(),
            _ => return Err(HostCallError::InvalidContext),
        };

        let [inner_vm_id, ..] = registers.map(|r| r.value);

        if !x.pvm_instances.contains_key(&(inner_vm_id as usize)) {
            return Ok(HostCallResult::Refinement(RefinementHostCallResult {
                vm_state_change: who_change(BASE_GAS_USAGE),
                post_context: x,
            }));
        }

        let final_pc = x.pvm_instances.get(&(inner_vm_id as usize)).unwrap().pc;
        x.remove_pvm_instance(inner_vm_id as usize);

        Ok(HostCallResult::Refinement(RefinementHostCallResult {
            vm_state_change: HostCallVMStateChange {
                gas_usage: BASE_GAS_USAGE,
                r0_write: Some(final_pc as u32),
                ..Default::default()
            },
            post_context: x,
        }))
    }
}
