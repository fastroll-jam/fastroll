use crate::{
    contexts::InvocationContext,
    host_functions::InnerPVMResultConstant::{FAULT, HALT, HOST, PANIC},
    inner_vm::InnerPVM,
    utils::*,
};
use rjam_codec::{JamDecode, JamDecodeFixed, JamEncode, JamEncodeFixed};
use rjam_common::{
    Address, Balance, Hash32, Octets, UnsignedGas, ValidatorKey, CORE_COUNT, HASH32_EMPTY,
    HASH_SIZE, MAX_AUTH_QUEUE_SIZE, TRANSFER_MEMO_SIZE, VALIDATOR_COUNT,
};
use rjam_crypto::{hash, Blake2b256};
use rjam_pvm_core::{
    constants::{
        BASE_GAS_USAGE, DATA_SEGMENTS_SIZE, HOST_CALL_INPUT_REGISTERS_COUNT,
        PREIMAGE_EXPIRATION_PERIOD, REGISTERS_COUNT,
    },
    core::{PVMCore, Program, VMState},
    state::{
        memory::{AccessType, MemAddress, Memory},
        register::Register,
    },
    types::{
        common::{ExitReason, ExportDataSegment},
        error::{
            HostCallError::{
                AccountNotFound, DataSegmentLengthMismatch, InvalidContext, InvalidExitReason,
            },
            PVMError,
        },
    },
};
use rjam_state::{StateManager, StateWriteOp};
use rjam_types::{
    common::transfers::DeferredTransfer,
    state::{
        services::{AccountMetadata, B_S},
        validators::StagingSet,
    },
};

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
    Refinement(RefineHostCallResult),
    Accumulation(AccumulateHostCallResult),
    OnTransfer,
}

pub enum AccumulateResult {
    Unchanged,
    Result(Option<Hash32>), // optional result hash
}

pub struct HostCallVMStateChange {
    pub gas_usage: UnsignedGas,
    pub r7_write: Option<u32>,
    pub r8_write: Option<u32>,
    pub memory_write: (MemAddress, u32, Vec<u8>), // (start_address, data_len, data)
    pub exit_reason: ExitReason,                  // TODO: check if necessary
}

impl Default for HostCallVMStateChange {
    fn default() -> Self {
        Self {
            gas_usage: BASE_GAS_USAGE,
            r7_write: None,
            r8_write: None,
            memory_write: (0, 0, vec![]),
            exit_reason: ExitReason::Continue,
        }
    }
}

//
// Host Call Results
//

// FIXME: replace with `HostCallVMStateChange`
pub struct AccumulateHostCallResult {
    pub vm_state_change: HostCallVMStateChange,
}

pub struct RefineHostCallResult {
    pub vm_state_change: HostCallVMStateChange,
}

//
// Host Functions
//

pub struct HostFunction;

impl HostFunction {
    //
    // General Functions
    //

    pub fn host_gas(gas: UnsignedGas) -> Result<HostCallResult, PVMError> {
        let gas_remaining = gas.wrapping_sub(10);

        Ok(HostCallResult::General(HostCallVMStateChange {
            gas_usage: BASE_GAS_USAGE,
            r7_write: Some((gas_remaining & 0xFFFFFFFF) as u32),
            r8_write: Some((gas_remaining >> 32) as u32),
            ..Default::default()
        }))
    }

    pub fn host_lookup(
        target_address: Address,
        regs: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
    ) -> Result<HostCallResult, PVMError> {
        let account_address_reg = regs[7].value as Address;
        let hash_offset = regs[8].value as MemAddress;
        let buffer_offset = regs[9].value as MemAddress;
        let buffer_size = regs[10].value as usize;

        let account_address =
            if account_address_reg == u32::MAX || account_address_reg == target_address {
                target_address
            } else {
                account_address_reg
            };

        if !memory.is_range_readable(hash_offset, 32).unwrap() {
            return Ok(HostCallResult::General(oob_change(BASE_GAS_USAGE)));
        }

        let hash = hash::<Blake2b256>(&memory.read_bytes(hash_offset, 32)?)?;
        let preimage_entry = state_manager.get_account_preimages_entry(account_address, &hash)?;

        match preimage_entry {
            Some(entry) => {
                let write_data_size = buffer_size.min(entry.value.len());

                if !memory.is_range_writable(buffer_offset, buffer_size)? {
                    return Ok(HostCallResult::General(oob_change(BASE_GAS_USAGE)));
                }

                Ok(HostCallResult::General(HostCallVMStateChange {
                    gas_usage: BASE_GAS_USAGE,
                    r7_write: Some(entry.value.len() as u32),
                    memory_write: (
                        buffer_offset,
                        write_data_size as u32,
                        entry.value[..write_data_size].to_vec(),
                    ),
                    ..Default::default()
                }))
            }
            None => Ok(HostCallResult::General(none_change(BASE_GAS_USAGE))),
        }
    }

    pub fn host_read(
        target_address: Address,
        regs: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
    ) -> Result<HostCallResult, PVMError> {
        let account_address_reg = regs[7].value as Address;
        let key_offset = regs[8].value as MemAddress;
        let key_size = regs[9].value as usize;
        let buffer_offset = regs[10].value as MemAddress;
        let buffer_size = regs[11].value as usize;

        let account_address =
            if account_address_reg == u32::MAX || account_address_reg == target_address {
                target_address
            } else {
                account_address_reg
            };

        if !memory.is_range_readable(key_offset, key_size)? {
            return Ok(HostCallResult::General(oob_change(BASE_GAS_USAGE)));
        }

        let mut key = vec![];
        key.extend(target_address.encode_fixed(4)?);
        key.extend(memory.read_bytes(key_offset, key_size)?);
        let storage_key = hash::<Blake2b256>(&key)?;

        let storage_entry =
            state_manager.get_account_storage_entry(account_address, &storage_key)?;

        if let Some(entry) = storage_entry {
            let write_data_size = buffer_size.min(entry.value.len());

            if !memory.is_range_writable(buffer_offset, buffer_size)? {
                return Ok(HostCallResult::General(oob_change(BASE_GAS_USAGE)));
            }

            Ok(HostCallResult::General(HostCallVMStateChange {
                gas_usage: BASE_GAS_USAGE,
                r7_write: Some(entry.value.len() as u32),
                memory_write: (
                    buffer_offset,
                    write_data_size as u32,
                    entry.value[..write_data_size].to_vec(),
                ),
                ..Default::default()
            }))
        } else {
            Ok(HostCallResult::General(none_change(BASE_GAS_USAGE)))
        }
    }

    // TODO: check if `target_address` is provided as an arg - not specified in the GP
    pub fn host_write(
        target_address: Address,
        regs: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
    ) -> Result<HostCallResult, PVMError> {
        let key_offset = regs[7].value as MemAddress;
        let key_size = regs[8].value as usize;
        let value_offset = regs[9].value as MemAddress;
        let value_size = regs[10].value as usize;

        if !memory.is_range_readable(key_offset, key_size)?
            || !memory.is_range_readable(value_offset, value_size)?
        {
            return Ok(HostCallResult::General(oob_change(BASE_GAS_USAGE)));
        }

        let mut key = vec![];
        key.extend(target_address.encode_fixed(4)?);
        key.extend(memory.read_bytes(key_offset, key_size)?);
        let storage_key = hash::<Blake2b256>(&key)?;

        let storage_entry =
            state_manager.get_account_storage_entry(target_address, &storage_key)?;

        let previous_size = if let Some(entry) = storage_entry {
            entry.value.len()
        } else {
            HostCallResultConstant::NONE as usize
        };

        if value_size == 0 {
            state_manager.with_mut_account_storage_entry(
                StateWriteOp::Remove,
                target_address,
                &storage_key,
                |_| {},
            )?;
        } else {
            let data = memory.read_bytes(value_offset, value_size)?;

            if previous_size == HostCallResultConstant::NONE as usize {
                state_manager.with_mut_account_storage_entry(
                    StateWriteOp::Add,
                    target_address,
                    &storage_key,
                    |entry| {
                        entry.value = Octets::from_vec(data);
                    },
                )?;
            } else {
                state_manager.with_mut_account_storage_entry(
                    StateWriteOp::Update,
                    target_address,
                    &storage_key,
                    |entry| {
                        entry.value = Octets::from_vec(data);
                    },
                )?;
            }
        }

        let target_account_metadata = state_manager
            .get_account_metadata(target_address)?
            .ok_or(PVMError::HostCallError(AccountNotFound))?;

        if target_account_metadata.get_threshold_balance()
            > target_account_metadata.account_info.balance
        {
            Ok(HostCallResult::General(full_change(BASE_GAS_USAGE)))
        } else {
            Ok(HostCallResult::General(HostCallVMStateChange {
                gas_usage: BASE_GAS_USAGE,
                r7_write: Some(previous_size as u32),
                ..Default::default()
            }))
        }
    }

    pub fn host_info(
        target_address: Address,
        regs: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
    ) -> Result<HostCallResult, PVMError> {
        let account_address_reg = regs[7].value as Address;
        let buffer_offset = regs[8].value as MemAddress;

        let account_address =
            if account_address_reg == u32::MAX || account_address_reg == target_address {
                target_address
            } else {
                account_address_reg
            };

        let account = match state_manager.get_account_metadata(account_address)? {
            Some(metadata) => metadata,
            None => return Ok(HostCallResult::General(none_change(BASE_GAS_USAGE))),
        };

        // Encode account fields with JAM Codec
        let mut info = vec![];
        account.account_info.code_hash.encode_to(&mut info)?; // c
        account.account_info.balance.encode_to(&mut info)?; // b
        account.get_threshold_balance().encode_to(&mut info)?; // t
        account
            .account_info
            .gas_limit_accumulate
            .encode_to(&mut info)?; // g
        account
            .account_info
            .gas_limit_on_transfer
            .encode_to(&mut info)?; // m
        account.total_octets_footprint.encode_to(&mut info)?; // l
        account.item_counts_footprint.encode_to(&mut info)?; // i

        if !memory.is_range_writable(buffer_offset, info.len())? {
            return Ok(HostCallResult::General(oob_change(BASE_GAS_USAGE)));
        }

        Ok(HostCallResult::General(HostCallVMStateChange {
            gas_usage: BASE_GAS_USAGE,
            r7_write: Some(HostCallResultConstant::OK as u32),
            memory_write: (buffer_offset, info.len() as u32, info.clone()),
            ..Default::default()
        }))
    }

    //
    // Accumulate Functions
    //

    // Accumulation host functions mutate: gas, regs, contexts
    pub fn host_empower(
        regs: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        state_manager: &StateManager,
    ) -> Result<HostCallResult, PVMError> {
        let manager = regs[7].value as Address;
        let assign = regs[8].value as Address;
        let designate = regs[9].value as Address;

        state_manager.with_mut_privileged_services(
            StateWriteOp::Update,
            |privileged_services| {
                privileged_services.manager_service = manager;
                privileged_services.assign_service = assign;
                privileged_services.designate_service = designate;
            },
        )?;

        Ok(HostCallResult::Accumulation(AccumulateHostCallResult {
            vm_state_change: HostCallVMStateChange::default(),
        }))
    }

    #[allow(clippy::needless_range_loop)]
    pub fn host_assign(
        regs: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
    ) -> Result<HostCallResult, PVMError> {
        let core_index = regs[7].value as usize;
        let offset = regs[8].value as MemAddress;

        if !memory.is_range_readable(offset, HASH_SIZE * MAX_AUTH_QUEUE_SIZE)? {
            return Ok(HostCallResult::Accumulation(AccumulateHostCallResult {
                vm_state_change: oob_change(BASE_GAS_USAGE),
            }));
        }

        if core_index >= CORE_COUNT {
            return Ok(HostCallResult::Accumulation(AccumulateHostCallResult {
                vm_state_change: core_change(BASE_GAS_USAGE),
            }));
        }

        let mut queue_assignment = [HASH32_EMPTY; MAX_AUTH_QUEUE_SIZE];
        for i in 0..MAX_AUTH_QUEUE_SIZE {
            if let Ok(slice) = memory.read_bytes(offset + (HASH_SIZE * i) as MemAddress, HASH_SIZE)
            {
                queue_assignment[i] = Hash32::decode(&mut &slice[..])?;
            }
        }

        state_manager.with_mut_auth_queue(StateWriteOp::Update, |auth_queue| {
            auth_queue.0[core_index] = queue_assignment;
        })?;

        Ok(HostCallResult::Accumulation(AccumulateHostCallResult {
            vm_state_change: ok_change(BASE_GAS_USAGE),
        }))
    }

    pub fn host_designate(
        regs: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
    ) -> Result<HostCallResult, PVMError> {
        let offset = regs[7].value as MemAddress;

        // FIXME: check the public key blob length - the PVM spec describes as 176 but public key blob is 336 bytes in general
        const PUBLIC_KEY_SIZE: usize = 336;
        if !memory.is_range_readable(offset, PUBLIC_KEY_SIZE * VALIDATOR_COUNT)? {
            return Ok(HostCallResult::Accumulation(AccumulateHostCallResult {
                vm_state_change: oob_change(BASE_GAS_USAGE),
            }));
        }

        let mut new_staging_set = StagingSet::default();
        for i in 0..VALIDATOR_COUNT {
            if let Ok(slice) = memory.read_bytes(
                offset + (PUBLIC_KEY_SIZE * i) as MemAddress,
                PUBLIC_KEY_SIZE,
            ) {
                let validator_key = ValidatorKey::decode(&mut &slice[..])?;
                new_staging_set.0[i] = validator_key;
            }
        }

        state_manager.with_mut_staging_set(StateWriteOp::Update, |staging_set| {
            *staging_set = new_staging_set;
        })?;

        Ok(HostCallResult::Accumulation(AccumulateHostCallResult {
            vm_state_change: ok_change(BASE_GAS_USAGE),
        }))
    }

    pub fn host_checkpoint(
        gas: UnsignedGas,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let acc_pair = match context.as_accumulate_context_mut() {
            Some(pair) => pair,
            None => return Err(PVMError::HostCallError(InvalidContext)),
        };

        let x_clone = acc_pair.get_x().clone();
        *acc_pair.get_mut_y() = x_clone; // assign the cloned `x` context to the `y` context

        let post_gas = gas.saturating_sub(BASE_GAS_USAGE); // TODO: gas management

        Ok(HostCallResult::Accumulation(AccumulateHostCallResult {
            vm_state_change: HostCallVMStateChange {
                gas_usage: BASE_GAS_USAGE,
                r7_write: Some(post_gas as u32),
                r8_write: Some((post_gas >> 32) as u32),
                ..Default::default()
            },
        }))
    }
    pub fn host_new(
        creator_address: Address,
        regs: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let acc_pair = match context.as_accumulate_context_mut() {
            Some(pair) => pair,
            None => return Err(PVMError::HostCallError(InvalidContext)),
        };
        let x = acc_pair.get_mut_x();

        let offset = regs[7].value as MemAddress;
        let lookup_len = regs[8].value;
        let gas_limit_g_low = regs[9].value;
        let gas_limit_g_high = regs[10].value;
        let gas_limit_m_low = regs[11].value;
        let gas_limit_m_high = regs[12].value;

        if !memory.is_range_readable(offset, HASH_SIZE)? {
            return Ok(HostCallResult::Accumulation(AccumulateHostCallResult {
                vm_state_change: oob_change(BASE_GAS_USAGE),
            }));
        }

        let code_hash = Hash32::decode(&mut memory.read_bytes(offset, HASH_SIZE)?.as_slice())?;
        let gas_limit_g = ((gas_limit_g_high as u64) << 32 | gas_limit_g_low as u64) as UnsignedGas;
        let gas_limit_m = ((gas_limit_m_high as u64) << 32 | gas_limit_m_low as u64) as UnsignedGas;

        let new_threshold_balance = AccountMetadata::get_initial_threshold_balance();

        // Check the creator account's balance and subtract by the initial threshold balance
        // to be transferred to the new account.
        let creator_account_account_metadata = state_manager
            .get_account_metadata(creator_address)?
            .unwrap();
        let creator_account_threshold_balance =
            creator_account_account_metadata.get_threshold_balance();
        let creator_subtracted_balance = creator_account_account_metadata
            .account_info
            .balance
            .saturating_sub(new_threshold_balance);

        if creator_subtracted_balance < creator_account_threshold_balance {
            return Ok(HostCallResult::Accumulation(AccumulateHostCallResult {
                vm_state_change: cash_change(BASE_GAS_USAGE),
            }));
        }

        state_manager.with_mut_account_metadata(
            StateWriteOp::Update,
            creator_address,
            |account_metadata| account_metadata.account_info.balance = creator_subtracted_balance,
        )?;

        // Add a new account.
        // State of new accounts is also maintained in the state cache, marked as `Dirty(StateWriteOp::Add)`
        let new_account_address = x.get_next_new_account_address();
        state_manager.with_mut_account_metadata(
            StateWriteOp::Add,
            new_account_address,
            |account_metadata| {
                account_metadata.account_info.code_hash = code_hash;
                account_metadata.account_info.balance = new_threshold_balance;
                account_metadata.account_info.gas_limit_accumulate = gas_limit_g;
                account_metadata.account_info.gas_limit_on_transfer = gas_limit_m;
            },
        )?;

        // Add an empty lookups storage entry to the new account.
        state_manager.with_mut_account_lookups_entry(
            StateWriteOp::Add,
            new_account_address,
            (&code_hash, lookup_len),
            |lookup_entry| {
                lookup_entry.value = vec![];
            },
        )?;

        x.rotate_new_account_address(state_manager)?;

        Ok(HostCallResult::Accumulation(AccumulateHostCallResult {
            vm_state_change: HostCallVMStateChange {
                gas_usage: BASE_GAS_USAGE,
                r7_write: Some(new_account_address),
                ..Default::default()
            },
        }))
    }

    pub fn host_upgrade(
        target_address: Address,
        regs: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
    ) -> Result<HostCallResult, PVMError> {
        let offset = regs[7].value as MemAddress;
        let gas_limit_g_low = regs[8].value;
        let gas_limit_g_high = regs[9].value;
        let gas_limit_m_low = regs[10].value;
        let gas_limit_m_high = regs[11].value;

        if !memory.is_range_readable(offset, HASH_SIZE)? {
            return Ok(HostCallResult::Accumulation(AccumulateHostCallResult {
                vm_state_change: oob_change(BASE_GAS_USAGE),
            }));
        }

        let code_hash = Hash32::decode(&mut memory.read_bytes(offset, HASH_SIZE)?.as_slice())?;
        let gas_limit_g = ((gas_limit_g_high as u64) << 32 | gas_limit_g_low as u64) as UnsignedGas;
        let gas_limit_m = ((gas_limit_m_high as u64) << 32 | gas_limit_m_low as u64) as UnsignedGas;

        state_manager.with_mut_account_metadata(
            StateWriteOp::Update,
            target_address,
            |account_metadata| {
                account_metadata.account_info.code_hash = code_hash;
                account_metadata.account_info.gas_limit_accumulate = gas_limit_g;
                account_metadata.account_info.gas_limit_on_transfer = gas_limit_m;
            },
        )?;

        Ok(HostCallResult::Accumulation(AccumulateHostCallResult {
            vm_state_change: ok_change(BASE_GAS_USAGE),
        }))
    }

    pub fn host_transfer(
        sender_address: Address,
        gas: UnsignedGas,
        regs: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let acc_pair = match context.as_accumulate_context_mut() {
            Some(pair) => pair,
            None => return Err(PVMError::HostCallError(InvalidContext)),
        };
        let x = acc_pair.get_mut_x();

        let dest = regs[7].value as Address;
        let amount_low = regs[8].value;
        let amount_high = regs[9].value;
        let gas_limit_low = regs[10].value;
        let gas_limit_high = regs[11].value;
        let offset = regs[12].value as MemAddress;

        let amount = ((amount_high as u64) << 32 | amount_low as u64) as Balance;
        let gas_limit = ((gas_limit_high as u64) << 32 | gas_limit_low as u64) as UnsignedGas;

        if !memory.is_range_readable(offset, TRANSFER_MEMO_SIZE)? {
            return Ok(HostCallResult::Accumulation(AccumulateHostCallResult {
                vm_state_change: oob_change(BASE_GAS_USAGE),
            }));
        }

        let transfer_memo = <[u8; TRANSFER_MEMO_SIZE]>::decode(
            &mut &memory.read_bytes(offset, TRANSFER_MEMO_SIZE)?[..],
        )?;

        let transfer = DeferredTransfer {
            from: sender_address,
            to: dest,
            amount,
            memo: transfer_memo,
            gas_limit,
        };

        let sender_account_metadata = state_manager.get_account_metadata(sender_address)?.unwrap();

        let sender_post_balance = sender_account_metadata.account_info.balance - amount;

        // State cache lookup also detects new accounts added during accumulation
        if !state_manager.account_exists(dest)? {
            return Ok(HostCallResult::Accumulation(AccumulateHostCallResult {
                vm_state_change: who_change(BASE_GAS_USAGE + amount),
            }));
        }

        let dest_gas_limit_m = state_manager
            .get_account_metadata(dest)?
            .unwrap()
            .account_info
            .gas_limit_on_transfer;

        if gas_limit < dest_gas_limit_m {
            return Ok(HostCallResult::Accumulation(AccumulateHostCallResult {
                vm_state_change: low_change(BASE_GAS_USAGE + amount),
            }));
        }

        if gas < gas_limit {
            return Ok(HostCallResult::Accumulation(AccumulateHostCallResult {
                vm_state_change: high_change(BASE_GAS_USAGE + amount),
            }));
        }

        if sender_post_balance < sender_account_metadata.get_threshold_balance() {
            return Ok(HostCallResult::Accumulation(AccumulateHostCallResult {
                vm_state_change: cash_change(BASE_GAS_USAGE + amount),
            }));
        }

        x.add_to_deferred_transfers(transfer);
        state_manager.with_mut_account_metadata(
            StateWriteOp::Update,
            sender_address,
            |sender_account_metadata| {
                sender_account_metadata.account_info.balance = sender_post_balance;
            },
        )?;

        Ok(HostCallResult::Accumulation(AccumulateHostCallResult {
            vm_state_change: oob_change(BASE_GAS_USAGE + amount),
        }))
    }

    pub fn host_quit(
        target_address: Address,
        gas: UnsignedGas,
        regs: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let acc_pair = match context.as_accumulate_context_mut() {
            Some(pair) => pair,
            None => return Err(PVMError::HostCallError(InvalidContext)),
        };
        let x = acc_pair.get_mut_x();

        let dest = regs[7].value as Address;
        let offset = regs[8].value as MemAddress;

        let context_account = state_manager.get_account_metadata(target_address)?.unwrap();

        let amount = context_account
            .account_info
            .balance
            .wrapping_sub(context_account.get_threshold_balance())
            + B_S;

        if dest == u32::MAX || dest == target_address {
            return Ok(HostCallResult::VMHalt(ok_change(BASE_GAS_USAGE))); // TODO: check gas usage from the GP
        }

        if !memory.is_range_readable(offset, TRANSFER_MEMO_SIZE)? {
            return Ok(HostCallResult::Accumulation(AccumulateHostCallResult {
                vm_state_change: oob_change(BASE_GAS_USAGE),
            }));
        }

        let transfer_memo = <[u8; TRANSFER_MEMO_SIZE]>::decode(
            &mut &memory.read_bytes(offset, TRANSFER_MEMO_SIZE)?[..],
        )?;

        let transfer = DeferredTransfer {
            from: target_address,
            to: dest,
            amount,
            memo: transfer_memo,
            gas_limit: gas,
        };

        // State cache lookup also detects new accounts added during accumulation
        if !state_manager.account_exists(dest)? {
            return Ok(HostCallResult::Accumulation(AccumulateHostCallResult {
                vm_state_change: who_change(BASE_GAS_USAGE + amount),
            }));
        }

        let dest_gas_limit_m = state_manager
            .get_account_metadata(dest)?
            .unwrap()
            .account_info
            .gas_limit_on_transfer;

        if gas < dest_gas_limit_m {
            return Ok(HostCallResult::Accumulation(AccumulateHostCallResult {
                vm_state_change: low_change(BASE_GAS_USAGE + amount),
            }));
        }
        x.add_to_deferred_transfers(transfer);

        Ok(HostCallResult::VMHalt(ok_change(BASE_GAS_USAGE)))
    }

    pub fn host_solicit(
        target_address: Address,
        regs: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
    ) -> Result<HostCallResult, PVMError> {
        let offset = regs[7].value as MemAddress;
        let lookup_len = regs[8].value;

        if !memory.is_range_readable(offset, HASH_SIZE)? {
            return Ok(HostCallResult::Accumulation(AccumulateHostCallResult {
                vm_state_change: oob_change(BASE_GAS_USAGE),
            }));
        }

        let lookup_hash = Hash32::decode(&mut memory.read_bytes(offset, HASH_SIZE)?.as_slice())?;

        let account = state_manager.get_account_metadata(target_address)?.unwrap();
        if account.account_info.balance < account.get_threshold_balance() {
            return Ok(HostCallResult::Accumulation(AccumulateHostCallResult {
                vm_state_change: full_change(BASE_GAS_USAGE),
            }));
        }

        // Insert current timeslot if the entry exists.
        // If the key doesn't exist, insert a new empty Vec<Timeslot> with the key.
        // If the entry's timeslot vector length is not equal to 2, return with result constant `HUH`.
        let current_timeslot = state_manager.get_timeslot()?;
        let lookups_key = (&lookup_hash, lookup_len);
        let account_lookups_entry =
            state_manager.get_account_lookups_entry(target_address, lookups_key)?;
        match account_lookups_entry {
            Some(entry) => {
                // Add current timeslot.
                if entry.value.len() == 2 {
                    state_manager.with_mut_account_lookups_entry(
                        StateWriteOp::Update,
                        target_address,
                        lookups_key,
                        |entry| {
                            entry.value.push(current_timeslot);
                        },
                    )?;
                } else {
                    return Ok(HostCallResult::Accumulation(AccumulateHostCallResult {
                        vm_state_change: huh_change(BASE_GAS_USAGE),
                    }));
                }
            }
            None => {
                // Add a new entry.
                state_manager.with_mut_account_lookups_entry(
                    StateWriteOp::Add,
                    target_address,
                    (&lookup_hash, lookup_len),
                    |entry| entry.value = vec![],
                )?;
            }
        }

        Ok(HostCallResult::Accumulation(AccumulateHostCallResult {
            vm_state_change: ok_change(BASE_GAS_USAGE),
        }))
    }

    pub fn host_forget(
        target_address: Address,
        regs: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
    ) -> Result<HostCallResult, PVMError> {
        let offset = regs[7].value as MemAddress;
        let lookup_len = regs[8].value;

        if !memory.is_range_readable(offset, HASH_SIZE)? {
            return Ok(HostCallResult::Accumulation(AccumulateHostCallResult {
                vm_state_change: oob_change(BASE_GAS_USAGE),
            }));
        }

        let lookup_hash = Hash32::decode(&mut memory.read_bytes(offset, HASH_SIZE)?.as_slice())?;

        let current_timeslot = state_manager.get_timeslot()?;
        let lookups_key = (&lookup_hash, lookup_len);
        let account_lookups_entry =
            state_manager.get_account_lookups_entry(target_address, lookups_key)?;

        let vm_state_change = match account_lookups_entry {
            None => huh_change(BASE_GAS_USAGE),
            Some(entry) => {
                let lookups_timeslots = entry.value;
                // Length of the timeslots vector

                match lookups_timeslots.len() {
                    0 => {
                        // Remove the lookups table entry
                        state_manager.with_mut_account_lookups_entry(
                            StateWriteOp::Remove,
                            target_address,
                            lookups_key,
                            |_| {},
                        )?;
                        // Remove the preimages table entry
                        state_manager.with_mut_account_preimages_entry(
                            StateWriteOp::Remove,
                            target_address,
                            &lookup_hash,
                            |_| {},
                        )?;
                        ok_change(BASE_GAS_USAGE)
                    }
                    1 => {
                        state_manager.with_mut_account_lookups_entry(
                            StateWriteOp::Update,
                            target_address,
                            lookups_key,
                            |entry_mut| {
                                entry_mut.value.push(current_timeslot);
                            },
                        )?;
                        ok_change(BASE_GAS_USAGE)
                    }
                    2 | 3
                        if lookups_timeslots[1].0
                            < current_timeslot.0 - PREIMAGE_EXPIRATION_PERIOD =>
                    {
                        if lookups_timeslots.len() == 2 {
                            // Remove the lookups table entry
                            state_manager.with_mut_account_lookups_entry(
                                StateWriteOp::Remove,
                                target_address,
                                lookups_key,
                                |_| {},
                            )?;
                            // Remove the preimages table entry
                            state_manager.with_mut_account_preimages_entry(
                                StateWriteOp::Remove,
                                target_address,
                                &lookup_hash,
                                |_| {},
                            )?;
                        } else {
                            state_manager.with_mut_account_lookups_entry(
                                StateWriteOp::Update,
                                target_address,
                                lookups_key,
                                |entry_mut| {
                                    entry_mut.value.clear();
                                    entry_mut
                                        .value
                                        .extend(vec![lookups_timeslots[2], current_timeslot]);
                                },
                            )?
                        }
                        ok_change(BASE_GAS_USAGE)
                    }
                    _ => huh_change(BASE_GAS_USAGE),
                }
            }
        };

        Ok(HostCallResult::Accumulation(AccumulateHostCallResult {
            vm_state_change,
        }))
    }

    //
    // Refine Functions
    //

    pub fn host_historical_lookup(
        target_address: Address,
        regs: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
    ) -> Result<HostCallResult, PVMError> {
        // FIXME: timeslot should come from the refinement context, not current timeslot
        let timeslot = state_manager.get_timeslot()?;

        let account_address_reg = regs[7].value as Address;
        let lookup_hash_offset = regs[8].value as MemAddress;
        let buffer_offset = regs[9].value as MemAddress;
        let buffer_size = regs[10].value as usize;

        let account_address =
            if account_address_reg == u32::MAX || state_manager.account_exists(target_address)? {
                target_address
            } else if state_manager.account_exists(account_address_reg)? {
                account_address_reg
            } else {
                return Ok(HostCallResult::Refinement(RefineHostCallResult {
                    vm_state_change: none_change(BASE_GAS_USAGE),
                }));
            };

        if !memory.is_range_readable(lookup_hash_offset, HASH_SIZE)? {
            return Ok(HostCallResult::Refinement(RefineHostCallResult {
                vm_state_change: oob_change(BASE_GAS_USAGE),
            }));
        }

        let lookup_hash =
            Hash32::decode(&mut memory.read_bytes(lookup_hash_offset, HASH_SIZE)?.as_slice())?;

        let preimage = state_manager.lookup_preimage(account_address, &timeslot, &lookup_hash)?;

        if let Some(preimage) = preimage {
            let write_data_size = buffer_size.min(preimage.len());

            if !memory.is_range_writable(buffer_offset, buffer_size)? {
                return Ok(HostCallResult::Refinement(RefineHostCallResult {
                    vm_state_change: oob_change(BASE_GAS_USAGE),
                }));
            }

            Ok(HostCallResult::Refinement(RefineHostCallResult {
                vm_state_change: HostCallVMStateChange {
                    gas_usage: BASE_GAS_USAGE,
                    r7_write: Some(preimage.len() as u32),
                    memory_write: (
                        buffer_offset,
                        write_data_size as u32,
                        preimage[..write_data_size].to_vec(),
                    ),
                    ..Default::default()
                },
            }))
        } else {
            Ok(HostCallResult::Refinement(RefineHostCallResult {
                vm_state_change: none_change(BASE_GAS_USAGE),
            }))
        }
    }

    pub fn host_import(
        regs: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        import_segments: Vec<ExportDataSegment>,
    ) -> Result<HostCallResult, PVMError> {
        let segment_index = regs[7].value as usize;
        let offset = regs[8].value as MemAddress;
        let segments_len = regs[9].value as usize;

        if segments_len >= DATA_SEGMENTS_SIZE {
            return Ok(HostCallResult::Refinement(RefineHostCallResult {
                vm_state_change: none_change(BASE_GAS_USAGE),
            }));
        }

        let import_segment = import_segments[segment_index];
        let segment_len = segments_len.min(DATA_SEGMENTS_SIZE);

        if !memory.is_range_writable(offset, segment_len)? {
            return Ok(HostCallResult::Refinement(RefineHostCallResult {
                vm_state_change: oob_change(BASE_GAS_USAGE),
            }));
        }

        Ok(HostCallResult::Refinement(RefineHostCallResult {
            vm_state_change: HostCallVMStateChange {
                gas_usage: BASE_GAS_USAGE,
                r7_write: Some(HostCallResultConstant::OK as u32),
                memory_write: (offset, segment_len as u32, import_segment.to_vec()),
                ..Default::default()
            },
        }))
    }

    pub fn host_export(
        regs: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        context: &mut InvocationContext,
        export_segment_offset: usize,
    ) -> Result<HostCallResult, PVMError> {
        let x = match context.as_refine_context_mut() {
            Some(ctx) => ctx,
            None => return Err(PVMError::HostCallError(InvalidContext)),
        };

        let offset = regs[7].value as MemAddress;
        let size = regs[8].value as usize;

        let size = size.min(DATA_SEGMENTS_SIZE);

        if !memory.is_range_readable(offset, size)? {
            return Ok(HostCallResult::Refinement(RefineHostCallResult {
                vm_state_change: oob_change(BASE_GAS_USAGE),
            }));
        }

        let data: ExportDataSegment =
            zero_pad(memory.read_bytes(offset, size)?, DATA_SEGMENTS_SIZE)
                .try_into()
                .map_err(|v: Vec<u8>| {
                    PVMError::HostCallError(DataSegmentLengthMismatch {
                        expected: DATA_SEGMENTS_SIZE,
                        actual: v.len(),
                    })
                })?;

        let export_segment_limit = export_segment_offset + data.len();
        // TODO: check the size limit - definition of the constant `W_X` in the GP isn't clear
        if export_segment_limit >= DATA_SEGMENTS_SIZE {
            return Ok(HostCallResult::Refinement(RefineHostCallResult {
                vm_state_change: full_change(BASE_GAS_USAGE),
            }));
        }

        x.export_segments.extend(vec![data]);

        Ok(HostCallResult::Refinement(RefineHostCallResult {
            vm_state_change: HostCallVMStateChange {
                gas_usage: BASE_GAS_USAGE,
                r7_write: Some((export_segment_limit) as u32),
                ..Default::default()
            },
        }))
    }

    pub fn host_machine(
        regs: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let x = match context.as_refine_context_mut() {
            Some(ctx) => ctx,
            None => return Err(PVMError::HostCallError(InvalidContext)),
        };

        let program_offset = regs[7].value as MemAddress;
        let program_size = regs[8].value as usize;
        let initial_pc = regs[9].value as MemAddress;

        if !memory.is_range_readable(program_offset, program_size)? {
            return Ok(HostCallResult::Refinement(RefineHostCallResult {
                vm_state_change: oob_change(BASE_GAS_USAGE),
            }));
        }

        let program = memory.read_bytes(program_offset, program_size)?;
        let inner_vm = InnerPVM::new(program, initial_pc);
        let inner_vm_id = x.add_pvm_instance(inner_vm);

        Ok(HostCallResult::Refinement(RefineHostCallResult {
            vm_state_change: HostCallVMStateChange {
                gas_usage: BASE_GAS_USAGE,
                r7_write: Some(inner_vm_id as u32),
                ..Default::default()
            },
        }))
    }

    pub fn host_peek(
        regs: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let x = match context.as_refine_context_mut() {
            Some(ctx) => ctx,
            None => return Err(PVMError::HostCallError(InvalidContext)),
        };

        let inner_vm_id = regs[7].value as usize;
        let memory_offset = regs[8].value as MemAddress;
        let inner_memory_offset = regs[9].value as MemAddress;
        let data_len = regs[10].value as usize;

        if !x.pvm_instances.contains_key(&inner_vm_id) {
            return Ok(HostCallResult::Refinement(RefineHostCallResult {
                vm_state_change: who_change(BASE_GAS_USAGE),
            }));
        }
        let inner_memory = &x.pvm_instances.get(&inner_vm_id).unwrap().memory;

        if !inner_memory.is_range_readable(inner_memory_offset, data_len)? {
            return Ok(HostCallResult::Refinement(RefineHostCallResult {
                vm_state_change: oob_change(BASE_GAS_USAGE),
            }));
        }
        let data = inner_memory.read_bytes(inner_memory_offset, data_len)?;

        Ok(HostCallResult::Refinement(RefineHostCallResult {
            vm_state_change: HostCallVMStateChange {
                gas_usage: BASE_GAS_USAGE,
                r7_write: Some(HostCallResultConstant::OK as u32),
                memory_write: (memory_offset, data_len as u32, data),
                ..Default::default()
            },
        }))
    }

    pub fn host_poke(
        regs: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let x = match context.as_refine_context_mut() {
            Some(ctx) => ctx,
            None => return Err(PVMError::HostCallError(InvalidContext)),
        };

        let inner_vm_id = regs[7].value as usize;
        let memory_offset = regs[8].value as MemAddress;
        let inner_memory_offset = regs[9].value as MemAddress;
        let data_len = regs[10].value as usize;

        if !x.pvm_instances.contains_key(&inner_vm_id) {
            return Ok(HostCallResult::Refinement(RefineHostCallResult {
                vm_state_change: who_change(BASE_GAS_USAGE),
            }));
        }
        let inner_memory = &mut x.pvm_instances.get_mut(&inner_vm_id).unwrap().memory;

        if !memory.is_range_readable(memory_offset, data_len)? {
            return Ok(HostCallResult::Refinement(RefineHostCallResult {
                vm_state_change: oob_change(BASE_GAS_USAGE),
            }));
        }
        let data = memory.read_bytes(memory_offset, data_len)?;

        inner_memory.set_range(inner_memory_offset as usize, &data, AccessType::ReadWrite);
        // TODO: set `CellStatus` for the range

        Ok(HostCallResult::Refinement(RefineHostCallResult {
            vm_state_change: ok_change(BASE_GAS_USAGE),
        }))
    }

    pub fn host_invoke(
        regs: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        memory: &Memory,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let x = match context.as_refine_context_mut() {
            Some(ctx) => ctx,
            None => return Err(PVMError::HostCallError(InvalidContext)),
        };

        let inner_vm_id = regs[7].value as usize;
        let memory_offset = regs[8].value as MemAddress;

        if !memory.is_range_writable(memory_offset, 60)? {
            return Ok(HostCallResult::Refinement(RefineHostCallResult {
                vm_state_change: oob_change(BASE_GAS_USAGE),
            }));
        }

        if !x.pvm_instances.contains_key(&inner_vm_id) {
            return Ok(HostCallResult::Refinement(RefineHostCallResult {
                vm_state_change: who_change(BASE_GAS_USAGE),
            }));
        }

        let gas = UnsignedGas::decode_fixed(&mut &memory.read_bytes(memory_offset, 8)?[..], 8)?;

        let mut regs = [Register::default(); REGISTERS_COUNT];
        for (i, register) in regs.iter_mut().enumerate() {
            register.value = u32::decode_fixed(
                &mut &memory.read_bytes(
                    memory_offset
                        .wrapping_add(8)
                        .wrapping_add(4 * i as MemAddress),
                    4,
                )?[..],
                4,
            )?;
        }

        let inner_vm = x.pvm_instances.get_mut(&inner_vm_id).unwrap();

        // Construct a new `VMState` and `Program` for the general invocation function.
        let mut inner_vm_state = VMState {
            registers: regs,
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

                Ok(HostCallResult::Refinement(RefineHostCallResult {
                    vm_state_change: HostCallVMStateChange {
                        gas_usage: BASE_GAS_USAGE,
                        r7_write: Some(HOST as u32),
                        r8_write: Some(host_call_type.clone() as u32),
                        memory_write: (memory_offset, 60, buf),
                        exit_reason: ExitReason::HostCall(host_call_type), // TODO: check if necessary
                    },
                }))
            }
            ExitReason::PageFault(address) => {
                Ok(HostCallResult::Refinement(RefineHostCallResult {
                    vm_state_change: HostCallVMStateChange {
                        gas_usage: BASE_GAS_USAGE,
                        r7_write: Some(FAULT as u32),
                        r8_write: Some(address),
                        memory_write: (memory_offset, 60, buf),
                        exit_reason: ExitReason::PageFault(address),
                    },
                }))
            }
            ExitReason::Panic => Ok(HostCallResult::Refinement(RefineHostCallResult {
                vm_state_change: HostCallVMStateChange {
                    gas_usage: BASE_GAS_USAGE,
                    r7_write: Some(PANIC as u32),
                    r8_write: None,
                    memory_write: (memory_offset, 60, buf),
                    exit_reason: ExitReason::Panic,
                },
            })),
            ExitReason::RegularHalt => Ok(HostCallResult::Refinement(RefineHostCallResult {
                vm_state_change: HostCallVMStateChange {
                    gas_usage: BASE_GAS_USAGE,
                    r7_write: Some(HALT as u32),
                    r8_write: None,
                    memory_write: (memory_offset, 60, buf),
                    exit_reason: ExitReason::RegularHalt,
                },
            })),
            _ => Err(PVMError::HostCallError(InvalidExitReason)),
        }
    }

    pub fn host_expunge(
        regs: &[Register; HOST_CALL_INPUT_REGISTERS_COUNT],
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let x = match context {
            InvocationContext::X_R(x) => x,
            _ => return Err(PVMError::HostCallError(InvalidContext)),
        };

        let inner_vm_id = regs[7].value as usize;

        if !x.pvm_instances.contains_key(&inner_vm_id) {
            return Ok(HostCallResult::Refinement(RefineHostCallResult {
                vm_state_change: who_change(BASE_GAS_USAGE),
            }));
        }

        let final_pc = x.pvm_instances.get(&inner_vm_id).unwrap().pc;
        x.remove_pvm_instance(inner_vm_id);

        Ok(HostCallResult::Refinement(RefineHostCallResult {
            vm_state_change: HostCallVMStateChange {
                gas_usage: BASE_GAS_USAGE,
                r7_write: Some(final_pc),
                ..Default::default()
            },
        }))
    }
}
