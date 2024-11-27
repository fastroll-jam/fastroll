use crate::{
    contexts::InvocationContext, host_functions::InnerPVMResultConstant::*, inner_vm::InnerPVM,
    utils::*,
};
use rjam_codec::{JamDecode, JamDecodeFixed, JamEncode, JamEncodeFixed};
use rjam_common::*;
use rjam_crypto::{hash, Blake2b256};
use rjam_pvm_core::{
    constants::*,
    core::{PVMCore, VMState},
    program::program_decoder::ProgramState,
    state::{
        memory::{MemAddress, Memory},
        register::Register,
    },
    types::{
        common::{ExitReason, ExportDataSegment, RegValue},
        error::{HostCallError::*, PVMError},
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

#[repr(u64)]
pub enum HostCallResultConstant {
    NONE = u64::MAX,     // An item does not exist.
    WHAT = u64::MAX - 1, // Name unknown.
    OOB = u64::MAX - 2,  // Memory index is not accessible for reading or writing.
    WHO = u64::MAX - 3,  // Index unknown.
    FULL = u64::MAX - 4, // Storage full.
    CORE = u64::MAX - 5, // Core index unknown.
    CASH = u64::MAX - 6, // Insufficient funds.
    LOW = u64::MAX - 7,  // Gas limit too low.
    HIGH = u64::MAX - 8, // Gas limit too high.
    HUH = u64::MAX - 9,  // The item is already solicited or cannot be forgotten.
    OK = 0,
}

#[repr(u32)]
pub enum InnerPVMResultConstant {
    HALT = 0,  // Normal halt
    PANIC = 1, // Panic
    FAULT = 2, // Page fault
    HOST = 3,  // Host-call fault
    OOG = 4,   // out of gas
}

pub enum AccumulateResult {
    Unchanged,
    Result(Option<Hash32>), // optional result hash
}

#[derive(Default)]
pub struct HostCallChangeSet {
    pub exit_reason: ExitReason,
    pub vm_change: HostCallVMStateChange,
}

impl HostCallChangeSet {
    fn continue_with_vm_change(vm_change: HostCallVMStateChange) -> Self {
        Self {
            exit_reason: ExitReason::Continue,
            vm_change,
        }
    }
}

pub struct HostCallVMStateChange {
    pub gas_charge: UnsignedGas,
    pub r7_write: Option<RegValue>,
    pub r8_write: Option<RegValue>,
    pub memory_write: (MemAddress, u32, Vec<u8>), // (start_address, data_len, data)
}

impl Default for HostCallVMStateChange {
    fn default() -> Self {
        Self {
            gas_charge: BASE_GAS_CHARGE,
            r7_write: None,
            r8_write: None,
            memory_write: (0, 0, vec![]),
        }
    }
}

//
// Host Functions
//

pub struct HostFunction;

impl HostFunction {
    //
    // General Functions
    //

    pub fn host_gas(gas: UnsignedGas) -> Result<HostCallChangeSet, PVMError> {
        let gas_remaining = gas.wrapping_sub(10);

        Ok(HostCallChangeSet::continue_with_vm_change(
            HostCallVMStateChange {
                gas_charge: BASE_GAS_CHARGE,
                r7_write: Some((gas_remaining & 0xFFFF_FFFF) as RegValue),
                r8_write: Some((gas_remaining >> 32) as RegValue),
                ..Default::default()
            },
        ))
    }

    pub fn host_lookup(
        target_address: Address,
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
    ) -> Result<HostCallChangeSet, PVMError> {
        let account_address_reg = regs[7].as_account_address()?;
        let hash_offset = regs[8].as_mem_address()?;
        let buffer_offset = regs[9].as_mem_address()?;
        let buffer_size = regs[10].as_usize()?;

        let account_address =
            if account_address_reg == u32::MAX || account_address_reg == target_address {
                target_address
            } else {
                account_address_reg
            };

        if !memory.is_range_readable(hash_offset, 32).unwrap() {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        let hash = hash::<Blake2b256>(&memory.read_bytes(hash_offset, 32)?)?;
        let preimage_entry = state_manager.get_account_preimages_entry(account_address, &hash)?;

        match preimage_entry {
            Some(entry) => {
                let write_data_size = buffer_size.min(entry.value.len());

                if !memory.is_range_writable(buffer_offset, buffer_size)? {
                    return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                        BASE_GAS_CHARGE,
                    )));
                }

                Ok(HostCallChangeSet::continue_with_vm_change(
                    HostCallVMStateChange {
                        gas_charge: BASE_GAS_CHARGE,
                        r7_write: Some(entry.value.len() as RegValue),
                        memory_write: (
                            buffer_offset,
                            write_data_size as u32,
                            entry.value[..write_data_size].to_vec(),
                        ),
                        ..Default::default()
                    },
                ))
            }
            None => Ok(HostCallChangeSet::continue_with_vm_change(none_change(
                BASE_GAS_CHARGE,
            ))),
        }
    }

    pub fn host_read(
        target_address: Address,
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
    ) -> Result<HostCallChangeSet, PVMError> {
        let account_address_reg = regs[7].as_account_address()?;
        let key_offset = regs[8].as_mem_address()?;
        let key_size = regs[9].as_usize()?;
        let buffer_offset = regs[10].as_mem_address()?;
        let buffer_size = regs[11].as_usize()?;

        let account_address =
            if account_address_reg == u32::MAX || account_address_reg == target_address {
                target_address
            } else {
                account_address_reg
            };

        if !memory.is_range_readable(key_offset, key_size)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
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
                return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                    BASE_GAS_CHARGE,
                )));
            }

            Ok(HostCallChangeSet::continue_with_vm_change(
                HostCallVMStateChange {
                    gas_charge: BASE_GAS_CHARGE,
                    r7_write: Some(entry.value.len() as RegValue),
                    memory_write: (
                        buffer_offset,
                        write_data_size as u32,
                        entry.value[..write_data_size].to_vec(),
                    ),
                    ..Default::default()
                },
            ))
        } else {
            Ok(HostCallChangeSet::continue_with_vm_change(none_change(
                BASE_GAS_CHARGE,
            )))
        }
    }

    // TODO: check if `target_address` is provided as an arg - not specified in the GP
    pub fn host_write(
        target_address: Address,
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
    ) -> Result<HostCallChangeSet, PVMError> {
        let key_offset = regs[7].as_mem_address()?;
        let key_size = regs[8].as_usize()?;
        let value_offset = regs[9].as_mem_address()?;
        let value_size = regs[10].as_usize()?;

        if !memory.is_range_readable(key_offset, key_size)?
            || !memory.is_range_readable(value_offset, value_size)?
        {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        let mut key = vec![];
        key.extend(target_address.encode_fixed(4)?);
        key.extend(memory.read_bytes(key_offset, key_size)?);
        let storage_key = hash::<Blake2b256>(&key)?;

        let storage_entry =
            state_manager.get_account_storage_entry(target_address, &storage_key)?;

        let previous_size = if let Some(entry) = storage_entry {
            entry.value.len() as u64
        } else {
            HostCallResultConstant::NONE as u64
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

            if previous_size == HostCallResultConstant::NONE as u64 {
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
            Ok(HostCallChangeSet::continue_with_vm_change(full_change(
                BASE_GAS_CHARGE,
            )))
        } else {
            Ok(HostCallChangeSet::continue_with_vm_change(
                HostCallVMStateChange {
                    gas_charge: BASE_GAS_CHARGE,
                    r7_write: Some(previous_size as RegValue),
                    ..Default::default()
                },
            ))
        }
    }

    pub fn host_info(
        target_address: Address,
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
    ) -> Result<HostCallChangeSet, PVMError> {
        let account_address_reg = regs[7].as_account_address()?;
        let buffer_offset = regs[8].as_mem_address()?;

        let account_address =
            if account_address_reg == u32::MAX || account_address_reg == target_address {
                target_address
            } else {
                account_address_reg
            };

        let account = match state_manager.get_account_metadata(account_address)? {
            Some(metadata) => metadata,
            None => {
                return Ok(HostCallChangeSet::continue_with_vm_change(none_change(
                    BASE_GAS_CHARGE,
                )))
            }
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
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        Ok(HostCallChangeSet::continue_with_vm_change(
            HostCallVMStateChange {
                gas_charge: BASE_GAS_CHARGE,
                r7_write: Some(HostCallResultConstant::OK as RegValue),
                memory_write: (buffer_offset, info.len() as u32, info.clone()),
                ..Default::default()
            },
        ))
    }

    //
    // Accumulate Functions
    //

    // Accumulation host functions mutate: gas, regs, contexts
    pub fn host_bless(
        regs: &[Register; REGISTERS_COUNT],
        state_manager: &StateManager,
    ) -> Result<HostCallChangeSet, PVMError> {
        let manager = regs[7].as_account_address()?;
        let assign = regs[8].as_account_address()?;
        let designate = regs[9].as_account_address()?;

        state_manager.with_mut_privileged_services(
            StateWriteOp::Update,
            |privileged_services| {
                privileged_services.manager_service = manager;
                privileged_services.assign_service = assign;
                privileged_services.designate_service = designate;
            },
        )?;

        Ok(HostCallChangeSet::continue_with_vm_change(
            HostCallVMStateChange::default(),
        ))
    }

    #[allow(clippy::needless_range_loop)]
    pub fn host_assign(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
    ) -> Result<HostCallChangeSet, PVMError> {
        let core_index = regs[7].as_usize()?;
        let offset = regs[8].as_mem_address()?;

        if !memory.is_range_readable(offset, HASH_SIZE * MAX_AUTH_QUEUE_SIZE)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        if core_index >= CORE_COUNT {
            return Ok(HostCallChangeSet::continue_with_vm_change(core_change(
                BASE_GAS_CHARGE,
            )));
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

        Ok(HostCallChangeSet::continue_with_vm_change(ok_change(
            BASE_GAS_CHARGE,
        )))
    }

    pub fn host_designate(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
    ) -> Result<HostCallChangeSet, PVMError> {
        let offset = regs[7].as_mem_address()?;

        // FIXME: check the public key blob length - the PVM spec describes as 176 but public key blob is 336 bytes in general
        const PUBLIC_KEY_SIZE: usize = 336;
        if !memory.is_range_readable(offset, PUBLIC_KEY_SIZE * VALIDATOR_COUNT)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
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

        Ok(HostCallChangeSet::continue_with_vm_change(ok_change(
            BASE_GAS_CHARGE,
        )))
    }

    pub fn host_checkpoint(
        gas: UnsignedGas,
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let acc_pair = match context.as_accumulate_context_mut() {
            Some(pair) => pair,
            None => return Err(PVMError::HostCallError(InvalidContext)),
        };

        let x_clone = acc_pair.get_x().clone();
        *acc_pair.get_mut_y() = x_clone; // assign the cloned `x` context to the `y` context

        let post_gas = gas.saturating_sub(BASE_GAS_CHARGE); // TODO: gas management

        Ok(HostCallChangeSet::continue_with_vm_change(
            HostCallVMStateChange {
                gas_charge: BASE_GAS_CHARGE,
                r7_write: Some(post_gas as RegValue),
                r8_write: Some((post_gas >> 32) as RegValue),
                ..Default::default()
            },
        ))
    }
    pub fn host_new(
        creator_address: Address,
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let acc_pair = match context.as_accumulate_context_mut() {
            Some(pair) => pair,
            None => return Err(PVMError::HostCallError(InvalidContext)),
        };
        let x = acc_pair.get_mut_x();

        let offset = regs[7].as_mem_address()?;
        let lookup_len = regs[8].value();
        let gas_limit_g_low = regs[9].value();
        let gas_limit_g_high = regs[10].value();
        let gas_limit_m_low = regs[11].value();
        let gas_limit_m_high = regs[12].value();

        if !memory.is_range_readable(offset, HASH_SIZE)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        let code_hash = Hash32::decode(&mut memory.read_bytes(offset, HASH_SIZE)?.as_slice())?;
        let gas_limit_g = gas_limit_g_high << 32 | gas_limit_g_low;
        let gas_limit_m = gas_limit_m_high << 32 | gas_limit_m_low;

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
            return Ok(HostCallChangeSet::continue_with_vm_change(cash_change(
                BASE_GAS_CHARGE,
            )));
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
            (&code_hash, lookup_len as u32), // FIXME: conversion
            |lookup_entry| {
                lookup_entry.value = vec![];
            },
        )?;

        x.rotate_new_account_address(state_manager)?;

        Ok(HostCallChangeSet::continue_with_vm_change(
            HostCallVMStateChange {
                gas_charge: BASE_GAS_CHARGE,
                r7_write: Some(new_account_address as RegValue),
                ..Default::default()
            },
        ))
    }

    pub fn host_upgrade(
        target_address: Address,
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
    ) -> Result<HostCallChangeSet, PVMError> {
        let offset = regs[7].as_mem_address()?;
        let gas_limit_g_low = regs[8].value();
        let gas_limit_g_high = regs[9].value();
        let gas_limit_m_low = regs[10].value();
        let gas_limit_m_high = regs[11].value();

        if !memory.is_range_readable(offset, HASH_SIZE)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        let code_hash = Hash32::decode(&mut memory.read_bytes(offset, HASH_SIZE)?.as_slice())?;
        let gas_limit_g = gas_limit_g_high << 32 | gas_limit_g_low;
        let gas_limit_m = gas_limit_m_high << 32 | gas_limit_m_low;

        state_manager.with_mut_account_metadata(
            StateWriteOp::Update,
            target_address,
            |account_metadata| {
                account_metadata.account_info.code_hash = code_hash;
                account_metadata.account_info.gas_limit_accumulate = gas_limit_g;
                account_metadata.account_info.gas_limit_on_transfer = gas_limit_m;
            },
        )?;

        Ok(HostCallChangeSet::continue_with_vm_change(ok_change(
            BASE_GAS_CHARGE,
        )))
    }

    pub fn host_transfer(
        sender_address: Address,
        gas: UnsignedGas,
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let acc_pair = match context.as_accumulate_context_mut() {
            Some(pair) => pair,
            None => return Err(PVMError::HostCallError(InvalidContext)),
        };
        let x = acc_pair.get_mut_x();

        let dest = regs[7].as_account_address()?;
        let amount_low = regs[8].value();
        let amount_high = regs[9].value();
        let gas_limit_low = regs[10].value();
        let gas_limit_high = regs[11].value();
        let offset = regs[12].as_mem_address()?;

        let amount = amount_high << 32 | amount_low;
        let gas_limit = gas_limit_high << 32 | gas_limit_low;

        if !memory.is_range_readable(offset, TRANSFER_MEMO_SIZE)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
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
            return Ok(HostCallChangeSet::continue_with_vm_change(who_change(
                BASE_GAS_CHARGE + amount,
            )));
        }

        let dest_gas_limit_m = state_manager
            .get_account_metadata(dest)?
            .unwrap()
            .account_info
            .gas_limit_on_transfer;

        if gas_limit < dest_gas_limit_m {
            return Ok(HostCallChangeSet::continue_with_vm_change(low_change(
                BASE_GAS_CHARGE + amount,
            )));
        }

        if gas < gas_limit {
            return Ok(HostCallChangeSet::continue_with_vm_change(high_change(
                BASE_GAS_CHARGE + amount,
            )));
        }

        if sender_post_balance < sender_account_metadata.get_threshold_balance() {
            return Ok(HostCallChangeSet::continue_with_vm_change(cash_change(
                BASE_GAS_CHARGE + amount,
            )));
        }

        x.add_to_deferred_transfers(transfer);
        state_manager.with_mut_account_metadata(
            StateWriteOp::Update,
            sender_address,
            |sender_account_metadata| {
                sender_account_metadata.account_info.balance = sender_post_balance;
            },
        )?;

        Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
            BASE_GAS_CHARGE + amount,
        )))
    }

    pub fn host_quit(
        target_address: Address,
        gas: UnsignedGas,
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let acc_pair = match context.as_accumulate_context_mut() {
            Some(pair) => pair,
            None => return Err(PVMError::HostCallError(InvalidContext)),
        };
        let x = acc_pair.get_mut_x();

        let dest = regs[7].as_account_address()?;
        let offset = regs[8].as_mem_address()?;

        let context_account = state_manager.get_account_metadata(target_address)?.unwrap();

        let amount = context_account
            .account_info
            .balance
            .wrapping_sub(context_account.get_threshold_balance())
            + B_S;

        if dest == u32::MAX || dest == target_address {
            return Ok(HostCallChangeSet {
                exit_reason: ExitReason::RegularHalt,
                vm_change: HostCallVMStateChange {
                    gas_charge: BASE_GAS_CHARGE,
                    r7_write: Some(HostCallResultConstant::OK as RegValue),
                    ..Default::default()
                },
            }); // TODO: check gas usage from the GP
        }

        if !memory.is_range_readable(offset, TRANSFER_MEMO_SIZE)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
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
            return Ok(HostCallChangeSet::continue_with_vm_change(who_change(
                BASE_GAS_CHARGE + amount,
            )));
        }

        let dest_gas_limit_m = state_manager
            .get_account_metadata(dest)?
            .unwrap()
            .account_info
            .gas_limit_on_transfer;

        if gas < dest_gas_limit_m {
            return Ok(HostCallChangeSet::continue_with_vm_change(low_change(
                BASE_GAS_CHARGE + amount,
            )));
        }
        x.add_to_deferred_transfers(transfer);

        Ok(HostCallChangeSet {
            exit_reason: ExitReason::RegularHalt,
            vm_change: HostCallVMStateChange {
                gas_charge: BASE_GAS_CHARGE,
                r7_write: Some(HostCallResultConstant::OK as RegValue),
                ..Default::default()
            },
        })
    }

    pub fn host_solicit(
        target_address: Address,
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
    ) -> Result<HostCallChangeSet, PVMError> {
        let offset = regs[7].as_mem_address()?;
        let lookup_len = regs[8].as_u32()?;

        if !memory.is_range_readable(offset, HASH_SIZE)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        let lookup_hash = Hash32::decode(&mut memory.read_bytes(offset, HASH_SIZE)?.as_slice())?;

        let account = state_manager.get_account_metadata(target_address)?.unwrap();
        if account.account_info.balance < account.get_threshold_balance() {
            return Ok(HostCallChangeSet::continue_with_vm_change(full_change(
                BASE_GAS_CHARGE,
            )));
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
                    return Ok(HostCallChangeSet::continue_with_vm_change(huh_change(
                        BASE_GAS_CHARGE,
                    )));
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

        Ok(HostCallChangeSet::continue_with_vm_change(ok_change(
            BASE_GAS_CHARGE,
        )))
    }

    pub fn host_forget(
        target_address: Address,
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
    ) -> Result<HostCallChangeSet, PVMError> {
        let offset = regs[7].as_mem_address()?;
        let lookup_len = regs[8].as_u32()?;

        if !memory.is_range_readable(offset, HASH_SIZE)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        let lookup_hash = Hash32::decode(&mut memory.read_bytes(offset, HASH_SIZE)?.as_slice())?;

        let current_timeslot = state_manager.get_timeslot()?;
        let lookups_key = (&lookup_hash, lookup_len);
        let account_lookups_entry =
            state_manager.get_account_lookups_entry(target_address, lookups_key)?;

        let vm_state_change = match account_lookups_entry {
            None => huh_change(BASE_GAS_CHARGE),
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
                        ok_change(BASE_GAS_CHARGE)
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
                        ok_change(BASE_GAS_CHARGE)
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
                        ok_change(BASE_GAS_CHARGE)
                    }
                    _ => huh_change(BASE_GAS_CHARGE),
                }
            }
        };
        Ok(HostCallChangeSet::continue_with_vm_change(vm_state_change))
    }

    //
    // Refine Functions
    //

    pub fn host_historical_lookup(
        target_address: Address,
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
    ) -> Result<HostCallChangeSet, PVMError> {
        // FIXME: timeslot should come from the refinement context, not current timeslot
        let timeslot = state_manager.get_timeslot()?;

        let account_address_reg = regs[7].as_account_address()?;
        let lookup_hash_offset = regs[8].as_mem_address()?;
        let buffer_offset = regs[9].as_mem_address()?;
        let buffer_size = regs[10].as_usize()?;

        let account_address =
            if account_address_reg == u32::MAX || state_manager.account_exists(target_address)? {
                target_address
            } else if state_manager.account_exists(account_address_reg)? {
                account_address_reg
            } else {
                return Ok(HostCallChangeSet::continue_with_vm_change(none_change(
                    BASE_GAS_CHARGE,
                )));
            };

        if !memory.is_range_readable(lookup_hash_offset, HASH_SIZE)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        let lookup_hash =
            Hash32::decode(&mut memory.read_bytes(lookup_hash_offset, HASH_SIZE)?.as_slice())?;

        let preimage = state_manager.lookup_preimage(account_address, &timeslot, &lookup_hash)?;

        if let Some(preimage) = preimage {
            let write_data_size = buffer_size.min(preimage.len());

            if !memory.is_range_writable(buffer_offset, buffer_size)? {
                return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                    BASE_GAS_CHARGE,
                )));
            }

            Ok(HostCallChangeSet::continue_with_vm_change(
                HostCallVMStateChange {
                    gas_charge: BASE_GAS_CHARGE,
                    r7_write: Some(preimage.len() as RegValue),
                    memory_write: (
                        buffer_offset,
                        write_data_size as u32,
                        preimage[..write_data_size].to_vec(),
                    ),
                    ..Default::default()
                },
            ))
        } else {
            Ok(HostCallChangeSet::continue_with_vm_change(none_change(
                BASE_GAS_CHARGE,
            )))
        }
    }

    pub fn host_import(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        import_segments: Vec<ExportDataSegment>,
    ) -> Result<HostCallChangeSet, PVMError> {
        let segment_index = regs[7].as_usize()?;
        let offset = regs[8].as_mem_address()?;
        let segments_len = regs[9].as_usize()?;

        if segments_len >= DATA_SEGMENTS_SIZE {
            return Ok(HostCallChangeSet::continue_with_vm_change(none_change(
                BASE_GAS_CHARGE,
            )));
        }

        let import_segment = import_segments[segment_index];
        let segment_len = segments_len.min(DATA_SEGMENTS_SIZE);

        if !memory.is_range_writable(offset, segment_len)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        Ok(HostCallChangeSet::continue_with_vm_change(
            HostCallVMStateChange {
                gas_charge: BASE_GAS_CHARGE,
                r7_write: Some(HostCallResultConstant::OK as RegValue),
                memory_write: (offset, segment_len as u32, import_segment.to_vec()),
                ..Default::default()
            },
        ))
    }

    pub fn host_export(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        context: &mut InvocationContext,
        export_segment_offset: usize,
    ) -> Result<HostCallChangeSet, PVMError> {
        let x = match context.as_refine_context_mut() {
            Some(ctx) => ctx,
            None => return Err(PVMError::HostCallError(InvalidContext)),
        };

        let offset = regs[7].as_mem_address()?;
        let size = regs[8].as_usize()?;

        let size = size.min(DATA_SEGMENTS_SIZE);

        if !memory.is_range_readable(offset, size)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
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
            return Ok(HostCallChangeSet::continue_with_vm_change(full_change(
                BASE_GAS_CHARGE,
            )));
        }

        x.export_segments.extend(vec![data]);

        Ok(HostCallChangeSet::continue_with_vm_change(
            HostCallVMStateChange {
                gas_charge: BASE_GAS_CHARGE,
                r7_write: Some((export_segment_limit) as RegValue),
                ..Default::default()
            },
        ))
    }

    pub fn host_machine(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let x = match context.as_refine_context_mut() {
            Some(ctx) => ctx,
            None => return Err(PVMError::HostCallError(InvalidContext)),
        };

        let program_offset = regs[7].as_mem_address()?;
        let program_size = regs[8].as_usize()?;
        let initial_pc = regs[9].value();

        if !memory.is_range_readable(program_offset, program_size)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        let program = memory.read_bytes(program_offset, program_size)?;
        let inner_vm = InnerPVM::new(program, initial_pc);
        let inner_vm_id = x.add_pvm_instance(inner_vm);

        Ok(HostCallChangeSet::continue_with_vm_change(
            HostCallVMStateChange {
                gas_charge: BASE_GAS_CHARGE,
                r7_write: Some(inner_vm_id as RegValue),
                ..Default::default()
            },
        ))
    }

    pub fn host_peek(
        regs: &[Register; REGISTERS_COUNT],
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let x = match context.as_refine_context_mut() {
            Some(ctx) => ctx,
            None => return Err(PVMError::HostCallError(InvalidContext)),
        };

        let inner_vm_id = regs[7].as_usize()?;
        let memory_offset = regs[8].as_mem_address()?;
        let inner_memory_offset = regs[9].as_mem_address()?;
        let data_len = regs[10].as_usize()?;

        if !x.pvm_instances.contains_key(&inner_vm_id) {
            return Ok(HostCallChangeSet::continue_with_vm_change(who_change(
                BASE_GAS_CHARGE,
            )));
        }
        let inner_memory = &x.pvm_instances.get(&inner_vm_id).unwrap().memory;

        if !inner_memory.is_range_readable(inner_memory_offset, data_len)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }
        let data = inner_memory.read_bytes(inner_memory_offset, data_len)?;

        Ok(HostCallChangeSet::continue_with_vm_change(
            HostCallVMStateChange {
                gas_charge: BASE_GAS_CHARGE,
                r7_write: Some(HostCallResultConstant::OK as RegValue),
                memory_write: (memory_offset, data_len as u32, data),
                ..Default::default()
            },
        ))
    }

    pub fn host_poke(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let x = match context.as_refine_context_mut() {
            Some(ctx) => ctx,
            None => return Err(PVMError::HostCallError(InvalidContext)),
        };

        let inner_vm_id = regs[7].as_usize()?;
        let memory_offset = regs[8].as_mem_address()?;
        let inner_memory_offset = regs[9].as_mem_address()?;
        let data_len = regs[10].as_usize()?;

        if !x.pvm_instances.contains_key(&inner_vm_id) {
            return Ok(HostCallChangeSet::continue_with_vm_change(who_change(
                BASE_GAS_CHARGE,
            )));
        }
        let inner_memory = &mut x.pvm_instances.get_mut(&inner_vm_id).unwrap().memory;

        if !memory.is_range_readable(memory_offset, data_len)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }
        let data = memory.read_bytes(memory_offset, data_len)?;

        inner_memory.write_bytes(inner_memory_offset as MemAddress, &data)?;

        Ok(HostCallChangeSet::continue_with_vm_change(ok_change(
            BASE_GAS_CHARGE,
        )))
    }

    pub fn host_invoke(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let x = match context.as_refine_context_mut() {
            Some(ctx) => ctx,
            None => return Err(PVMError::HostCallError(InvalidContext)),
        };

        let inner_vm_id = regs[7].as_usize()?;
        let memory_offset = regs[8].as_mem_address()?;

        if !memory.is_range_writable(memory_offset, 60)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        if !x.pvm_instances.contains_key(&inner_vm_id) {
            return Ok(HostCallChangeSet::continue_with_vm_change(who_change(
                BASE_GAS_CHARGE,
            )));
        }

        let gas = UnsignedGas::decode_fixed(&mut &memory.read_bytes(memory_offset, 8)?[..], 8)?;

        let mut regs = [Register::default(); REGISTERS_COUNT];
        for (i, register) in regs.iter_mut().enumerate() {
            register.value = RegValue::decode_fixed(
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

        // Construct a new `VMState` and `ProgramState` for the general invocation function.
        let mut inner_vm_state = VMState {
            registers: regs,
            memory: inner_vm.memory.clone(), // FIXME: remove `clone`
            pc: inner_vm.pc,
            gas_counter: gas,
        };
        let inner_vm_program_code = &inner_vm.program_code;
        let mut inner_vm_program_state = ProgramState::default();

        let inner_vm_exit_reason = PVMCore::general_invocation(
            &mut inner_vm_state,
            &mut inner_vm_program_state,
            inner_vm_program_code,
        )?;

        // TODO: update the InnerVM pc

        let mut buf = vec![];
        inner_vm_state.gas_counter.encode_to_fixed(&mut buf, 8)?;
        for reg in inner_vm_state.registers {
            reg.value.encode_to_fixed(&mut buf, 4)?;
        }

        match inner_vm_exit_reason {
            ExitReason::HostCall(host_call_type) => {
                inner_vm_state.pc += 1;
                Ok(HostCallChangeSet::continue_with_vm_change(
                    HostCallVMStateChange {
                        gas_charge: BASE_GAS_CHARGE,
                        r7_write: Some(HOST as RegValue),
                        r8_write: Some(host_call_type as RegValue),
                        memory_write: (memory_offset, 60, buf),
                    },
                ))
            }
            ExitReason::PageFault(address) => Ok(HostCallChangeSet::continue_with_vm_change(
                HostCallVMStateChange {
                    gas_charge: BASE_GAS_CHARGE,
                    r7_write: Some(FAULT as RegValue),
                    r8_write: Some(address as RegValue),
                    memory_write: (memory_offset, 60, buf),
                },
            )),
            ExitReason::Panic => Ok(HostCallChangeSet::continue_with_vm_change(
                HostCallVMStateChange {
                    gas_charge: BASE_GAS_CHARGE,
                    r7_write: Some(PANIC as RegValue),
                    r8_write: None,
                    memory_write: (memory_offset, 60, buf),
                },
            )),
            ExitReason::RegularHalt => Ok(HostCallChangeSet::continue_with_vm_change(
                HostCallVMStateChange {
                    gas_charge: BASE_GAS_CHARGE,
                    r7_write: Some(HALT as RegValue),
                    r8_write: None,
                    memory_write: (memory_offset, 60, buf),
                },
            )),

            _ => Err(PVMError::HostCallError(InvalidExitReason)),
        }
    }

    pub fn host_expunge(
        regs: &[Register; REGISTERS_COUNT],
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let x = match context {
            InvocationContext::X_R(x) => x,
            _ => return Err(PVMError::HostCallError(InvalidContext)),
        };

        let inner_vm_id = regs[7].as_usize()?;

        if !x.pvm_instances.contains_key(&inner_vm_id) {
            return Ok(HostCallChangeSet::continue_with_vm_change(who_change(
                BASE_GAS_CHARGE,
            )));
        }

        let final_pc = x.pvm_instances.get(&inner_vm_id).unwrap().pc;
        x.remove_pvm_instance(inner_vm_id);

        Ok(HostCallChangeSet::continue_with_vm_change(
            HostCallVMStateChange {
                gas_charge: BASE_GAS_CHARGE,
                r7_write: Some(final_pc),
                ..Default::default()
            },
        ))
    }
}
