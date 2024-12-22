use crate::{
    context::types::InvocationContext, host_functions::InnerPVMResultConstant::*,
    inner_vm::InnerPVM, utils::*,
};
use rjam_codec::{JamDecode, JamDecodeFixed, JamEncodeFixed};
use rjam_common::*;
use rjam_crypto::{hash, Blake2b256};
use rjam_pvm_core::{
    constants::*,
    core::{PVMCore, VMState},
    program::program_decoder::ProgramState,
    state::{
        memory::{AccessType, MemAddress, Memory},
        register::Register,
    },
    types::{
        common::{ExitReason, ExportDataSegment, RegValue},
        error::{HostCallError::*, PVMError, VMCoreError::InvalidRegVal},
    },
};
use rjam_state::{
    StateManager,
    StateManagerError::{LookupsEntryNotFound, StorageEntryNotFound},
};
use rjam_types::{common::transfers::DeferredTransfer, state::*};
use std::collections::HashMap;

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

/// Represents the state changes in the PVM resulting from a single host function execution.
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

pub struct HostFunction;

impl HostFunction {
    //
    // General Functions
    //

    /// Retrieves the current remaining gas limit of the VM state after deducting the base gas charge
    /// for executing this instruction.
    pub fn host_gas(gas: UnsignedGas) -> Result<HostCallChangeSet, PVMError> {
        let gas_remaining = gas.wrapping_sub(BASE_GAS_CHARGE);

        Ok(HostCallChangeSet::continue_with_vm_change(
            HostCallVMStateChange {
                gas_charge: BASE_GAS_CHARGE,
                r7_write: Some(gas_remaining as RegValue),
                ..Default::default()
            },
        ))
    }

    /// Fetches the preimage of the specified hash from the given service account's preimage storage
    /// and writes it to memory.
    pub fn host_lookup(
        target_address: Address,
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let accounts_sandbox = context.get_mut_accounts_sandbox()?;

        let account_address_reg = regs[7].as_u64()?;
        let hash_offset = regs[8].as_mem_address()?;
        let buffer_offset = regs[9].as_mem_address()?;
        let buffer_size = regs[10].as_usize()?;

        let account_address =
            if account_address_reg == u64::MAX || account_address_reg == target_address as u64 {
                target_address
            } else {
                account_address_reg as Address
            };

        if !memory.is_address_range_readable(hash_offset, 32)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        let hash = hash::<Blake2b256>(&memory.read_bytes(hash_offset, 32)?)?;

        if let Some(entry) = accounts_sandbox.get_or_load_account_preimages_entry(
            state_manager,
            account_address,
            &hash,
        )? {
            let write_data_size = buffer_size.min(entry.value.len());

            if !memory.is_address_range_writable(buffer_offset, buffer_size)? {
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

    /// Fetches the storage entry value of the specified storage key from the given service account's
    /// storage and writes it into memory.
    pub fn host_read(
        target_address: Address,
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let accounts_sandbox = context.get_mut_accounts_sandbox()?;

        let account_address_reg = regs[7].as_u64()?;
        let key_offset = regs[8].as_mem_address()?;
        let key_size = regs[9].as_usize()?;
        let buffer_offset = regs[10].as_mem_address()?;
        let buffer_size = regs[11].as_usize()?;

        let account_address =
            if account_address_reg == u64::MAX || account_address_reg == target_address as u64 {
                target_address
            } else {
                account_address_reg as Address
            };

        if !memory.is_address_range_readable(key_offset, key_size)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        let mut key = target_address.encode_fixed(4)?;
        key.extend(memory.read_bytes(key_offset, key_size)?);
        let storage_key = hash::<Blake2b256>(&key)?;

        if let Some(entry) = accounts_sandbox.get_or_load_account_storage_entry(
            state_manager,
            account_address,
            &storage_key,
        )? {
            let write_data_size = buffer_size.min(entry.value.len());

            if !memory.is_address_range_writable(buffer_offset, buffer_size)? {
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

    /// Writes an entry to the storage of the service account hosting the code being executed,
    /// using a key and value loaded from memory.
    /// If the value size is zero, the entry corresponding to the key is removed.
    /// The size of the previous value, if any, is returned via the register.
    pub fn host_write(
        target_address: Address,
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let accounts_sandbox = context.get_mut_accounts_sandbox()?;

        let key_offset = regs[7].as_mem_address()?;
        let key_size = regs[8].as_usize()?;
        let value_offset = regs[9].as_mem_address()?;
        let value_size = regs[10].as_usize()?;

        if !memory.is_address_range_readable(key_offset, key_size)?
            || !memory.is_address_range_readable(value_offset, value_size)?
        {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        let mut key = target_address.encode_fixed(4)?;
        key.extend(memory.read_bytes(key_offset, key_size)?);
        let storage_key = hash::<Blake2b256>(&key)?;

        // Threshold balance change simulation
        let prev_storage_entry = accounts_sandbox.get_or_load_account_storage_entry(
            state_manager,
            target_address,
            &storage_key,
        )?;

        let prev_value_size = if let Some(entry) = &prev_storage_entry {
            entry.value.len() as u64
        } else {
            HostCallResultConstant::NONE as u64
        };

        let new_storage_entry_data = memory.read_bytes(value_offset, value_size)?;
        let new_storage_entry = AccountStorageEntry {
            value: Octets::from_vec(new_storage_entry_data.clone()),
        };

        let (storage_items_count_delta, storage_octets_count_delta) =
            AccountMetadata::calculate_storage_footprint_delta(
                prev_storage_entry.as_ref(),
                &new_storage_entry,
            )
            .ok_or(PVMError::StateManagerError(StorageEntryNotFound))?;

        let target_account_metadata = accounts_sandbox
            .get_account_metadata(state_manager, target_address)?
            .ok_or(PVMError::HostCallError(AccountNotFound))?;

        let simulated_threshold_balance = target_account_metadata
            .simulate_threshold_balance_after_mutation(
                0,
                storage_items_count_delta,
                0,
                storage_octets_count_delta,
            );

        if simulated_threshold_balance > target_account_metadata.account_info.balance {
            return Ok(HostCallChangeSet::continue_with_vm_change(full_change(
                BASE_GAS_CHARGE,
            )));
        }

        // Apply the state change
        if value_size == 0 {
            // Remove the entry if the size of the new entry value is zero
            accounts_sandbox.remove_account_storage_entry(
                state_manager,
                target_address,
                storage_key,
            )?;
        } else {
            // FIXME: get prev_value here
            accounts_sandbox.insert_account_storage_entry(
                state_manager,
                target_address,
                storage_key,
                new_storage_entry,
            )?;
        }

        Ok(HostCallChangeSet::continue_with_vm_change(
            HostCallVMStateChange {
                gas_charge: BASE_GAS_CHARGE,
                r7_write: Some(prev_value_size as RegValue),
                ..Default::default()
            },
        ))
    }

    /// Retrieves the metadata of the specified account in a serialized format.
    pub fn host_info(
        target_address: Address,
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let accounts_sandbox = context.get_mut_accounts_sandbox()?;

        let account_address_reg = regs[7].as_u64()?;
        let buffer_offset = regs[8].as_mem_address()?;

        let account_address =
            if account_address_reg == u64::MAX || account_address_reg == target_address as u64 {
                target_address
            } else {
                account_address_reg as Address
            };

        let account_metadata = if let Some(metadata) =
            accounts_sandbox.get_account_metadata(state_manager, account_address)?
        {
            metadata
        } else {
            return Ok(HostCallChangeSet::continue_with_vm_change(none_change(
                BASE_GAS_CHARGE,
            )));
        };

        // Encode account metadata with JAM Codec
        let info = account_metadata.encode_for_info_hostcall()?;

        if !memory.is_address_range_writable(buffer_offset, info.len())? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        Ok(HostCallChangeSet::continue_with_vm_change(
            HostCallVMStateChange {
                gas_charge: BASE_GAS_CHARGE,
                r7_write: Some(HostCallResultConstant::OK as RegValue),
                memory_write: (buffer_offset, info.len() as u32, info),
                ..Default::default()
            },
        ))
    }

    //
    // Accumulate Functions
    //

    /// Assigns new privileged services: manager (m), assign (a), designate (v) and
    /// always-accumulates (g) to the accumulate context partial state.
    pub fn host_bless(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let x = context.get_mut_accumulate_x()?;

        let manager = regs[7].as_account_address()?;
        let assign = regs[8].as_account_address()?;
        let designate = regs[9].as_account_address()?;
        let offset = regs[10].as_mem_address()?;
        let always_accumulates_count = regs[11].as_usize()?;

        if !memory.is_address_range_readable(offset, 12 * always_accumulates_count)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        let mut always_accumulate_services = HashMap::new();

        for i in 0..always_accumulates_count {
            let always_accumulate_serialized =
                memory.read_bytes(offset + 12 * i as MemAddress, 12)?;
            let address = u32::decode_fixed(&mut always_accumulate_serialized.as_slice(), 4)?;
            let basic_gas = u64::decode_fixed(&mut always_accumulate_serialized.as_slice(), 8)?;
            always_accumulate_services.insert(address, basic_gas);
        }

        x.assign_new_privileged_services(manager, assign, designate, always_accumulate_services)?;

        Ok(HostCallChangeSet::continue_with_vm_change(ok_change(
            BASE_GAS_CHARGE,
        )))
    }

    /// Assigns `MAX_AUTH_QUEUE_SIZE` new authorizers to the `AuthQueue` of the specified core
    /// in the accumulate context partial state.
    pub fn host_assign(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let x = context.get_mut_accumulate_x()?;

        let core_index = regs[7].as_usize()?;
        let offset = regs[8].as_mem_address()?;

        if !memory.is_address_range_readable(offset, HASH_SIZE * MAX_AUTH_QUEUE_SIZE)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        if core_index >= CORE_COUNT {
            return Ok(HostCallChangeSet::continue_with_vm_change(core_change(
                BASE_GAS_CHARGE,
            )));
        }

        let mut queue_assignment = AuthQueue::default();
        for i in 0..MAX_AUTH_QUEUE_SIZE {
            let authorizer =
                memory.read_bytes(offset + (HASH_SIZE * i) as MemAddress, HASH_SIZE)?;
            queue_assignment.0[core_index][i] = Hash32::decode(&mut authorizer.as_slice())?;
        }

        x.assign_new_auth_queue(queue_assignment)?;

        Ok(HostCallChangeSet::continue_with_vm_change(ok_change(
            BASE_GAS_CHARGE,
        )))
    }

    /// Assigns `VALIDATOR_COUNT` new validators to the `StagingSet` in the accumulate context partial state.
    pub fn host_designate(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let x = context.get_mut_accumulate_x()?;

        let offset = regs[7].as_mem_address()?;

        if !memory.is_address_range_readable(offset, PUBLIC_KEY_SIZE * VALIDATOR_COUNT)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        let mut new_staging_set = StagingSet::default();
        for i in 0..VALIDATOR_COUNT {
            let validator_key = memory.read_bytes(
                offset + (PUBLIC_KEY_SIZE * i) as MemAddress,
                PUBLIC_KEY_SIZE,
            )?;
            new_staging_set[i] = ValidatorKey::decode(&mut validator_key.as_slice())?;
        }

        x.assign_new_staging_set(new_staging_set)?;

        Ok(HostCallChangeSet::continue_with_vm_change(ok_change(
            BASE_GAS_CHARGE,
        )))
    }

    /// Copies a snapshot of the current accumulate context state into
    /// the checkpoint context of the context pair.
    pub fn host_checkpoint(
        gas: UnsignedGas,
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let x_clone = context.get_accumulate_x()?.clone();
        let y_mut = context.get_mut_accumulate_y()?;

        *y_mut = x_clone; // assign the cloned `x` context to the `y` context

        // If execution of this function results in `ExitReason::OutOfGas`,
        // returns zero value for the remaining gas limit.
        let post_gas = gas.saturating_sub(BASE_GAS_CHARGE);

        Ok(HostCallChangeSet::continue_with_vm_change(
            HostCallVMStateChange {
                gas_charge: BASE_GAS_CHARGE,
                r7_write: Some(post_gas as RegValue),
                ..Default::default()
            },
        ))
    }

    /// Creates a new service account with an address derived from the hash of the accumulator address,
    /// the current epochal entropy, and the block timeslot index.
    ///
    /// The code hash is loaded into memory, and the two gas limits are provided as arguments in registers.
    ///
    /// The account storage and lookup dictionary are initialized as empty.
    pub fn host_new(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let x = context.get_mut_accumulate_x()?;

        let offset = regs[7].as_mem_address()?;
        let code_lookup_len = regs[8].as_u32()?;
        let gas_limit_g = regs[9].value();
        let gas_limit_m = regs[10].value();

        if !memory.is_address_range_readable(offset, HASH_SIZE)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        let code_hash = Hash32::decode(&mut memory.read_bytes(offset, HASH_SIZE)?.as_slice())?;
        let new_threshold_balance = AccountMetadata::get_initial_threshold_balance();

        // Check if the accumulator's balance if sufficient and subtract by
        // the initial threshold balance to be transferred to the new account.
        let accumulator_metadata = x.get_accumulator_metadata(state_manager)?;
        let accumulator_balance = accumulator_metadata.balance();
        let accumulator_threshold_balance = accumulator_metadata.threshold_balance();

        if accumulator_balance < accumulator_threshold_balance + new_threshold_balance {
            return Ok(HostCallChangeSet::continue_with_vm_change(cash_change(
                BASE_GAS_CHARGE,
            )));
        }

        x.subtract_accumulator_balance(state_manager, new_threshold_balance)?;

        // Add a new account to the partial state
        let new_account_address = x.add_new_account(
            state_manager,
            AccountInfo {
                code_hash,
                balance: new_threshold_balance,
                gas_limit_accumulate: gas_limit_g,
                gas_limit_on_transfer: gas_limit_m,
            },
            (code_hash, code_lookup_len),
        )?;

        // Update the next new account address in the partial state
        x.rotate_new_account_address(state_manager)?;

        Ok(HostCallChangeSet::continue_with_vm_change(
            HostCallVMStateChange {
                gas_charge: BASE_GAS_CHARGE,
                r7_write: Some(new_account_address as RegValue),
                ..Default::default()
            },
        ))
    }

    /// Upgrades three metadata fields of the accumulating service account:
    /// code hash, accumulate gas limit and on-transfer gas limit.
    pub fn host_upgrade(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let x = context.get_mut_accumulate_x()?;

        let offset = regs[7].as_mem_address()?;
        let gas_limit_g = regs[8].value();
        let gas_limit_m = regs[9].value();

        if !memory.is_address_range_readable(offset, HASH_SIZE)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        let code_hash = Hash32::decode(&mut memory.read_bytes(offset, HASH_SIZE)?.as_slice())?;

        x.update_accumulator_metadata(state_manager, code_hash, gas_limit_g, gas_limit_m)?;

        Ok(HostCallChangeSet::continue_with_vm_change(ok_change(
            BASE_GAS_CHARGE,
        )))
    }

    /// Transfers tokens from the accumulating service account to another service account.
    pub fn host_transfer(
        gas: UnsignedGas,
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let x = context.get_mut_accumulate_x()?;

        let dest = regs[7].as_account_address()?;
        let amount = regs[8].value();
        let gas_limit = regs[9].value();
        let offset = regs[10].as_mem_address()?;
        let gas_charge = BASE_GAS_CHARGE + amount + (1 << 32) * gas_limit;

        if !memory.is_address_range_readable(offset, TRANSFER_MEMO_SIZE)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        let memo = <[u8; TRANSFER_MEMO_SIZE]>::decode(
            &mut memory.read_bytes(offset, TRANSFER_MEMO_SIZE)?.as_slice(),
        )?;

        let transfer = DeferredTransfer {
            from: x.accumulate_host,
            to: dest,
            amount,
            memo,
            gas_limit,
        };

        let accumulator_balance = x.get_accumulator_metadata(state_manager)?.balance();
        let accumulator_threshold_balance = x
            .get_accumulator_metadata(state_manager)?
            .threshold_balance();

        // Check the state manager and the accumulate context partial state to confirm that the
        // destination account exists.
        let dest_on_transfer_gas_limit = match x
            .partial_state
            .accounts_sandbox
            .get_account_metadata(state_manager, dest)?
        {
            Some(metadata) => metadata.account_info.gas_limit_on_transfer,
            None => {
                return Ok(HostCallChangeSet::continue_with_vm_change(who_change(
                    gas_charge,
                )));
            }
        };

        if gas_limit < dest_on_transfer_gas_limit {
            return Ok(HostCallChangeSet::continue_with_vm_change(low_change(
                gas_charge,
            )));
        }

        if gas < gas_limit {
            return Ok(HostCallChangeSet::continue_with_vm_change(high_change(
                gas_charge,
            )));
        }

        if accumulator_balance < amount + accumulator_threshold_balance {
            return Ok(HostCallChangeSet::continue_with_vm_change(cash_change(
                gas_charge,
            )));
        }

        x.subtract_accumulator_balance(state_manager, amount)?;
        x.add_to_deferred_transfers(transfer);

        Ok(HostCallChangeSet::continue_with_vm_change(ok_change(
            gas_charge,
        )))
    }

    /// Halts the host call execution and optionally transfers tokens to the specified destination
    /// account, leaving (threshold balance - initial threshold balance) in the accumulator account.
    ///
    /// Upon a successful halt, The accumulating service account is removed from
    /// the accumulate context partial state.
    pub fn host_quit(
        target_address: Address,
        gas: UnsignedGas,
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let x = context.get_mut_accumulate_x()?;

        let dest = regs[7].value();
        let offset = regs[8].as_mem_address()?;

        // Halts with no transfer
        if dest == x.accumulate_host as u64 || dest == u64::MAX {
            x.remove_accumulator_account()?;
            return Ok(HostCallChangeSet::continue_with_vm_change(ok_change(
                BASE_GAS_CHARGE,
            )));
        }
        let dest = u32::try_from(dest).map_err(|_| PVMError::VMCoreError(InvalidRegVal))?;

        if !memory.is_address_range_readable(offset, TRANSFER_MEMO_SIZE)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        let memo = <[u8; TRANSFER_MEMO_SIZE]>::decode(
            &mut memory.read_bytes(offset, TRANSFER_MEMO_SIZE)?.as_slice(),
        )?;

        let accumulator_metadata = x.get_accumulator_metadata(state_manager)?;
        let amount =
            accumulator_metadata.balance() - accumulator_metadata.threshold_balance() + B_S;

        let transfer = DeferredTransfer {
            from: target_address,
            to: dest,
            amount,
            memo,
            gas_limit: gas,
        };

        // Check the state manager and the accumulate context partial state to confirm that the
        // destination account exists.
        let dest_on_transfer_gas_limit = match x
            .partial_state
            .accounts_sandbox
            .get_account_metadata(state_manager, dest)?
        {
            Some(metadata) => metadata.account_info.gas_limit_on_transfer,
            None => {
                return Ok(HostCallChangeSet::continue_with_vm_change(who_change(
                    BASE_GAS_CHARGE,
                )));
            }
        };

        if gas < dest_on_transfer_gas_limit {
            return Ok(HostCallChangeSet::continue_with_vm_change(low_change(
                BASE_GAS_CHARGE,
            )));
        }

        x.add_to_deferred_transfers(transfer);
        x.remove_accumulator_account()?;

        Ok(HostCallChangeSet {
            exit_reason: ExitReason::RegularHalt,
            vm_change: HostCallVMStateChange {
                gas_charge: BASE_GAS_CHARGE,
                r7_write: Some(HostCallResultConstant::OK as RegValue),
                ..Default::default()
            },
        })
    }

    /// Marks the accumulating account's lookup dictionary entry, which references a preimage entry
    /// that was previously available but is currently unavailable, as available again starting
    /// from the current timeslot.
    ///
    /// This is done by appending the current timeslot index to the timeslots vector of the
    /// lookup dictionary entry. It is asserted that the previous length of the vector is 2.
    pub fn host_solicit(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let x = context.get_mut_accumulate_x()?;

        let offset = regs[7].as_mem_address()?;
        let lookup_len = regs[8].as_u32()?;

        if !memory.is_address_range_readable(offset, HASH_SIZE)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        let lookup_hash = Hash32::decode(&mut memory.read_bytes(offset, HASH_SIZE)?.as_slice())?;
        let lookups_key = (lookup_hash, lookup_len);

        let prev_lookups_entry = x
            .partial_state
            .accounts_sandbox
            .get_or_load_account_lookups_entry(state_manager, x.accumulate_host, &lookups_key)?;

        let timeslot = state_manager.get_timeslot()?;

        // Insert current timeslot if the entry exists and the timeslot vector length is 2.
        // If the key doesn't exist, insert a new empty Vec<Timeslot> with the key.
        // If the entry's timeslot vector length is not equal to 2, return with result constant `HUH`.
        let new_lookups_entry = match prev_lookups_entry.clone() {
            Some(mut entry) => {
                if entry.value.len() != 2 {
                    return Ok(HostCallChangeSet::continue_with_vm_change(huh_change(
                        BASE_GAS_CHARGE,
                    )));
                }
                // Add current timeslot to the timeslot vector.
                entry.value.push(timeslot);
                entry
            }
            None => {
                // Add a new entry with an empty timeslot vector.
                AccountLookupsEntry { value: vec![] }
            }
        };

        // Construct `AccountLookupsOctetsUsage` types from the previous and the new entries.
        let prev_lookups_octets_usage = prev_lookups_entry.map(|p| AccountLookupsOctetsUsage {
            preimage_length: lookup_len,
            entry: p,
        });
        let new_lookups_octets_usage = AccountLookupsOctetsUsage {
            preimage_length: lookup_len,
            entry: new_lookups_entry.clone(),
        };

        // Simulate the threshold balance change
        let (lookups_items_count_delta, lookups_octets_count_delta) =
            AccountMetadata::calculate_storage_footprint_delta(
                prev_lookups_octets_usage.as_ref(),
                &new_lookups_octets_usage,
            )
            .ok_or(PVMError::StateManagerError(LookupsEntryNotFound))?;

        let accumulator_metadata = x.get_accumulator_metadata(state_manager)?;
        let simulated_threshold_balance = accumulator_metadata
            .simulate_threshold_balance_after_mutation(
                lookups_items_count_delta,
                0,
                lookups_octets_count_delta,
                0,
            );

        if simulated_threshold_balance > accumulator_metadata.balance() {
            return Ok(HostCallChangeSet::continue_with_vm_change(full_change(
                BASE_GAS_CHARGE,
            )));
        }

        // Apply the state change
        x.partial_state
            .accounts_sandbox
            .insert_account_lookups_entry(
                state_manager,
                x.accumulate_host,
                lookups_key,
                new_lookups_entry,
            )?;

        Ok(HostCallChangeSet::continue_with_vm_change(ok_change(
            BASE_GAS_CHARGE,
        )))
    }

    /// Removes a preimage from the accumulating account's preimage and lookups storage,
    /// or marks a lookups entry as unavailable by updating its timeslot vector.
    ///
    /// If the timeslot vector indicates the preimage is unavailable, remove the corresponding entries
    /// from both storages. Otherwise, mark the preimage as unavailable by appending the current timeslot
    /// to the timeslot vector.
    pub fn host_forget(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: &StateManager,
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let x = context.get_mut_accumulate_x()?;

        let offset = regs[7].as_mem_address()?;
        let lookup_len = regs[8].as_u32()?;

        if !memory.is_address_range_readable(offset, HASH_SIZE)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        let lookup_hash = Hash32::decode(&mut memory.read_bytes(offset, HASH_SIZE)?.as_slice())?;
        let lookups_key = (lookup_hash, lookup_len);
        let lookups_entry = x
            .partial_state
            .accounts_sandbox
            .get_or_load_account_lookups_entry(state_manager, x.accumulate_host, &lookups_key)?;

        let timeslot = state_manager.get_timeslot()?;
        let vm_state_change = match lookups_entry {
            None => huh_change(BASE_GAS_CHARGE),
            Some(entry) => {
                let lookups_timeslots = entry.value.clone();

                match lookups_timeslots.len() {
                    0 => {
                        // Remove preimage and lookups storage entry
                        x.partial_state
                            .accounts_sandbox
                            .remove_account_preimages_entry(
                                state_manager,
                                x.accumulate_host,
                                lookup_hash,
                            )?;
                        x.partial_state
                            .accounts_sandbox
                            .remove_account_lookups_entry(
                                state_manager,
                                x.accumulate_host,
                                lookups_key,
                            )?;
                        ok_change(BASE_GAS_CHARGE)
                    }
                    1 => {
                        // Add current timeslot to the lookups entry timeslot vector
                        x.partial_state
                            .accounts_sandbox
                            .push_timeslot_to_account_lookups_entry(
                                state_manager,
                                x.accumulate_host,
                                lookups_key,
                                timeslot,
                            )?;
                        ok_change(BASE_GAS_CHARGE)
                    }
                    len if len == 2 || len == 3 => {
                        let is_expired = lookups_timeslots[1].slot()
                            < timeslot.slot() - PREIMAGE_EXPIRATION_PERIOD;
                        if is_expired {
                            if len == 2 {
                                // Remove preimage and lookups storage entry
                                x.partial_state
                                    .accounts_sandbox
                                    .remove_account_preimages_entry(
                                        state_manager,
                                        x.accumulate_host,
                                        lookup_hash,
                                    )?;
                                x.partial_state
                                    .accounts_sandbox
                                    .remove_account_lookups_entry(
                                        state_manager,
                                        x.accumulate_host,
                                        lookups_key,
                                    )?;
                            } else {
                                let prev_last_timeslot = lookups_timeslots.last().cloned().unwrap(); // Not empty at this point
                                x.partial_state
                                    .accounts_sandbox
                                    .drain_account_lookups_entry_timeslots(
                                        state_manager,
                                        x.accumulate_host,
                                        lookups_key,
                                    )?;
                                x.partial_state
                                    .accounts_sandbox
                                    .extend_timeslots_to_account_lookups_entry(
                                        state_manager,
                                        x.accumulate_host,
                                        lookups_key,
                                        vec![prev_last_timeslot, timeslot],
                                    )?;
                            }
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

    /// Performs a historical preimage lookup for the specified account and hash,
    /// retrieving the preimage data if available.
    ///
    /// This is the only stateful operation in the refinement process and allows auditors to access
    /// states required for execution of the refinement through historical lookups.
    pub fn host_historical_lookup(
        refine_account_address: Address,
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        context: &mut InvocationContext,
        state_manager: &StateManager,
    ) -> Result<HostCallChangeSet, PVMError> {
        let x = context.get_mut_refine_x()?;

        let account_address_reg = regs[7].value();
        let lookup_hash_offset = regs[8].as_mem_address()?;
        let buffer_offset = regs[9].as_mem_address()?;
        let buffer_size = regs[10].as_usize()?;

        let account_address = if account_address_reg == u64::MAX
            || state_manager.account_exists(refine_account_address)?
        {
            refine_account_address
        } else if state_manager.account_exists(regs[7].as_account_address()?)? {
            regs[7].as_account_address()?
        } else {
            return Ok(HostCallChangeSet::continue_with_vm_change(none_change(
                BASE_GAS_CHARGE,
            )));
        };

        if !memory.is_address_range_readable(lookup_hash_offset, HASH_SIZE)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        let lookup_hash =
            Hash32::decode(&mut memory.read_bytes(lookup_hash_offset, HASH_SIZE)?.as_slice())?;

        let preimage = state_manager.lookup_preimage(
            account_address,
            &Timeslot::new(x.lookup_anchor_timeslot),
            &lookup_hash,
        )?;

        if let Some(preimage) = preimage {
            let write_data_size = buffer_size.min(preimage.len());

            if !memory.is_address_range_writable(buffer_offset, buffer_size)? {
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

    /// Fetches the import segment of the specified index from the ImportDA common storage and
    /// writes it into memory.
    pub fn host_import(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let x = context.get_mut_refine_x()?;

        let import_segment_index = regs[7].as_usize()?;
        let offset = regs[8].as_mem_address()?;
        let segment_len = regs[9].as_usize()?;

        if x.import_segments.len() <= import_segment_index {
            return Ok(HostCallChangeSet::continue_with_vm_change(none_change(
                BASE_GAS_CHARGE,
            )));
        }
        let import_segment = x.import_segments[import_segment_index].clone();

        let segment_read_len = segment_len.min(DATA_SEGMENTS_SIZE);

        if !memory.is_address_range_writable(offset, segment_read_len)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        Ok(HostCallChangeSet::continue_with_vm_change(
            HostCallVMStateChange {
                gas_charge: BASE_GAS_CHARGE,
                r7_write: Some(HostCallResultConstant::OK as RegValue),
                memory_write: (offset, segment_read_len as u32, import_segment.to_vec()),
                ..Default::default()
            },
        ))
    }

    /// Appends an entry to the export segments vector using the value loaded from memory.
    /// This export segments vector will be written to the ImportDA after the successful execution
    /// of the refinement process.
    pub fn host_export(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let x = context.get_mut_refine_x()?;

        let offset = regs[7].as_mem_address()?;
        let size = regs[8].as_usize()?;

        let export_segment_size = size.min(DATA_SEGMENTS_SIZE);

        if !memory.is_address_range_readable(offset, export_segment_size)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        let next_export_segments_offset = x.export_segments.len() + x.export_segments_offset;
        if next_export_segments_offset >= IMPORT_EXPORT_SEGMENTS_LENGTH_LIMIT {
            return Ok(HostCallChangeSet::continue_with_vm_change(full_change(
                BASE_GAS_CHARGE,
            )));
        }

        let data_segment: ExportDataSegment = zero_pad_as_array::<DATA_SEGMENTS_SIZE>(
            memory.read_bytes(offset, export_segment_size)?,
        )
        .ok_or(PVMError::HostCallError(DataSegmentTooLarge))?;

        x.export_segments.push(data_segment);
        x.export_segments_offset = next_export_segments_offset;

        Ok(HostCallChangeSet::continue_with_vm_change(
            HostCallVMStateChange {
                gas_charge: BASE_GAS_CHARGE,
                r7_write: Some(next_export_segments_offset as RegValue),
                ..Default::default()
            },
        ))
    }

    /// Initializes an inner VM with the specified program and sets the initial program counter value.
    ///
    /// The inner VM's memory is initialized with all cells set to zero and all pages marked as
    /// `Inaccessible`.
    pub fn host_machine(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let x = context.get_mut_refine_x()?;

        let program_offset = regs[7].as_mem_address()?;
        let program_size = regs[8].as_usize()?;
        let initial_pc = regs[9].value();

        if !memory.is_address_range_readable(program_offset, program_size)? {
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

    /// Peeks data from the inner VM memory and copies it to the external host VM memory.
    ///
    /// This function reads data from the memory of the inner VM at the specified index
    /// ands write it to the memory of the external host VM.
    pub fn host_peek(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let x = context.get_mut_refine_x()?;

        let inner_vm_id = regs[7].as_usize()?;
        let memory_offset = regs[8].as_mem_address()?;
        let inner_memory_offset = regs[9].as_mem_address()?;
        let data_len = regs[10].as_usize()?;

        let inner_memory = if let Some(inner_memory) = x.get_inner_vm_memory(inner_vm_id) {
            inner_memory
        } else {
            return Ok(HostCallChangeSet::continue_with_vm_change(who_change(
                BASE_GAS_CHARGE,
            )));
        };

        if !inner_memory.is_address_range_readable(inner_memory_offset, data_len)?
            || !memory.is_address_range_writable(memory_offset, data_len)?
        {
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

    /// Pokes data into the memory of the inner VM from the external host VM memory.
    ///
    /// This function writes data to the memory of the inner VM at the specified index,
    /// copying it from the memory of the external host VM.
    pub fn host_poke(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let x = context.get_mut_refine_x()?;

        let inner_vm_id = regs[7].as_usize()?;
        let memory_offset = regs[8].as_mem_address()?;
        let inner_memory_offset = regs[9].as_mem_address()?;
        let data_len = regs[10].as_usize()?;

        let inner_memory_mut =
            if let Some(inner_memory_mut) = x.get_mut_inner_vm_memory(inner_vm_id) {
                inner_memory_mut
            } else {
                return Ok(HostCallChangeSet::continue_with_vm_change(who_change(
                    BASE_GAS_CHARGE,
                )));
            };

        if !memory.is_address_range_readable(memory_offset, data_len)?
            || !inner_memory_mut.is_address_range_writable(inner_memory_offset, data_len)?
        {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }
        let data = memory.read_bytes(memory_offset, data_len)?;

        inner_memory_mut.write_bytes(inner_memory_offset as MemAddress, &data)?;

        Ok(HostCallChangeSet::continue_with_vm_change(ok_change(
            BASE_GAS_CHARGE,
        )))
    }

    /// Sets the specified range of pages in the inner VM's memory to zero
    /// and marks the pages as `ReadWrite`.
    pub fn host_zero(
        regs: &[Register; REGISTERS_COUNT],
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let x = context.get_mut_refine_x()?;

        let inner_vm_id = regs[7].as_usize()?;
        let inner_memory_page_offset = regs[8].as_usize()?;
        let pages_count = regs[9].as_usize()?;

        if inner_memory_page_offset < 16
            || inner_memory_page_offset + pages_count >= (1 << 32) / PAGE_SIZE
        {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        let inner_memory_mut =
            if let Some(inner_memory_mut) = x.get_mut_inner_vm_memory(inner_vm_id) {
                inner_memory_mut
            } else {
                return Ok(HostCallChangeSet::continue_with_vm_change(who_change(
                    BASE_GAS_CHARGE,
                )));
            };

        // set values
        let address_offset = (inner_memory_page_offset * PAGE_SIZE) as MemAddress;
        let data_len = pages_count * PAGE_SIZE;
        let data = vec![0u8; data_len];
        inner_memory_mut.write_bytes(address_offset, &data)?;

        // set access types
        let page_start = inner_memory_page_offset;
        let page_end = inner_memory_page_offset + pages_count;
        inner_memory_mut.set_page_range_access(page_start..page_end, AccessType::ReadWrite)?;

        Ok(HostCallChangeSet::continue_with_vm_change(ok_change(
            BASE_GAS_CHARGE,
        )))
    }

    /// Sets the specified range of pages in the inner VM's memory to zero
    /// and marks the pages as `Inaccessible`.
    pub fn host_void(
        regs: &[Register; REGISTERS_COUNT],
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let x = context.get_mut_refine_x()?;

        let inner_vm_id = regs[7].as_usize()?;
        let inner_memory_page_offset = regs[8].as_usize()?;
        let pages_count = regs[9].as_usize()?;

        let inner_memory_mut =
            if let Some(inner_memory_mut) = x.get_mut_inner_vm_memory(inner_vm_id) {
                inner_memory_mut
            } else {
                return Ok(HostCallChangeSet::continue_with_vm_change(who_change(
                    BASE_GAS_CHARGE,
                )));
            };

        let page_start = inner_memory_page_offset;
        let page_end = inner_memory_page_offset + pages_count;
        // TODO: Check the GP's range validation rule here
        if inner_memory_page_offset < 16
            || inner_memory_page_offset + pages_count >= (1 << 32) / PAGE_SIZE
            || !inner_memory_mut.is_page_range_readable(page_start..page_end)?
        {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        // set values
        let address_offset = (inner_memory_page_offset * PAGE_SIZE) as MemAddress;
        let data_len = pages_count * PAGE_SIZE;
        let data = vec![0u8; data_len];
        inner_memory_mut.write_bytes(address_offset, &data)?;

        // set access types
        inner_memory_mut.set_page_range_access(page_start..page_end, AccessType::Inaccessible)?;

        Ok(HostCallChangeSet::continue_with_vm_change(ok_change(
            BASE_GAS_CHARGE,
        )))
    }

    /// Invokes the inner VM with its program using the PVM general invocation function.
    ///
    /// The gas limit and initial register values for the inner VM are read from the memory of the host VM.
    /// Upon completion, the posterior state (e.g., gas counter, memory, registers) of the inner VM is
    /// written back to the memory of the host VM, while the final state of the inner VM's memory
    /// is preserved within the inner VM.
    pub fn host_invoke(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let x = context.get_mut_refine_x()?;

        let inner_vm_id = regs[7].as_usize()?;
        let memory_offset = regs[8].as_mem_address()?;

        if !memory.is_address_range_writable(memory_offset, 60)? {
            return Ok(HostCallChangeSet::continue_with_vm_change(oob_change(
                BASE_GAS_CHARGE,
            )));
        }

        let inner_vm_mut = if let Some(inner_vm_mut) = x.pvm_instances.get_mut(&inner_vm_id) {
            inner_vm_mut
        } else {
            return Ok(HostCallChangeSet::continue_with_vm_change(who_change(
                BASE_GAS_CHARGE,
            )));
        };

        let gas =
            UnsignedGas::decode_fixed(&mut memory.read_bytes(memory_offset, 8)?.as_slice(), 8)?;

        let mut regs = [Register::default(); REGISTERS_COUNT];
        for (i, register) in regs.iter_mut().enumerate() {
            register.value = RegValue::decode_fixed(
                &mut memory
                    .read_bytes(memory_offset + 8 + 4 * i as MemAddress, 4)?
                    .as_slice(),
                4,
            )?;
        }

        // Construct a new `VMState` and `ProgramState` for the general invocation function.
        let mut inner_vm_state_copy = VMState {
            registers: regs,
            memory: inner_vm_mut.memory.clone(), // TODO: reduce unnecessary copies
            pc: inner_vm_mut.pc,
            gas_counter: gas,
        };
        let inner_vm_program_code = &inner_vm_mut.program_code;
        let mut inner_vm_program_state = ProgramState::default();

        let inner_vm_exit_reason = PVMCore::general_invocation(
            &mut inner_vm_state_copy,
            &mut inner_vm_program_state,
            inner_vm_program_code,
        )?;

        // Apply the mutation of the `VMState` to the InnerVM state of the refine context
        inner_vm_mut.pc = inner_vm_state_copy.pc;
        inner_vm_mut.memory = inner_vm_state_copy.memory;

        let mut write_data = vec![];
        inner_vm_state_copy
            .gas_counter
            .encode_to_fixed(&mut write_data, 8)?;
        for reg in inner_vm_state_copy.registers {
            reg.value.encode_to_fixed(&mut write_data, 4)?;
        }

        match inner_vm_exit_reason {
            ExitReason::HostCall(host_call_type) => {
                inner_vm_mut.pc += 1;
                Ok(HostCallChangeSet::continue_with_vm_change(
                    HostCallVMStateChange {
                        gas_charge: BASE_GAS_CHARGE,
                        r7_write: Some(HOST as RegValue),
                        r8_write: Some(host_call_type as RegValue),
                        memory_write: (memory_offset, 60, write_data),
                    },
                ))
            }
            ExitReason::PageFault(address) => Ok(HostCallChangeSet::continue_with_vm_change(
                HostCallVMStateChange {
                    gas_charge: BASE_GAS_CHARGE,
                    r7_write: Some(FAULT as RegValue),
                    r8_write: Some(address as RegValue),
                    memory_write: (memory_offset, 60, write_data),
                },
            )),
            ExitReason::OutOfGas => Ok(HostCallChangeSet::continue_with_vm_change(
                HostCallVMStateChange {
                    gas_charge: BASE_GAS_CHARGE,
                    r7_write: Some(OOG as RegValue),
                    r8_write: None,
                    memory_write: (memory_offset, 60, write_data),
                },
            )),
            ExitReason::Panic => Ok(HostCallChangeSet::continue_with_vm_change(
                HostCallVMStateChange {
                    gas_charge: BASE_GAS_CHARGE,
                    r7_write: Some(PANIC as RegValue),
                    r8_write: None,
                    memory_write: (memory_offset, 60, write_data),
                },
            )),
            ExitReason::RegularHalt => Ok(HostCallChangeSet::continue_with_vm_change(
                HostCallVMStateChange {
                    gas_charge: BASE_GAS_CHARGE,
                    r7_write: Some(HALT as RegValue),
                    r8_write: None,
                    memory_write: (memory_offset, 60, write_data),
                },
            )),

            _ => Err(PVMError::HostCallError(InvalidExitReason)),
        }
    }

    /// Removes an inner VM instance from the refine context.
    pub fn host_expunge(
        regs: &[Register; REGISTERS_COUNT],
        context: &mut InvocationContext,
    ) -> Result<HostCallChangeSet, PVMError> {
        let x = context.get_mut_refine_x()?;

        let inner_vm_id = regs[7].as_usize()?;

        let final_pc = if let Some(inner_vm) = x.pvm_instances.get(&inner_vm_id) {
            inner_vm.pc
        } else {
            return Ok(HostCallChangeSet::continue_with_vm_change(who_change(
                BASE_GAS_CHARGE,
            )));
        };

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
