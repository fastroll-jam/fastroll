use crate::{
    context::types::InvocationContext, continue_cash, continue_core, continue_full, continue_huh,
    continue_low, continue_none, continue_ok, continue_oob, continue_what, continue_who,
    continue_with_vm_change, get_mut_accounts_sandbox, get_mut_accumulate_x, get_mut_refine_x,
    get_refine_x, host_call_panic, host_functions::InnerPVMResultConstant::*, inner_vm::InnerPVM,
    utils::zero_pad_as_array,
};
use rjam_codec::{JamDecode, JamDecodeFixed, JamEncode, JamEncodeFixed};
use rjam_common::*;
use rjam_crypto::{hash, octets_to_hash32, Blake2b256};
use rjam_pvm_core::{
    constants::*,
    core::{PVMCore, VMState},
    program::program_decoder::{ProgramDecoder, ProgramState},
    state::{
        memory::{AccessType, MemAddress, Memory},
        register::Register,
    },
    types::{
        common::{ExitReason, ExportDataSegment, RegValue},
        error::{HostCallError::*, PVMError},
    },
};
use rjam_state::{
    error::StateManagerError::{LookupsEntryNotFound, StorageEntryNotFound},
    StateManager,
};
use rjam_types::{common::transfers::DeferredTransfer, state::*};
use std::{collections::HashMap, sync::Arc};

#[repr(u64)]
pub enum HostCallReturnCode {
    NONE = u64::MAX,     // An item does not exist.
    WHAT = u64::MAX - 1, // Name unknown.
    OOB = u64::MAX - 2, // The inner PVM memory index provided for reading/writing is not accessible.
    WHO = u64::MAX - 3, // Index unknown.
    FULL = u64::MAX - 4, // Storage full.
    CORE = u64::MAX - 5, // Core index unknown.
    CASH = u64::MAX - 6, // Insufficient funds.
    LOW = u64::MAX - 7, // Gas limit too low.
    HUH = u64::MAX - 8, // The item is already solicited or cannot be forgotten.
    OK = 0,             // The return value indicating general success.
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
pub struct HostCallResult {
    pub exit_reason: ExitReason,
    pub vm_change: HostCallVMStateChange,
}

impl HostCallResult {
    fn continue_with_vm_change(vm_change: HostCallVMStateChange) -> Self {
        Self {
            exit_reason: ExitReason::Continue,
            vm_change,
        }
    }

    pub fn continue_with_return_code(code: HostCallReturnCode) -> Self {
        Self {
            exit_reason: ExitReason::Continue,
            vm_change: HostCallVMStateChange {
                gas_charge: BASE_GAS_CHARGE,
                r7_write: Some(code as RegValue),
                ..Default::default()
            },
        }
    }

    pub fn continue_with_return_code_and_gas(
        code: HostCallReturnCode,
        gas_charge: UnsignedGas,
    ) -> Self {
        Self {
            exit_reason: ExitReason::Continue,
            vm_change: HostCallVMStateChange {
                gas_charge,
                r7_write: Some(code as RegValue),
                ..Default::default()
            },
        }
    }

    pub fn panic() -> Self {
        Self {
            exit_reason: ExitReason::Panic,
            vm_change: Default::default(),
        }
    }

    pub fn panic_with_gas(gas_charge: UnsignedGas) -> Self {
        Self {
            exit_reason: ExitReason::Panic,
            vm_change: HostCallVMStateChange {
                gas_charge,
                ..Default::default()
            },
        }
    }
}

#[derive(Clone)]
pub struct MemWrite {
    pub buf_offset: MemAddress,
    pub write_len: u32,
    pub write_data: Vec<u8>,
}

impl MemWrite {
    pub fn new(buf_offset: MemAddress, write_len: u32, write_data: Vec<u8>) -> Self {
        Self {
            buf_offset,
            write_len,
            write_data,
        }
    }
}

/// Represents the state changes in the PVM resulting from a single host function execution.
pub struct HostCallVMStateChange {
    pub gas_charge: UnsignedGas,
    pub r7_write: Option<RegValue>,
    pub r8_write: Option<RegValue>,
    pub memory_write: Option<MemWrite>, // (start_address, data_len, data)
}

impl Default for HostCallVMStateChange {
    fn default() -> Self {
        Self {
            gas_charge: BASE_GAS_CHARGE,
            r7_write: None,
            r8_write: None,
            memory_write: None,
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
    pub fn host_gas(gas: UnsignedGas) -> Result<HostCallResult, PVMError> {
        // FIXME: `gas_remaining` should be of type `i64`. Explicit conversion might be needed.
        let gas_remaining = gas.wrapping_sub(BASE_GAS_CHARGE);

        continue_with_vm_change!(r7: gas_remaining)
    }

    /// Fetches the preimage of the specified hash from the given service account's preimage storage
    /// and writes it into memory.
    pub async fn host_lookup(
        service_id: ServiceId,
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: Arc<StateManager>,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let accounts_sandbox = get_mut_accounts_sandbox!(context);

        let service_id_reg = regs[7].value();
        let hash_offset = regs[8].as_mem_address()?; // h
        let buf_offset = regs[9].as_mem_address()?; // o

        let service_id = if service_id_reg == u64::MAX || service_id_reg == service_id as u64 {
            service_id
        } else {
            service_id_reg as ServiceId
        };

        if !memory.is_address_range_readable(hash_offset, 32)? {
            return host_call_panic!();
        }

        // Read preimage storage key (hash) from the memory
        let hash = octets_to_hash32(&memory.read_bytes(hash_offset, 32)?)
            .expect("Should not fail to convert 32-byte octets to Hash32 type");

        if let Some(entry) = accounts_sandbox
            .get_account_preimages_entry(state_manager, service_id, &hash)
            .await?
        {
            let preimage_size = entry.value.len();
            let preimage_offset = regs[10].as_usize()?.min(preimage_size); // f
            let lookup_size = regs[11].as_usize()?.min(preimage_size - preimage_offset); // l

            if !memory.is_address_range_writable(buf_offset, lookup_size)? {
                return host_call_panic!();
            }

            continue_with_vm_change!(
                r7: preimage_size,
                mem_offset: buf_offset,
                mem_size: lookup_size,
                mem_data: entry.value[preimage_offset..preimage_offset + lookup_size].to_vec()
            )
        } else {
            continue_none!()
        }
    }

    /// Fetches the storage entry value of the specified storage key from the given service account's
    /// storage and writes it into memory.
    pub async fn host_read(
        service_id: ServiceId,
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: Arc<StateManager>,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let accounts_sandbox = get_mut_accounts_sandbox!(context);

        let service_id_reg = regs[7].value();
        let key_offset = regs[8].as_mem_address()?; // k_o
        let key_size = regs[9].as_usize()?; // k_z
        let buf_offset = regs[10].as_mem_address()?; // o

        let service_id = if service_id_reg == u64::MAX {
            service_id
        } else {
            service_id_reg as ServiceId
        };

        if !memory.is_address_range_readable(key_offset, key_size)? {
            return host_call_panic!();
        }

        let mut key = service_id.encode_fixed(4)?;
        key.extend(memory.read_bytes(key_offset, key_size)?);
        let storage_key = hash::<Blake2b256>(&key)?;

        if let Some(entry) = accounts_sandbox
            .get_account_storage_entry(state_manager, service_id, &storage_key)
            .await?
        {
            let storage_val_size = entry.value.len();
            let storage_val_offset = regs[11].as_usize()?.min(storage_val_size); // f
            let read_len = regs[12]
                .as_usize()?
                .min(storage_val_size - storage_val_offset); // l

            if !memory.is_address_range_writable(buf_offset, read_len)? {
                return host_call_panic!();
            }

            continue_with_vm_change!(
                r7: storage_val_size,
                mem_offset: buf_offset,
                mem_size: storage_val_size,
                mem_data: entry.value[storage_val_offset..storage_val_offset + read_len].to_vec()
            )
        } else {
            continue_none!()
        }
    }

    /// Writes an entry to the storage of the service account hosting the code being executed,
    /// using a key and value read from the memory.
    /// If the value size is zero, the entry corresponding to the key is removed.
    /// The size of the previous value, if any, is returned via the register.
    pub async fn host_write(
        service_id: ServiceId,
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: Arc<StateManager>,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let accounts_sandbox = get_mut_accounts_sandbox!(context);

        let key_offset = regs[7].as_mem_address()?; // k_o
        let key_size = regs[8].as_usize()?; // k_z
        let value_offset = regs[9].as_mem_address()?; // v_o
        let value_size = regs[10].as_usize()?; // v_z

        if !memory.is_address_range_readable(key_offset, key_size)?
            || (value_size > 0 && !memory.is_address_range_readable(value_offset, value_size)?)
        {
            return host_call_panic!();
        }

        let mut key = service_id.encode_fixed(4)?;
        key.extend(memory.read_bytes(key_offset, key_size)?);
        let storage_key = hash::<Blake2b256>(&key)?;

        // Threshold balance change simulation
        let maybe_prev_storage_entry = accounts_sandbox
            .get_account_storage_entry(state_manager.clone(), service_id, &storage_key)
            .await?;

        let prev_storage_val_size_or_return_code = if let Some(ref entry) = maybe_prev_storage_entry
        {
            entry.value.len() as u64
        } else {
            HostCallReturnCode::NONE as u64
        };

        let new_storage_entry = if value_size == 0 {
            None
        } else {
            Some(AccountStorageEntry {
                value: Octets::from_vec(memory.read_bytes(value_offset, value_size)?),
            })
        };

        let (storage_items_count_delta, storage_octets_count_delta) =
            AccountMetadata::calculate_storage_footprint_delta(
                maybe_prev_storage_entry.as_ref(),
                new_storage_entry.as_ref(),
            )
            .ok_or(PVMError::StateManagerError(StorageEntryNotFound))?;

        let account_metadata = accounts_sandbox
            .get_account_metadata(state_manager.clone(), service_id)
            .await?
            .ok_or(PVMError::HostCallError(AccountNotFound))?;

        let simulated_threshold_balance = account_metadata
            .simulate_threshold_balance_after_mutation(
                0,
                storage_items_count_delta,
                0,
                storage_octets_count_delta,
            );

        if simulated_threshold_balance > account_metadata.account_info.balance {
            return continue_full!();
        }

        // Apply the state change
        if let Some(new_entry) = new_storage_entry {
            accounts_sandbox
                .insert_account_storage_entry(state_manager, service_id, storage_key, new_entry)
                .await?;
        } else {
            // Remove the entry if the size of the new entry value is zero
            accounts_sandbox
                .remove_account_storage_entry(state_manager, service_id, storage_key)
                .await?;
        }

        continue_with_vm_change!(r7: prev_storage_val_size_or_return_code)
    }

    /// Retrieves the metadata of the specified account in a serialized format.
    pub async fn host_info(
        service_id: ServiceId,
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: Arc<StateManager>,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let accounts_sandbox = get_mut_accounts_sandbox!(context);

        let service_id_reg = regs[7].value();
        let buf_offset = regs[8].as_mem_address()?; // o

        let service_id = if service_id_reg == u64::MAX {
            service_id
        } else {
            service_id_reg as ServiceId
        };

        let account_metadata = if let Some(metadata) = accounts_sandbox
            .get_account_metadata(state_manager, service_id)
            .await?
        {
            metadata
        } else {
            return continue_none!();
        };

        // Encode account metadata with JAM Codec
        let info = account_metadata.encode_for_info_hostcall()?;

        if !memory.is_address_range_writable(buf_offset, info.len())? {
            return continue_oob!();
        }

        continue_with_vm_change!(
            r7: HostCallReturnCode::OK,
            mem_offset: buf_offset,
            mem_size: info.len(),
            mem_data: info
        )
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
    ) -> Result<HostCallResult, PVMError> {
        let x = get_mut_accumulate_x!(context);

        let (manager, assign, designate) = match (
            regs[7].as_service_id(),
            regs[8].as_service_id(),
            regs[9].as_service_id(),
        ) {
            (Ok(manager), Ok(assign), Ok(designate)) => (manager, assign, designate),
            _ => {
                return continue_who!();
            }
        };

        let offset = regs[10].as_mem_address()?; // o
        let always_accumulates_count = regs[11].as_usize()?; // n

        if !memory.is_address_range_readable(offset, 12 * always_accumulates_count)? {
            return host_call_panic!();
        }

        let mut always_accumulate_services = HashMap::with_capacity(always_accumulates_count);

        for i in 0..always_accumulates_count {
            let always_accumulate_serialized =
                memory.read_bytes(offset + 12 * i as MemAddress, 12)?;
            let address = u32::decode_fixed(&mut always_accumulate_serialized.as_slice(), 4)?;
            let basic_gas = u64::decode_fixed(&mut always_accumulate_serialized.as_slice(), 8)?;
            always_accumulate_services.insert(address, basic_gas);
        }

        x.assign_new_privileged_services(manager, assign, designate, always_accumulate_services)?;

        continue_ok!()
    }

    /// Assigns `MAX_AUTH_QUEUE_SIZE` new authorizers to the `AuthQueue` of the specified core
    /// in the accumulate context partial state.
    pub fn host_assign(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let x = get_mut_accumulate_x!(context);

        let core_index = regs[7].as_usize()?;
        let offset = regs[8].as_mem_address()?; // o

        if !memory.is_address_range_readable(offset, HASH_SIZE * MAX_AUTH_QUEUE_SIZE)? {
            return host_call_panic!();
        }

        if core_index >= CORE_COUNT {
            return continue_core!();
        }

        let mut queue_assignment = AuthQueue::default();
        for i in 0..MAX_AUTH_QUEUE_SIZE {
            let authorizer =
                memory.read_bytes(offset + (HASH_SIZE * i) as MemAddress, HASH_SIZE)?;
            queue_assignment.0[core_index][i] = Hash32::decode(&mut authorizer.as_slice())?;
        }

        x.assign_new_auth_queue(queue_assignment)?;

        continue_ok!()
    }

    /// Assigns `VALIDATOR_COUNT` new validators to the `StagingSet` in the accumulate context partial state.
    pub fn host_designate(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let x = get_mut_accumulate_x!(context);

        let offset = regs[7].as_mem_address()?; // o

        if !memory.is_address_range_readable(offset, PUBLIC_KEY_SIZE * VALIDATOR_COUNT)? {
            return host_call_panic!();
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

        continue_ok!()
    }

    /// Copies a snapshot of the current accumulate context state into
    /// the checkpoint context of the context pair.
    pub fn host_checkpoint(
        gas: UnsignedGas,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let (x_cloned, y_mut) = match (
            context.get_accumulate_x().cloned(),
            context.get_mut_accumulate_y(),
        ) {
            (Some(x_cloned), Some(y_mut)) => (x_cloned, y_mut),
            _ => return continue_what!(),
        };

        *y_mut = x_cloned; // assign the cloned `x` context to the `y` context

        // If execution of this function results in `ExitReason::OutOfGas`,
        // returns zero value for the remaining gas limit.
        let post_gas = gas.saturating_sub(BASE_GAS_CHARGE);

        continue_with_vm_change!(r7: post_gas)
    }

    /// Creates a new service account with an address derived from the hash of
    /// the accumulate host address, the current epochal entropy, and the block timeslot index.
    ///
    /// The code hash is loaded into memory, and the two gas limits are provided as arguments in registers.
    ///
    /// The account storage and lookup dictionary are initialized as empty.
    pub async fn host_new(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: Arc<StateManager>,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let x = get_mut_accumulate_x!(context);

        let offset = regs[7].as_mem_address()?; // o
        let code_lookup_len = regs[8].as_u32()?; // l
        let gas_limit_g = regs[9].value(); // g
        let gas_limit_m = regs[10].value(); // m

        if !memory.is_address_range_readable(offset, HASH_SIZE)? {
            return host_call_panic!();
        }

        let code_hash = Hash32::decode(&mut memory.read_bytes(offset, HASH_SIZE)?.as_slice())?;
        let new_account_threshold_balance =
            AccountMetadata::get_initial_threshold_balance(code_lookup_len);

        // Check if the accumulate host service account's balance is sufficient
        // and subtract by the initial threshold balance to be transferred to the new account.
        let accumulator_metadata = x.get_accumulator_metadata(state_manager.clone()).await?;
        let accumulator_balance = accumulator_metadata.balance();
        let accumulator_threshold_balance = accumulator_metadata.threshold_balance();

        if accumulator_balance.saturating_sub(accumulator_threshold_balance)
            < new_account_threshold_balance
        {
            return continue_cash!();
        }

        x.subtract_accumulator_balance(state_manager.clone(), new_account_threshold_balance)
            .await?;

        // Add a new account to the partial state
        let new_service_id = x
            .add_new_account(
                state_manager.clone(),
                AccountInfo {
                    code_hash,
                    balance: new_account_threshold_balance,
                    gas_limit_accumulate: gas_limit_g,
                    gas_limit_on_transfer: gas_limit_m,
                },
                (code_hash, code_lookup_len),
            )
            .await?;

        // Update the next new service account index in the partial state
        x.rotate_new_account_index(state_manager).await?;

        continue_with_vm_change!(r7: new_service_id)
    }

    /// Upgrades three metadata fields of the accumulating service account:
    /// code hash ahs gas limits for accumulate & on-transfer.
    pub async fn host_upgrade(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: Arc<StateManager>,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let x = get_mut_accumulate_x!(context);

        let offset = regs[7].as_mem_address()?; // o
        let gas_limit_g = regs[8].value(); // g
        let gas_limit_m = regs[9].value(); // m

        if !memory.is_address_range_readable(offset, HASH_SIZE)? {
            return host_call_panic!();
        }

        let code_hash = Hash32::decode(&mut memory.read_bytes(offset, HASH_SIZE)?.as_slice())?;

        x.update_accumulator_metadata(state_manager, code_hash, gas_limit_g, gas_limit_m)
            .await?;

        continue_ok!()
    }

    /// Transfers tokens from the accumulating service account to another service account.
    pub async fn host_transfer(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: Arc<StateManager>,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let x = get_mut_accumulate_x!(context);

        let dest = regs[7].as_service_id()?; // d
        let amount = regs[8].value(); // a
        let gas_limit = regs[9].value(); // l
        let offset = regs[10].as_mem_address()?; // o
        let gas_charge = BASE_GAS_CHARGE + gas_limit;

        if !memory.is_address_range_readable(offset, TRANSFER_MEMO_SIZE)? {
            return host_call_panic!(gas_charge);
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

        let accumulator_metadata = x.get_accumulator_metadata(state_manager.clone()).await?;
        let accumulator_balance = accumulator_metadata.balance();
        let accumulator_threshold_balance = accumulator_metadata.threshold_balance();

        // Check the global state and the accumulate context partial state to confirm that the
        // destination account exists.
        let dest_account_info = match x
            .partial_state
            .accounts_sandbox
            .get_account_metadata(state_manager.clone(), dest)
            .await?
        {
            Some(metadata) => &metadata.account_info,
            None => {
                return continue_who!(gas_charge);
            }
        };

        if gas_limit < dest_account_info.gas_limit_on_transfer {
            return continue_low!(gas_charge);
        }

        if accumulator_balance.saturating_sub(amount) < accumulator_threshold_balance {
            return continue_cash!(gas_charge);
        }

        x.subtract_accumulator_balance(state_manager, amount)
            .await?;
        x.add_to_deferred_transfers(transfer);

        continue_ok!(gas_charge)
    }

    /// Completely removes a service account from the global state.
    pub async fn host_eject(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: Arc<StateManager>,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let x = get_mut_accumulate_x!(context);

        let eject_address = regs[7].as_service_id()?; // d
        let offset = regs[8].as_mem_address()?; // o

        if !memory.is_address_range_readable(offset, HASH_SIZE)? {
            return host_call_panic!();
        }
        let preimage_hash = Hash32::decode(&mut memory.read_bytes(offset, HASH_SIZE)?.as_slice())?;

        if eject_address == x.accumulate_host {
            return continue_who!();
        }

        let eject_account_metadata = match x
            .partial_state
            .accounts_sandbox
            .get_account_metadata(state_manager.clone(), eject_address)
            .await?
        {
            Some(metadata) => metadata.clone(),
            None => {
                return continue_who!();
            }
        };

        let accumulate_host_as_hash = octets_to_hash32(&x.accumulate_host.encode_fixed(32)?)
            .expect("Should not fail convert 32-byte octets into Hash32");
        if eject_account_metadata.account_info.code_hash != accumulate_host_as_hash {
            return continue_who!();
        }

        // TODO: safe type casting
        let preimage_size = 81.max(eject_account_metadata.total_octets_footprint() as u32) - 81;
        if eject_account_metadata.item_counts_footprint() != 2 {
            return continue_huh!();
        }
        let lookups_key = (preimage_hash, preimage_size);

        // FIXME: use header timeslot value instead
        if let Some(entry) = x
            .partial_state
            .accounts_sandbox
            .get_account_lookups_entry(state_manager.clone(), eject_address, &lookups_key)
            .await?
        {
            let curr_timeslot = state_manager.get_timeslot().await?.slot();
            if entry.value.len() == 2
                && entry.value[1].slot() < curr_timeslot - PREIMAGE_EXPIRATION_PERIOD
            {
                x.add_accumulator_balance(state_manager.clone(), eject_account_metadata.balance())
                    .await?;
                x.partial_state
                    .accounts_sandbox
                    .eject_account(state_manager, eject_address)
                    .await?;

                return continue_ok!();
            }
        }

        continue_huh!()
    }

    /// Queries the lookups storage's timeslot scopes to determine the availability of a preimage entry.
    pub async fn host_query(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: Arc<StateManager>,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let x = get_mut_accumulate_x!(context);

        let offset = regs[7].as_mem_address()?; // o
        let preimage_size = regs[8].as_u32()?; // z

        if !memory.is_address_range_readable(offset, HASH_SIZE)? {
            return host_call_panic!();
        }
        let preimage_hash = Hash32::decode(&mut memory.read_bytes(offset, HASH_SIZE)?.as_slice())?;

        let lookups_key = (preimage_hash, preimage_size);
        if let Some(entry) = x
            .partial_state
            .accounts_sandbox
            .get_account_lookups_entry(state_manager, x.accumulate_host, &lookups_key)
            .await?
        {
            let (r7, r8) = match entry.value.len() {
                0 => (0, 0),
                1 => (1 + entry.value[0].slot() * (1 << 32), 0),
                2 => (2 + entry.value[0].slot() * (1 << 32), entry.value[1].slot()),
                3 => (
                    3 + entry.value[0].slot() * (1 << 32),
                    entry.value[1].slot() + entry.value[2].slot() * (1 << 32),
                ),
                _ => panic!("Should not have more than 3 timeslot values"),
            };
            continue_with_vm_change!(r7: r7, r8: r8)
        } else {
            continue_none!()
        }
    }

    /// Marks the accumulating account's lookup dictionary entry, which references a preimage entry
    /// that was previously available but is currently unavailable, as available again starting
    /// from the current timeslot.
    ///
    /// This is done by appending the current timeslot index to the timeslots vector of the
    /// lookup dictionary entry. It is asserted that the previous length of the vector is 2.
    pub async fn host_solicit(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: Arc<StateManager>,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let x = get_mut_accumulate_x!(context);

        let offset = regs[7].as_mem_address()?; // o
        let lookups_size = regs[8].as_u32()?; // z

        if !memory.is_address_range_readable(offset, HASH_SIZE)? {
            return host_call_panic!();
        }

        let lookup_hash = Hash32::decode(&mut memory.read_bytes(offset, HASH_SIZE)?.as_slice())?;
        let lookups_key = (lookup_hash, lookups_size);

        let prev_lookups_entry = x
            .partial_state
            .accounts_sandbox
            .get_account_lookups_entry(state_manager.clone(), x.accumulate_host, &lookups_key)
            .await?;

        let timeslot = state_manager.get_timeslot().await?;

        // Insert current timeslot if the entry exists and the timeslot vector length is 2.
        // If the key doesn't exist, insert a new empty Vec<Timeslot> with the key.
        // If the entry's timeslot vector length is not equal to 2, return with result constant `HUH`.
        let new_lookups_entry = match prev_lookups_entry.clone() {
            Some(mut entry) => {
                if entry.value.len() != 2 {
                    return continue_huh!();
                }
                // Add current timeslot to the timeslot vector.
                entry.value.push(timeslot);
                entry
            }
            None => {
                // Simulate the threshold balance change. In this case, a new lookups entry with an
                // empty timeslot vector is added.
                let new_lookups_entry = AccountLookupsEntry::default();
                let new_lookups_octets_usage = Some(AccountLookupsOctetsUsage {
                    preimage_length: lookups_size,
                    entry: new_lookups_entry.clone(),
                });
                let (lookups_items_count_delta, lookups_octets_count_delta) =
                    AccountMetadata::calculate_storage_footprint_delta(
                        None,
                        new_lookups_octets_usage.as_ref(),
                    )
                    .ok_or(PVMError::StateManagerError(LookupsEntryNotFound))?;

                let accumulator_metadata =
                    x.get_accumulator_metadata(state_manager.clone()).await?;
                let simulated_threshold_balance = accumulator_metadata
                    .simulate_threshold_balance_after_mutation(
                        lookups_items_count_delta,
                        0,
                        lookups_octets_count_delta,
                        0,
                    );

                if simulated_threshold_balance > accumulator_metadata.balance() {
                    return continue_full!();
                }

                new_lookups_entry
            }
        };

        // Apply the state change
        x.partial_state
            .accounts_sandbox
            .insert_account_lookups_entry(
                state_manager,
                x.accumulate_host,
                lookups_key,
                new_lookups_entry,
            )
            .await?;

        continue_ok!()
    }

    /// Removes a preimage from the accumulating account's preimage and lookups storage,
    /// or marks a lookups entry as unavailable by updating its timeslot vector.
    ///
    /// If the timeslot vector indicates the preimage is unavailable, remove the corresponding entries
    /// from both storages. Otherwise, mark the preimage as unavailable by appending the current timeslot
    /// to the timeslot vector.
    pub async fn host_forget(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        state_manager: Arc<StateManager>,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let x = get_mut_accumulate_x!(context);

        let offset = regs[7].as_mem_address()?;
        let lookup_len = regs[8].as_u32()?;

        if !memory.is_address_range_readable(offset, HASH_SIZE)? {
            return host_call_panic!();
        }

        let lookup_hash = Hash32::decode(&mut memory.read_bytes(offset, HASH_SIZE)?.as_slice())?;
        let lookups_key = (lookup_hash, lookup_len);
        let lookups_entry = x
            .partial_state
            .accounts_sandbox
            .get_account_lookups_entry(state_manager.clone(), x.accumulate_host, &lookups_key)
            .await?;

        let timeslot = state_manager.get_timeslot().await?;
        match lookups_entry {
            None => continue_huh!(),
            Some(entry) => {
                let lookups_timeslots = entry.value.clone();

                match lookups_timeslots.len() {
                    0 => {
                        // Remove preimage and lookups storage entry
                        x.partial_state
                            .accounts_sandbox
                            .remove_account_preimages_entry(
                                state_manager.clone(),
                                x.accumulate_host,
                                lookup_hash,
                            )
                            .await?;
                        x.partial_state
                            .accounts_sandbox
                            .remove_account_lookups_entry(
                                state_manager,
                                x.accumulate_host,
                                lookups_key,
                            )
                            .await?;
                        continue_ok!()
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
                            )
                            .await?;
                        continue_ok!()
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
                                        state_manager.clone(),
                                        x.accumulate_host,
                                        lookup_hash,
                                    )
                                    .await?;
                                x.partial_state
                                    .accounts_sandbox
                                    .remove_account_lookups_entry(
                                        state_manager,
                                        x.accumulate_host,
                                        lookups_key,
                                    )
                                    .await?;
                            } else {
                                let prev_last_timeslot = lookups_timeslots
                                    .last()
                                    .cloned()
                                    .expect("Should not be empty");
                                x.partial_state
                                    .accounts_sandbox
                                    .drain_account_lookups_entry_timeslots(
                                        state_manager.clone(),
                                        x.accumulate_host,
                                        lookups_key,
                                    )
                                    .await?;
                                x.partial_state
                                    .accounts_sandbox
                                    .extend_timeslots_to_account_lookups_entry(
                                        state_manager,
                                        x.accumulate_host,
                                        lookups_key,
                                        vec![prev_last_timeslot, timeslot],
                                    )
                                    .await?;
                            }
                        }
                        continue_ok!()
                    }
                    _ => continue_huh!(),
                }
            }
        }
    }

    /// Yields the accumulation result commitment hash to the accumulate context.
    pub async fn host_yield(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let x = get_mut_accumulate_x!(context);

        let offset = regs[7].as_mem_address()?; // o

        if !memory.is_address_range_readable(offset, HASH_SIZE)? {
            return host_call_panic!();
        }
        let commitment_hash =
            Hash32::decode(&mut memory.read_bytes(offset, HASH_SIZE)?.as_slice())?;

        x.yielded_accumulate_hash = Some(commitment_hash);

        continue_ok!()
    }

    //
    // Refine Functions
    //

    /// Performs a historical preimage lookup for the specified account and hash,
    /// retrieving the preimage data if available.
    ///
    /// This is the only stateful operation in the refinement process and allows auditors to access
    /// states required for execution of the refinement through historical lookups.
    pub async fn host_historical_lookup(
        refine_service_id: ServiceId,
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        context: &mut InvocationContext,
        state_manager: Arc<StateManager>,
    ) -> Result<HostCallResult, PVMError> {
        let x = get_refine_x!(context);

        let service_id_reg = regs[7].value();
        let hash_offset = regs[8].as_mem_address()?;
        let buf_offset = regs[9].as_mem_address()?;

        let service_id = if service_id_reg == u64::MAX
            || state_manager.account_exists(refine_service_id).await?
        {
            refine_service_id
        } else if state_manager
            .account_exists(regs[7].as_service_id()?)
            .await?
        {
            regs[7].as_service_id()?
        } else {
            return continue_none!();
        };

        if !memory.is_address_range_readable(hash_offset, HASH_SIZE)? {
            return host_call_panic!();
        }

        let lookup_hash =
            Hash32::decode(&mut memory.read_bytes(hash_offset, HASH_SIZE)?.as_slice())?;

        let preimage = state_manager
            .lookup_historical_preimage(
                service_id,
                &Timeslot::new(x.invoke_args.package.context.lookup_anchor_timeslot),
                &lookup_hash,
            )
            .await?
            .unwrap_or_default();

        let preimage_offset = regs[10].as_usize()?.min(preimage.len()); // f
        let lookup_size = regs[11].as_usize()?.min(preimage.len() - preimage_offset); // l

        if !memory.is_address_range_writable(buf_offset, lookup_size)? {
            return host_call_panic!();
        }

        continue_with_vm_change!(
            r7: preimage.len(),
            mem_offset: buf_offset,
            mem_size: lookup_size,
            mem_data: preimage[preimage_offset..preimage_offset + lookup_size].to_vec()
        )
    }

    /// Fetches various data types introduced as arguments of the refine invocation.
    /// This includes work-package data, authorizer output and imports data.
    pub fn host_fetch(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let x = get_refine_x!(context);
        let data_id = regs[10].as_usize()?;

        let data = match data_id {
            0 => x.invoke_args.package.clone().encode()?,
            1 => x.invoke_args.auth_output.clone(),
            2 => {
                let items = x.invoke_args.package.work_items.clone();
                let item_idx = regs[11].as_usize()?;
                if item_idx < items.len() {
                    items[item_idx].payload_blob.to_vec()
                } else {
                    return continue_none!();
                }
            }
            3 => {
                let items = x.invoke_args.package.work_items.clone();
                let item_idx = regs[11].as_usize()?;
                let xt_idx = regs[12].as_usize()?;
                if item_idx < items.len() && xt_idx < items[item_idx].extrinsic_data_info.len() {
                    let xt_info = items[item_idx].extrinsic_data_info[xt_idx].clone();
                    if let Some(xt_blob) = x.invoke_args.extrinsic_data_map.get(&xt_info) {
                        xt_blob.to_vec()
                    } else {
                        return continue_none!();
                    }
                } else {
                    return continue_none!();
                }
            }
            4 => {
                let items = x.invoke_args.package.work_items.clone();
                let item_idx = x.invoke_args.item_idx;
                let xt_idx = regs[11].as_usize()?;
                if xt_idx < items[item_idx].extrinsic_data_info.len() {
                    let xt_info = items[item_idx].extrinsic_data_info[xt_idx].clone();
                    if let Some(xt_blob) = x.invoke_args.extrinsic_data_map.get(&xt_info) {
                        xt_blob.to_vec()
                    } else {
                        return continue_none!();
                    }
                } else {
                    return continue_none!();
                }
            }
            5 => {
                let imports = x.invoke_args.import_segments.clone();
                let item_idx = regs[11].as_usize()?;
                let segment_idx = regs[12].as_usize()?;
                if item_idx < imports.len() && segment_idx < imports[item_idx].len() {
                    imports[item_idx][segment_idx].to_vec()
                } else {
                    return continue_none!();
                }
            }
            6 => {
                let imports = x.invoke_args.import_segments.clone();
                let item_idx = x.invoke_args.item_idx;
                let segment_idx = regs[11].as_usize()?;
                if segment_idx < imports[item_idx].len() {
                    imports[item_idx][segment_idx].to_vec()
                } else {
                    return continue_none!();
                }
            }
            _ => {
                return continue_none!();
            }
        };

        let buf_offset = regs[7].as_mem_address()?; // o
        let data_read_offset = regs[8].as_usize()?.min(data.len()); // f
        let data_read_size = regs[9].as_usize()?.min(data.len() - data_read_offset); // l

        if !memory.is_address_range_writable(buf_offset, data_read_size)? {
            return host_call_panic!();
        }

        continue_with_vm_change!(
            r7: data.len(),
            mem_offset: buf_offset,
            mem_size: data_read_size,
            mem_data: data[data_read_offset..data_read_offset + data_read_size].to_vec()
        )
    }

    /// Appends an entry to the export segments vector using the value loaded from memory.
    /// This export segments vector will be written to the ImportDA after the successful execution
    /// of the refinement process.
    pub fn host_export(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let x = get_mut_refine_x!(context);

        let offset = regs[7].as_mem_address()?; // p
        let export_size = regs[8].as_usize()?.min(SEGMENT_SIZE); // z

        if !memory.is_address_range_readable(offset, export_size)? {
            return host_call_panic!();
        }

        let next_export_segments_offset =
            x.export_segments.len() + x.invoke_args.export_segments_offset;
        if next_export_segments_offset >= WORK_PACKAGE_MANIFEST_SIZE_LIMIT {
            return continue_full!();
        }

        let data_segment: ExportDataSegment =
            zero_pad_as_array::<SEGMENT_SIZE>(memory.read_bytes(offset, export_size)?)
                .ok_or(PVMError::HostCallError(DataSegmentTooLarge))?;

        x.export_segments.push(data_segment);

        continue_with_vm_change!(r7: next_export_segments_offset)
    }

    /// Initializes an inner VM with the specified program and the initial program counter.
    ///
    /// Memory of the inner VM is initialized with zero value cells and `Inaccessible` pages.
    pub fn host_machine(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let x = get_mut_refine_x!(context);

        let program_offset = regs[7].as_mem_address()?; // p_o
        let program_size = regs[8].as_usize()?; // p_z
        let initial_pc = regs[9].value(); // i

        if !memory.is_address_range_readable(program_offset, program_size)? {
            return host_call_panic!();
        }

        let program = memory.read_bytes(program_offset, program_size)?;
        // Validate the program blob can be `deblob`ed properly
        if ProgramDecoder::deblob_program_code(&program).is_err() {
            return continue_huh!();
        }

        let inner_vm = InnerPVM::new(program, initial_pc);
        let inner_vm_id = x.add_pvm_instance(inner_vm); // n

        continue_with_vm_change!(r7: inner_vm_id)
    }

    /// Peeks data from the inner VM memory and copies it to the external host VM memory.
    ///
    /// `HostVM` `<--(peek)--` `InnerVM`
    pub fn host_peek(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let x = get_refine_x!(context);

        let inner_vm_id = regs[7].as_usize()?; // n
        let memory_offset = regs[8].as_mem_address()?; // o
        let inner_memory_offset = regs[9].as_mem_address()?; // s
        let data_size = regs[10].as_usize()?; // z

        if !memory.is_address_range_writable(memory_offset, data_size)? {
            return host_call_panic!();
        }

        let Some(inner_memory) = x.get_inner_vm_memory(inner_vm_id) else {
            return continue_who!();
        };

        if !inner_memory.is_address_range_readable(inner_memory_offset, data_size)? {
            return continue_oob!();
        }
        let data = inner_memory.read_bytes(inner_memory_offset, data_size)?;

        continue_with_vm_change!(r7: HostCallReturnCode::OK, mem_offset: memory_offset, mem_size: data_size, mem_data: data)
    }

    /// Pokes data into the inner VM memory from the external host VM memory.
    ///
    /// `HostVM` `--(poke)-->` `InnerVM`
    pub fn host_poke(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let x = get_mut_refine_x!(context);

        let inner_vm_id = regs[7].as_usize()?; // n
        let memory_offset = regs[8].as_mem_address()?; // s
        let inner_memory_offset = regs[9].as_mem_address()?; // o
        let data_size = regs[10].as_usize()?; // z

        if !memory.is_address_range_readable(memory_offset, data_size)? {
            return host_call_panic!();
        }

        let Some(inner_memory_mut) = x.get_mut_inner_vm_memory(inner_vm_id) else {
            return continue_who!();
        };

        if !inner_memory_mut.is_address_range_writable(inner_memory_offset, data_size)? {
            return continue_oob!();
        }
        let data = memory.read_bytes(memory_offset, data_size)?;

        inner_memory_mut.write_bytes(inner_memory_offset as MemAddress, &data)?;

        continue_ok!()
    }

    /// Sets the specified range of inner VM memory pages to zeros and marks them as `ReadWrite`.
    pub fn host_zero(
        regs: &[Register; REGISTERS_COUNT],
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let x = get_mut_refine_x!(context);

        let inner_vm_id = regs[7].as_usize()?; // n
        let inner_memory_page_offset = regs[8].as_usize()?; // p
        let pages_count = regs[9].as_usize()?; // c

        if inner_memory_page_offset < 16
            || inner_memory_page_offset + pages_count >= (1 << 32) / PAGE_SIZE
        {
            return continue_huh!();
        }

        let Some(inner_memory_mut) = x.get_mut_inner_vm_memory(inner_vm_id) else {
            return continue_who!();
        };

        // set values
        let address_offset = (inner_memory_page_offset * PAGE_SIZE) as MemAddress;
        let data_size = pages_count * PAGE_SIZE;
        inner_memory_mut.write_bytes(address_offset, &vec![0u8; data_size])?;

        // set access types
        let page_start = inner_memory_page_offset;
        let page_end = inner_memory_page_offset + pages_count;
        inner_memory_mut.set_page_range_access(page_start..page_end, AccessType::ReadWrite)?;

        continue_ok!()
    }

    /// Sets the specified range of inner VM memory pages to zeros and marks them as `Inaccessible`.
    pub fn host_void(
        regs: &[Register; REGISTERS_COUNT],
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let x = get_mut_refine_x!(context);

        let inner_vm_id = regs[7].as_usize()?; // n
        let inner_memory_page_offset = regs[8].as_usize()?; // p
        let pages_count = regs[9].as_usize()?; // c

        if inner_memory_page_offset < 16
            || inner_memory_page_offset + pages_count >= (1 << 32) / PAGE_SIZE
        {
            return continue_huh!();
        }

        let Some(inner_memory_mut) = x.get_mut_inner_vm_memory(inner_vm_id) else {
            return continue_who!();
        };

        let page_start = inner_memory_page_offset;
        let page_end = inner_memory_page_offset + pages_count;
        // should not have a page already `Inaccessible` within the range
        if !inner_memory_mut.is_page_range_readable(page_start..page_end)? {
            return continue_huh!();
        }

        // set values
        let address_offset = (inner_memory_page_offset * PAGE_SIZE) as MemAddress;
        let data_size = pages_count * PAGE_SIZE;
        inner_memory_mut.write_bytes(address_offset, &vec![0u8; data_size])?;

        // set access types
        inner_memory_mut.set_page_range_access(page_start..page_end, AccessType::Inaccessible)?;

        continue_ok!()
    }

    /// Invokes the inner VM with its program using the PVM general invocation function `Ψ`.
    ///
    /// The gas limit and initial register values for the inner VM are read from the memory of the host VM.
    /// Upon completion, the posterior state (e.g., gas counter, memory, registers) of the inner VM is
    /// written back to the memory of the host VM, while the final state of the inner VM's memory
    /// is preserved within the inner VM.
    pub fn host_invoke(
        regs: &[Register; REGISTERS_COUNT],
        memory: &Memory,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let x = get_mut_refine_x!(context);

        let inner_vm_id = regs[7].as_usize()?; // n
        let memory_offset = regs[8].as_mem_address()?; // o

        if !memory.is_address_range_writable(memory_offset, 112)? {
            return host_call_panic!();
        }

        let Some(inner_vm_mut) = x.pvm_instances.get_mut(&inner_vm_id) else {
            return continue_who!();
        };

        let gas_limit =
            UnsignedGas::decode_fixed(&mut memory.read_bytes(memory_offset, 8)?.as_slice(), 8)?;

        let mut regs = [Register::default(); REGISTERS_COUNT];
        for (i, reg) in regs.iter_mut().enumerate() {
            reg.value = RegValue::decode_fixed(
                &mut memory
                    .read_bytes(memory_offset + 8 + 8 * i as MemAddress, 8)?
                    .as_slice(),
                8,
            )?;
        }

        // Construct a new `VMState` and `ProgramState` for the general invocation function.
        let mut inner_vm_state_copy = VMState {
            registers: regs,
            memory: inner_vm_mut.memory.clone(),
            pc: inner_vm_mut.pc,
            gas_counter: gas_limit,
        };
        let inner_vm_program_code = &inner_vm_mut.program_code.clone();
        let mut inner_vm_program_state = ProgramState::default();

        let inner_vm_exit_reason = PVMCore::invoke_general(
            &mut inner_vm_state_copy,
            &mut inner_vm_program_state,
            inner_vm_program_code,
        )?;

        // Apply the mutation of the `VMState` to the InnerVM state of the refine context
        inner_vm_mut.pc = inner_vm_state_copy.pc;
        inner_vm_mut.memory = inner_vm_state_copy.memory;

        let mut host_buf = vec![];
        inner_vm_state_copy
            .gas_counter
            .encode_to_fixed(&mut host_buf, 8)?;
        for reg in inner_vm_state_copy.registers {
            reg.value.encode_to_fixed(&mut host_buf, 8)?;
        }

        match inner_vm_exit_reason {
            ExitReason::HostCall(host_call_type) => {
                inner_vm_mut.pc += 1;
                continue_with_vm_change!(
                    r7: HOST,
                    r8: host_call_type,
                    mem_offset: memory_offset,
                    mem_size: 112,
                    mem_data: host_buf
                )
            }
            ExitReason::PageFault(address) => {
                continue_with_vm_change!(
                    r7: FAULT,
                    r8: address,
                    mem_offset: memory_offset,
                    mem_size: 112,
                    mem_data: host_buf
                )
            }
            ExitReason::OutOfGas => {
                continue_with_vm_change!(
                    r7: OOG,
                    mem_offset: memory_offset,
                    mem_size: 112,
                    mem_data: host_buf
                )
            }
            ExitReason::Panic => {
                continue_with_vm_change!(
                    r7: PANIC,
                    mem_offset: memory_offset,
                    mem_size: 112,
                    mem_data: host_buf
                )
            }
            ExitReason::RegularHalt => {
                continue_with_vm_change!(
                    r7: HALT,
                    mem_offset: memory_offset,
                    mem_size: 112,
                    mem_data: host_buf
                )
            }

            _ => Err(PVMError::HostCallError(InvalidExitReason)),
        }
    }

    /// Removes an inner VM instance from the refine context and returns its final pc.
    pub fn host_expunge(
        regs: &[Register; REGISTERS_COUNT],
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, PVMError> {
        let x = get_mut_refine_x!(context);

        let inner_vm_id = regs[7].as_usize()?; // n

        let Some(inner_vm) = x.pvm_instances.get(&inner_vm_id) else {
            return continue_who!();
        };
        let final_pc = inner_vm.pc;

        x.remove_pvm_instance(inner_vm_id);

        continue_with_vm_change!(r7: final_pc)
    }
}
