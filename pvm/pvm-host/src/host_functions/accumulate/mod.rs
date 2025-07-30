#[cfg(test)]
mod tests;

use crate::{
    context::InvocationContext, error::HostCallError, host_functions::HostCallResult, macros::*,
};
use fr_codec::prelude::*;
use fr_common::{
    AuthHash, ByteArray, Hash32, Octets, ServiceId, SignedGas, UnsignedGas, AUTH_QUEUE_SIZE,
    CORE_COUNT, HASH_SIZE, MIN_PUBLIC_SERVICE_ID, PREIMAGE_EXPIRATION_PERIOD, PUBLIC_KEY_SIZE,
    TRANSFER_MEMO_SIZE, VALIDATOR_COUNT,
};
use fr_crypto::{hash, octets_to_hash32, types::ValidatorKey, Blake2b256};
use fr_pvm_core::state::{state_change::HostCallVMStateChange, vm_state::VMState};
use fr_pvm_types::{
    common::{MemAddress, RegValue},
    constants::HOSTCALL_BASE_GAS_CHARGE,
    invoke_args::DeferredTransfer,
    invoke_results::AccumulationOutputHash,
};
use fr_state::{
    manager::StateManager,
    types::{
        privileges::AssignServices, AccountLookupsEntry, AccountLookupsEntryExt, AccountMetadata,
        AuthQueue, StagingSet, Timeslot,
    },
};
use std::{collections::BTreeMap, sync::Arc};

pub struct AccumulateHostFunction;
impl AccumulateHostFunction {
    /// Assigns new privileged services: manager (M), assign (A), designate (V), registrar (R) and
    /// always-accumulates (Z) to the accumulate context partial state.
    pub fn host_bless(
        vm: &VMState,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: BLESS");
        check_out_of_gas!(vm.gas_counter);
        let x = get_mut_accumulate_x!(context);

        let Ok(manager) = vm.regs[7].as_service_id() else {
            continue_who!()
        };
        let Ok(assign_offset) = vm.regs[8].as_mem_address() else {
            host_call_panic!()
        };
        let Ok(designate) = vm.regs[9].as_service_id() else {
            continue_who!()
        };
        let Ok(registrar) = vm.regs[10].as_service_id() else {
            continue_who!()
        };

        if !vm
            .memory
            .is_address_range_readable(assign_offset, 4 * CORE_COUNT)
        {
            host_call_panic!()
        }
        let assign_services_encoded = vm.memory.read_bytes(assign_offset, 4 * CORE_COUNT)?;
        let assign_services = AssignServices::decode(&mut assign_services_encoded.as_slice())?;

        let Ok(always_accumulate_offset) = vm.regs[11].as_mem_address() else {
            host_call_panic!()
        };
        let Ok(always_accumulates_count) = vm.regs[12].as_usize() else {
            host_call_panic!()
        };

        if !vm
            .memory
            .is_address_range_readable(always_accumulate_offset, 12 * always_accumulates_count)
        {
            host_call_panic!()
        }

        let mut always_accumulate_services = BTreeMap::new();

        for i in 0..always_accumulates_count {
            let Ok(always_accumulate_encoded) = vm
                .memory
                .read_bytes(always_accumulate_offset + 12 * i as MemAddress, 12)
            else {
                host_call_panic!()
            };
            let address = u32::decode_fixed(&mut always_accumulate_encoded.as_slice(), 4)?;
            let basic_gas = u64::decode_fixed(&mut always_accumulate_encoded.as_slice(), 8)?;
            always_accumulate_services.insert(address, basic_gas);
        }

        x.assign_new_privileged_services(
            manager,
            assign_services.clone(),
            designate,
            registrar,
            always_accumulate_services.clone(),
        );
        tracing::debug!(
            "BLESS manager={manager} assigns={:?} designate={designate} registrar={registrar} always_accumulates={:?}",
            assign_services.as_slice(),
            always_accumulate_services.keys()
        );
        continue_ok!()
    }

    /// Assigns `MAX_AUTH_QUEUE_SIZE` new authorizers to the `AuthQueue` of the specified core
    /// in the accumulate context partial state.
    pub fn host_assign(
        vm: &VMState,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: ASSIGN");
        check_out_of_gas!(vm.gas_counter);
        let x = get_mut_accumulate_x!(context);

        let Ok(core_index) = vm.regs[7].as_usize() else {
            continue_core!()
        };
        let Ok(queue_offset) = vm.regs[8].as_mem_address() else {
            host_call_panic!()
        };
        let Ok(core_assign_service) = vm.regs[9].as_service_id() else {
            continue_who!()
        };

        if !vm
            .memory
            .is_address_range_readable(queue_offset, HASH_SIZE * AUTH_QUEUE_SIZE)
        {
            host_call_panic!()
        }

        if core_index >= CORE_COUNT {
            continue_core!()
        }

        // Only the privileged assign service of the core is allowed to invoke this host call
        if x.accumulate_host != x.partial_state.assign_services[core_index] {
            continue_huh!()
        }

        let mut queue_assignment = AuthQueue::default();
        for i in 0..AUTH_QUEUE_SIZE {
            let Ok(authorizer) = vm
                .memory
                .read_bytes(queue_offset + (HASH_SIZE * i) as MemAddress, HASH_SIZE)
            else {
                host_call_panic!()
            };
            queue_assignment.0[core_index][i] = AuthHash::decode(&mut authorizer.as_slice())?;
        }

        x.assign_new_auth_queue(queue_assignment);
        x.assign_new_core_assign_service(core_index, core_assign_service);
        tracing::debug!("ASSIGN core={core_index} new_assigner={core_assign_service}",);
        continue_ok!()
    }

    /// Assigns `VALIDATOR_COUNT` new validators to the `StagingSet` in the accumulate context partial state.
    pub fn host_designate(
        vm: &VMState,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: DESIGNATE");
        check_out_of_gas!(vm.gas_counter);
        let x = get_mut_accumulate_x!(context);

        let Ok(offset) = vm.regs[7].as_mem_address() else {
            host_call_panic!()
        };

        if !vm
            .memory
            .is_address_range_readable(offset, PUBLIC_KEY_SIZE * VALIDATOR_COUNT)
        {
            host_call_panic!()
        }

        let mut new_staging_set = StagingSet::default();
        for i in 0..VALIDATOR_COUNT {
            let Ok(validator_key) = vm.memory.read_bytes(
                offset + (PUBLIC_KEY_SIZE * i) as MemAddress,
                PUBLIC_KEY_SIZE,
            ) else {
                host_call_panic!()
            };
            new_staging_set[i] = ValidatorKey::decode(&mut validator_key.as_slice())?;
        }

        // Only the privileged designate service of the core is allowed to invoke this host call
        if x.accumulate_host != x.partial_state.designate_service {
            continue_huh!()
        }

        x.assign_new_staging_set(new_staging_set);
        continue_ok!()
    }

    /// Copies a snapshot of the current accumulate context state into
    /// the checkpoint context of the context pair.
    pub fn host_checkpoint(
        vm: &VMState,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: CHECKPOINT");
        check_out_of_gas!(vm.gas_counter);
        let (x_cloned, y_mut) = match (
            context.get_accumulate_x().cloned(),
            context.get_mut_accumulate_y(),
        ) {
            (Some(x_cloned), Some(y_mut)) => (x_cloned, y_mut),
            _ => continue_what!(),
        };

        *y_mut = x_cloned; // assign the cloned `x` context to the `y` context

        // If execution of this function results in `ExitReason::OutOfGas`,
        // returns zero value for the remaining gas limit.
        let post_gas = (vm.gas_counter as UnsignedGas).saturating_sub(HOSTCALL_BASE_GAS_CHARGE);
        continue_with_vm_change!(r7: post_gas)
    }

    /// Creates a new service account with an address derived from the hash of
    /// the accumulate host address, the current epochal entropy, and the block timeslot index.
    ///
    /// The code hash is loaded into memory, and the two gas limits and the gratis storage offset
    /// are provided as arguments in registers.
    ///
    /// The account storage and lookup dictionary are initialized as empty.
    pub async fn host_new(
        vm: &VMState,
        state_manager: Arc<StateManager>,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: NEW");
        check_out_of_gas!(vm.gas_counter);
        let x = get_mut_accumulate_x!(context);

        let Ok(offset) = vm.regs[7].as_mem_address() else {
            host_call_panic!()
        };
        let Ok(code_lookup_len) = vm.regs[8].as_u32() else {
            host_call_panic!()
        };
        let gas_limit_g = vm.regs[9].value();
        let gas_limit_m = vm.regs[10].value();
        let Ok(gratis_storage_offset) = vm.regs[11].as_balance() else {
            unreachable!(
                "as_balance() conversion should not fail: both RegValue and Balance are u64"
            )
        };
        let new_small_service_id = vm.regs[12].as_service_id().unwrap_or(ServiceId::MAX); // Not used if this value is larger than `MIN_PUBLIC_SERVICE_ID`

        if !vm.memory.is_address_range_readable(offset, HASH_SIZE) {
            host_call_panic!()
        }

        // Only the privileged manager service can create new accounts with gratis storage
        if gratis_storage_offset != 0 && x.accumulate_host != x.partial_state.manager_service {
            continue_huh!()
        }

        let Ok(code_hash_octets) = vm.memory.read_bytes(offset, HASH_SIZE) else {
            host_call_panic!()
        };
        let code_hash = Hash32::decode(&mut code_hash_octets.as_slice())?;
        let new_account_threshold_balance =
            AccountMetadata::get_initial_threshold_balance(code_lookup_len, gratis_storage_offset);

        // Check if the accumulate host service account's balance is sufficient
        // and subtract by the initial threshold balance to be transferred to the new account.
        let accumulator_metadata = x.get_accumulator_metadata(state_manager.clone()).await?;
        let accumulator_balance = accumulator_metadata.balance();
        let accumulator_threshold_balance = accumulator_metadata.threshold_balance();

        if accumulator_balance.saturating_sub(accumulator_threshold_balance)
            < new_account_threshold_balance
        {
            continue_cash!()
        }

        let has_small_service_id = new_small_service_id < MIN_PUBLIC_SERVICE_ID
            && x.accumulate_host == x.partial_state.registrar_service;
        let new_small_service_id_already_taken = x
            .partial_state
            .accounts_sandbox
            .account_exists(state_manager.clone(), new_small_service_id)
            .await?;

        if has_small_service_id && new_small_service_id_already_taken {
            continue_full!()
        }

        x.subtract_accumulator_balance(state_manager.clone(), new_account_threshold_balance)
            .await?;

        // Add a new account to the partial state
        let curr_timeslot = state_manager.get_timeslot().await?.slot();
        let new_service_id = if has_small_service_id {
            // Taking small service ids doesn't require rotating the next new service id
            new_small_service_id
        } else {
            let new_service_id = x
                .add_new_account(
                    state_manager.clone(),
                    code_hash.clone(),
                    new_account_threshold_balance,
                    gas_limit_g,
                    gas_limit_m,
                    (code_hash, code_lookup_len),
                    gratis_storage_offset,
                    curr_timeslot,
                    0,
                    x.accumulate_host,
                )
                .await?;

            // Update the next new service account index in the partial state
            x.rotate_new_account_id(state_manager).await?;
            new_service_id
        };

        tracing::debug!(
            "NEW service_id={new_service_id} parent={}",
            x.accumulate_host
        );
        continue_with_vm_change!(r7: new_service_id)
    }

    /// Upgrades three metadata fields of the accumulating service account:
    /// code hash and gas limits for accumulate & on-transfer.
    pub async fn host_upgrade(
        vm: &VMState,
        state_manager: Arc<StateManager>,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: UPGRADE");
        check_out_of_gas!(vm.gas_counter);
        let x = get_mut_accumulate_x!(context);

        let Ok(offset) = vm.regs[7].as_mem_address() else {
            host_call_panic!()
        };
        let gas_limit_g = vm.regs[8].value();
        let gas_limit_m = vm.regs[9].value();

        if !vm.memory.is_address_range_readable(offset, HASH_SIZE) {
            host_call_panic!()
        }

        let Ok(code_hash_octets) = vm.memory.read_bytes(offset, HASH_SIZE) else {
            host_call_panic!()
        };
        let code_hash = Hash32::decode(&mut code_hash_octets.as_slice())?;

        x.update_accumulator_metadata(state_manager, code_hash.clone(), gas_limit_g, gas_limit_m)
            .await?;
        tracing::debug!(
            "UPGRADE service_id={} code_hash={code_hash} g={gas_limit_g} m={gas_limit_m}",
            x.accumulate_host
        );
        continue_ok!()
    }

    /// Transfers tokens from the accumulating service account to another service account.
    pub async fn host_transfer(
        vm: &VMState,
        state_manager: Arc<StateManager>,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: TRANSFER");
        let x = get_mut_accumulate_x!(context);

        let Ok(dest) = vm.regs[7].as_service_id() else {
            continue_who!()
        };
        let amount = vm.regs[8].value();
        let gas_limit = vm.regs[9].value();
        let Ok(offset) = vm.regs[10].as_mem_address() else {
            host_call_panic!()
        };
        let gas_charge = HOSTCALL_BASE_GAS_CHARGE + gas_limit;

        check_out_of_gas!(vm.gas_counter, gas_charge);

        if !vm
            .memory
            .is_address_range_readable(offset, TRANSFER_MEMO_SIZE)
        {
            host_call_panic!(gas_charge)
        }

        let memo = ByteArray::<TRANSFER_MEMO_SIZE>::decode(
            &mut vm.memory.read_bytes(offset, TRANSFER_MEMO_SIZE)?.as_slice(),
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
        let Some(dest_account_metadata) = x
            .partial_state
            .accounts_sandbox
            .get_account_metadata(state_manager.clone(), dest)
            .await?
        else {
            continue_who!(gas_charge)
        };

        if gas_limit < dest_account_metadata.gas_limit_on_transfer {
            continue_low!(gas_charge)
        }

        if accumulator_balance.saturating_sub(amount) < accumulator_threshold_balance {
            continue_cash!(gas_charge)
        }

        x.subtract_accumulator_balance(state_manager, amount)
            .await?;
        x.add_to_deferred_transfers(transfer);
        tracing::debug!(
            "TRANSFER from={} to={dest} amount={amount}",
            x.accumulate_host
        );
        continue_ok!(gas_charge)
    }

    /// Completely removes a service account from the global state.
    pub async fn host_eject(
        vm: &VMState,
        state_manager: Arc<StateManager>,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: EJECT");
        check_out_of_gas!(vm.gas_counter);
        let x = get_mut_accumulate_x!(context);

        let Ok(eject_service_id) = vm.regs[7].as_service_id() else {
            continue_who!()
        };
        let Ok(offset) = vm.regs[8].as_mem_address() else {
            host_call_panic!()
        };

        if !vm.memory.is_address_range_readable(offset, HASH_SIZE) {
            host_call_panic!()
        }
        let Ok(preimage_hash_octets) = vm.memory.read_bytes(offset, HASH_SIZE) else {
            host_call_panic!()
        };
        let preimage_hash = Hash32::decode(&mut preimage_hash_octets.as_slice())?;

        if eject_service_id == x.accumulate_host {
            continue_who!()
        }

        let Some(eject_account_metadata) = x
            .partial_state
            .accounts_sandbox
            .get_account_metadata(state_manager.clone(), eject_service_id)
            .await?
            .cloned()
        else {
            continue_who!()
        };

        let accumulate_host_as_hash = octets_to_hash32(&x.accumulate_host.encode_fixed(32)?)
            .expect("Should not fail convert 32-byte octets into Hash32");
        if eject_account_metadata.code_hash != accumulate_host_as_hash {
            continue_who!()
        }

        // Note: This error handling assumes that preimage size (`l` component of lookups key)
        // exceeding `u32::MAX` implies incorrect lookups key, therefore returning `HUH`.
        let preimage_size_u64 = 81.max(eject_account_metadata.octets_footprint) - 81;
        let Some(preimage_size) = preimage_size_u64.try_into().ok() else {
            continue_huh!()
        };
        if eject_account_metadata.items_footprint != 2 {
            continue_huh!()
        }
        let lookups_key = (preimage_hash, preimage_size);

        let Some(entry) = x
            .partial_state
            .accounts_sandbox
            .get_account_lookups_entry(state_manager.clone(), eject_service_id, &lookups_key)
            .await?
        else {
            continue_huh!()
        };

        let curr_timeslot = state_manager.get_timeslot().await?.slot();
        if entry.value.len() != 2
            || entry.value[1].slot() + PREIMAGE_EXPIRATION_PERIOD >= curr_timeslot
        {
            continue_huh!()
        }

        x.add_accumulator_balance(state_manager.clone(), eject_account_metadata.balance())
            .await?;
        x.partial_state
            .accounts_sandbox
            .eject_account(state_manager, eject_service_id, lookups_key)
            .await?;
        tracing::debug!("EJECT service_id={eject_service_id}");
        continue_ok!()
    }

    /// Queries the lookups storage's timeslot scopes to determine the availability of a preimage entry.
    pub async fn host_query(
        vm: &VMState,
        state_manager: Arc<StateManager>,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: QUERY");
        check_out_of_gas!(vm.gas_counter);
        let x = get_mut_accumulate_x!(context);

        let Ok(offset) = vm.regs[7].as_mem_address() else {
            host_call_panic!()
        };
        let Ok(preimage_size) = vm.regs[8].as_u32() else {
            continue_none!()
        };

        if !vm.memory.is_address_range_readable(offset, HASH_SIZE) {
            host_call_panic!()
        }
        let Ok(preimage_hash_octets) = vm.memory.read_bytes(offset, HASH_SIZE) else {
            host_call_panic!()
        };
        let preimage_hash = Hash32::decode(&mut preimage_hash_octets.as_slice())?;

        let lookups_key = (preimage_hash, preimage_size);
        let Some(entry) = x
            .partial_state
            .accounts_sandbox
            .get_account_lookups_entry(state_manager, x.accumulate_host, &lookups_key)
            .await?
        else {
            continue_none!()
        };

        // for debugging
        let mut slots = Vec::with_capacity(3);
        let (r7, r8) = match entry.value.len() {
            0 => (0, 0),
            1 => {
                let slot_0 = entry.value[0].slot();
                slots.push(slot_0);
                (1 + slot_0 as u64 * (1 << 32), 0)
            }
            2 => {
                let slot_0 = entry.value[0].slot();
                let slot_1 = entry.value[1].slot();
                slots.push(slot_0);
                slots.push(slot_1);
                (2 + slot_0 as u64 * (1 << 32), slot_1 as u64)
            }
            3 => {
                let slot_0 = entry.value[0].slot();
                let slot_1 = entry.value[1].slot();
                let slot_2 = entry.value[2].slot();
                slots.push(slot_0);
                slots.push(slot_1);
                slots.push(slot_2);
                (
                    3 + slot_0 as u64 * (1 << 32),
                    slot_1 as u64 + slot_2 as u64 * (1 << 32),
                )
            }
            _ => panic!("Should not have more than 3 timeslot values"),
        };
        tracing::debug!(
            "QUERY key=({}, {}) slots={slots:?}",
            lookups_key.0,
            lookups_key.1
        );
        continue_with_vm_change!(r7: r7, r8: r8)
    }

    /// Marks the accumulating account's lookup dictionary entry, which references a preimage entry
    /// that was previously available but is currently unavailable, as available again starting
    /// from the current timeslot.
    ///
    /// This is done by appending the current timeslot index to the timeslots vector of the
    /// lookup dictionary entry. It is asserted that the previous length of the vector is 2.
    pub async fn host_solicit(
        vm: &VMState,
        state_manager: Arc<StateManager>,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: SOLICIT");
        check_out_of_gas!(vm.gas_counter);
        let x = get_mut_accumulate_x!(context);

        let Ok(offset) = vm.regs[7].as_mem_address() else {
            host_call_panic!()
        };
        // TODO: Determine whether lookups size larger than `u32::MAX` should be allowed.
        // TODO: For now, continues with `FULL` code with no further threshold balance check.
        // TODO: Also check `host_query`, `host_forget`, `host_eject` which assume those lookups entry doesn't exist.
        let Ok(lookups_size) = vm.regs[8].as_u32() else {
            continue_full!()
        };

        if !vm.memory.is_address_range_readable(offset, HASH_SIZE) {
            host_call_panic!()
        }

        let Ok(lookup_hash_octets) = vm.memory.read_bytes(offset, HASH_SIZE) else {
            host_call_panic!()
        };
        let lookup_hash = Hash32::decode(&mut lookup_hash_octets.as_slice())?;
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
        let new_lookups_entry = match prev_lookups_entry {
            Some(mut entry) => {
                if entry.value.len() != 2 {
                    continue_huh!()
                }
                // Add current timeslot to the timeslot vector.
                let Ok(_) = entry.value.try_push(timeslot) else {
                    continue_huh!()
                };
                entry
            }
            None => {
                // Simulate the threshold balance change. In this case, a new lookups entry with an
                // empty timeslot vector is added.
                let new_lookups_entry = AccountLookupsEntry::default();
                let new_lookups_octets_usage = Some(AccountLookupsEntryExt {
                    preimage_length: lookups_size,
                    entry: new_lookups_entry.clone(),
                });
                let lookups_usage_delta = AccountMetadata::calculate_storage_usage_delta(
                    None,
                    new_lookups_octets_usage.as_ref(),
                )
                .unwrap_or_default(); // Attempting to delete a storage entry that doesn't exist is basically a no-op

                let accumulator_metadata =
                    x.get_accumulator_metadata(state_manager.clone()).await?;
                let simulated_threshold_balance = accumulator_metadata
                    .simulate_threshold_balance_after_mutation(None, Some(lookups_usage_delta));

                if simulated_threshold_balance > accumulator_metadata.balance() {
                    continue_full!()
                }

                AccountLookupsEntryExt::from_entry(lookups_key.clone(), new_lookups_entry)
            }
        };

        // Apply the state change
        x.partial_state
            .accounts_sandbox
            .insert_account_lookups_entry(
                state_manager,
                x.accumulate_host,
                lookups_key.clone(),
                new_lookups_entry.clone(),
            )
            .await?;
        tracing::debug!(
            "SOLICIT key=({}, {}) post_slots={:?}",
            lookups_key.0,
            lookups_key.1,
            new_lookups_entry.entry.value.as_slice()
        );
        continue_ok!()
    }

    /// Removes a preimage from the accumulating account's preimage and lookups storage,
    /// or marks a lookups entry as unavailable by updating its timeslot vector.
    ///
    /// If the timeslot vector indicates the preimage is unavailable, remove the corresponding entries
    /// from both storages. Otherwise, mark the preimage as unavailable by appending the current timeslot
    /// to the timeslot vector.
    pub async fn host_forget(
        vm: &VMState,
        state_manager: Arc<StateManager>,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: FORGET");
        check_out_of_gas!(vm.gas_counter);
        let x = get_mut_accumulate_x!(context);

        let Ok(offset) = vm.regs[7].as_mem_address() else {
            host_call_panic!()
        };
        let Ok(lookup_len) = vm.regs[8].as_u32() else {
            continue_huh!()
        };

        if !vm.memory.is_address_range_readable(offset, HASH_SIZE) {
            host_call_panic!()
        }

        let Ok(lookup_hash_octets) = vm.memory.read_bytes(offset, HASH_SIZE) else {
            host_call_panic!()
        };
        let lookup_hash = Hash32::decode(&mut lookup_hash_octets.as_slice())?;
        let lookups_key = (lookup_hash.clone(), lookup_len);
        let lookups_entry = x
            .partial_state
            .accounts_sandbox
            .get_account_lookups_entry(state_manager.clone(), x.accumulate_host, &lookups_key)
            .await?;

        let timeslot = state_manager.get_timeslot().await?;
        match lookups_entry {
            None => continue_huh!(),
            Some(entry) => {
                let lookups_timeslots = &entry.value;
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
                                lookups_key.clone(),
                            )
                            .await?;
                        tracing::debug!(
                            "FORGET key=({}, {}) prev=[], curr=None",
                            lookups_key.0,
                            lookups_key.1
                        );
                        continue_ok!()
                    }
                    1 => {
                        // Add current timeslot to the lookups entry timeslot vector
                        let updated_lookups_entry = x
                            .partial_state
                            .accounts_sandbox
                            .push_timeslot_to_account_lookups_entry(
                                state_manager,
                                x.accumulate_host,
                                lookups_key.clone(),
                                timeslot,
                            )
                            .await?
                            .expect("Lookups entry for key already exists in global state")
                            .value
                            .as_slice()
                            .iter()
                            .map(Timeslot::slot)
                            .collect::<Vec<_>>();
                        tracing::debug!(
                            "FORGET key=({}, {}) prev={:?}, curr={:?}",
                            lookups_key.0,
                            lookups_key.1,
                            lookups_timeslots
                                .as_slice()
                                .iter()
                                .map(Timeslot::slot)
                                .collect::<Vec<_>>(),
                            updated_lookups_entry
                        );
                        continue_ok!()
                    }
                    len if len == 2 || len == 3 => {
                        let is_expired = lookups_timeslots[1].slot() + PREIMAGE_EXPIRATION_PERIOD
                            < timeslot.slot();
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
                                        lookups_key.clone(),
                                    )
                                    .await?;
                                tracing::debug!(
                                    "FORGET key=({}, {}) prev={:?}, curr=None",
                                    lookups_key.0,
                                    lookups_key.1,
                                    lookups_timeslots
                                        .as_slice()
                                        .iter()
                                        .map(Timeslot::slot)
                                        .collect::<Vec<_>>(),
                                );
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
                                        lookups_key.clone(),
                                    )
                                    .await?;
                                let updated_lookups_entry = x
                                    .partial_state
                                    .accounts_sandbox
                                    .extend_timeslots_to_account_lookups_entry(
                                        state_manager,
                                        x.accumulate_host,
                                        lookups_key.clone(),
                                        vec![prev_last_timeslot, timeslot],
                                    )
                                    .await?
                                    .expect("Lookups entry for key already exists in global state")
                                    .value
                                    .as_slice()
                                    .iter()
                                    .map(Timeslot::slot)
                                    .collect::<Vec<_>>();

                                tracing::debug!(
                                    "FORGET key=({}, {}) prev={:?}, curr={:?}",
                                    lookups_key.0,
                                    lookups_key.1,
                                    lookups_timeslots
                                        .as_slice()
                                        .iter()
                                        .map(Timeslot::slot)
                                        .collect::<Vec<_>>(),
                                    updated_lookups_entry
                                );
                            }
                        } else {
                            // Not expired
                            continue_huh!()
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
        vm: &VMState,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: YIELD");
        check_out_of_gas!(vm.gas_counter);
        let x = get_mut_accumulate_x!(context);

        let Ok(offset) = vm.regs[7].as_mem_address() else {
            host_call_panic!()
        };

        if !vm.memory.is_address_range_readable(offset, HASH_SIZE) {
            host_call_panic!()
        }
        let Ok(commitment_hash_octets) = vm.memory.read_bytes(offset, HASH_SIZE) else {
            host_call_panic!()
        };
        let commitment_hash =
            AccumulationOutputHash::decode(&mut commitment_hash_octets.as_slice())?;

        x.yielded_accumulate_hash = Some(commitment_hash.clone());
        tracing::debug!("YIELD commitment={commitment_hash}");
        continue_ok!()
    }

    /// Provides preimage data requested by services.
    pub async fn host_provide(
        service_id: ServiceId,
        vm: &VMState,
        state_manager: Arc<StateManager>,
        context: &mut InvocationContext,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: PROVIDE");
        check_out_of_gas!(vm.gas_counter);
        let x = get_mut_accumulate_x!(context);

        let service_id_reg = vm.regs[7].value();
        let Ok(offset) = vm.regs[8].as_mem_address() else {
            host_call_panic!()
        };
        let Ok(preimage_size) = vm.regs[9].as_usize() else {
            host_call_panic!()
        };

        let service_id = if service_id_reg == u64::MAX {
            service_id
        } else {
            service_id_reg as ServiceId
        };

        if !vm.memory.is_address_range_readable(offset, preimage_size) {
            host_call_panic!()
        }

        let Ok(preimage_data) = vm.memory.read_bytes(offset, preimage_size) else {
            host_call_panic!()
        };

        // Service account not found
        if x.partial_state
            .accounts_sandbox
            .get_account_metadata(state_manager.clone(), service_id)
            .await?
            .is_none()
        {
            continue_who!()
        }

        // Check current lookups entry
        let lookups_key = (hash::<Blake2b256>(&preimage_data)?, preimage_size as u32);
        let Some(lookups_entry) = x
            .partial_state
            .accounts_sandbox
            .get_account_lookups_entry(state_manager.clone(), service_id, &lookups_key)
            .await?
        else {
            // Preimage not requested
            continue_huh!()
        };
        if lookups_entry.timeslots_length() != 0 {
            // Preimage not requested
            continue_huh!()
        }

        // Check the partial state provided preimages set
        let data_len = preimage_data.len();
        let provided_preimage_entry = (service_id, Octets::from_vec(preimage_data));
        if x.provided_preimages.contains(&provided_preimage_entry) {
            // Preimage already included in the partial state
            continue_huh!()
        }

        // Insert the preimage entry
        x.provided_preimages.insert(provided_preimage_entry);
        tracing::debug!(
            "PROVIDE service_id={service_id} key=({}, {}), len={data_len}",
            lookups_key.0,
            lookups_key.1
        );
        continue_ok!()
    }
}
