#[cfg(test)]
mod tests;

use crate::{
    context::{InvocationContext, NewAccountFields},
    error::HostCallError,
    get_accumulate_x, get_mut_accumulate_y,
    host_functions::{HostCallResult, HostCallReturnCode},
    macros::*,
    out_of_gas,
};
use fr_codec::prelude::*;
use fr_common::{
    AuthHash, ByteArray, CoreIndex, Hash32, Octets, ServiceId, SignedGas, TimeslotIndex,
    UnsignedGas, AUTH_QUEUE_SIZE, CORE_COUNT, HASH_SIZE, MIN_PUBLIC_SERVICE_ID,
    PREIMAGE_EXPIRATION_PERIOD, PUBLIC_KEY_SIZE, TRANSFER_MEMO_SIZE, VALIDATOR_COUNT,
};
use fr_crypto::{hash, types::ValidatorKey, Blake2b256};
use fr_pvm_core::state::{state_change::HostCallVMStateChange, vm_state::VMState};
use fr_pvm_types::{
    common::{MemAddress, RegValue},
    constants::HOSTCALL_BASE_GAS_CHARGE,
    invoke_args::DeferredTransfer,
    invoke_results::AccumulationOutputHash,
};
use fr_state::{
    provider::HostStateProvider,
    state_utils::get_account_lookups_state_key,
    types::{
        privileges::AssignServices, AccountLookupsEntry, AccountLookupsEntryExt, AccountMetadata,
        AccountStorageUsageDelta, CoreAuthQueue, StagingSet, Timeslot,
    },
};
use std::{collections::BTreeMap, marker::PhantomData, sync::Arc};

pub struct AccumulateHostFunction<S> {
    _phantom: PhantomData<S>,
}
impl<S: HostStateProvider> AccumulateHostFunction<S> {
    /// Assigns new privileged services: manager (M), assign (A), designate (V), registrar (R) and
    /// always-accumulates (Z) to the accumulate context partial state.
    pub fn host_bless(
        vm: &VMState,
        context: &mut InvocationContext<S>,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: BLESS");
        check_out_of_gas!(vm.gas_counter);
        let x = get_mut_accumulate_x!(context);

        // --- Read from Memory (Err: Panic)

        let Ok(assign_offset) = vm.read_reg_as_mem_address(8) else {
            host_call_panic!()
        };
        let Ok(always_accumulate_offset) = vm.read_reg_as_mem_address(11) else {
            host_call_panic!()
        };
        let Ok(always_accumulates_count) = vm.read_reg_as_usize(12) else {
            host_call_panic!()
        };

        // Read assign services from the memory
        if !vm
            .memory
            .is_address_range_readable(assign_offset, 4 * CORE_COUNT)
        {
            host_call_panic!()
        }
        let Ok(assign_services_data) = vm.memory.read_bytes(assign_offset, 4 * CORE_COUNT) else {
            host_call_panic!()
        };
        let mut assign_services = Vec::with_capacity(CORE_COUNT);
        for i in 0..CORE_COUNT {
            assign_services.push(ServiceId::decode_fixed(
                &mut &assign_services_data[i * 4..i * 4 + 4],
                4,
            )?)
        }

        // Read always-accumulate services from the memory
        if !vm
            .memory
            .is_address_range_readable(always_accumulate_offset, 12 * always_accumulates_count)
        {
            host_call_panic!()
        }
        let Ok(always_accumulate_services_data) = vm
            .memory
            .read_bytes(always_accumulate_offset, 12 * always_accumulates_count)
        else {
            host_call_panic!()
        };

        // --- Check New Privileges (Err: WHO)

        let Ok(manager) = vm.read_reg_as_service_id(7) else {
            continue_who!()
        };
        let Ok(designate) = vm.read_reg_as_service_id(9) else {
            continue_who!()
        };
        let Ok(registrar) = vm.read_reg_as_service_id(10) else {
            continue_who!()
        };

        // --- OK

        let mut always_accumulate_services = BTreeMap::new();
        for i in 0..always_accumulates_count {
            let address = ServiceId::decode_fixed(
                &mut &always_accumulate_services_data[i * 12..i * 12 + 4],
                4,
            )?;
            let basic_gas = UnsignedGas::decode_fixed(
                &mut &always_accumulate_services_data[i * 12 + 4..i * 12 + 12],
                8,
            )?;
            always_accumulate_services.insert(address, basic_gas);
        }

        x.assign_new_privileged_services(
            x.accumulate_host,
            manager,
            AssignServices::try_from(assign_services.clone())?,
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
        context: &mut InvocationContext<S>,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: ASSIGN");
        check_out_of_gas!(vm.gas_counter);
        let x = get_mut_accumulate_x!(context);

        // --- Read from Memory (Err: Panic)

        let Ok(queue_offset) = vm.read_reg_as_mem_address(8) else {
            host_call_panic!()
        };

        if !vm
            .memory
            .is_address_range_readable(queue_offset, HASH_SIZE * AUTH_QUEUE_SIZE)
        {
            host_call_panic!()
        }

        let mut new_core_auth_queue = CoreAuthQueue::default();
        for i in 0..AUTH_QUEUE_SIZE {
            let Ok(authorizer) = vm
                .memory
                .read_bytes(queue_offset + (HASH_SIZE * i) as MemAddress, HASH_SIZE)
            else {
                host_call_panic!()
            };
            new_core_auth_queue[i] = AuthHash::decode(&mut authorizer.as_slice())?;
        }

        // --- Check Core Index (Err: CORE)

        let Ok(core_index) = vm.read_reg_as_usize(7) else {
            continue_core!()
        };
        if core_index >= CORE_COUNT {
            continue_core!()
        }

        // --- Check Privilege (Err: HUH)

        // Only the privileged assign service of the core is allowed to invoke this host call
        if x.accumulate_host != x.partial_state.assign_services.last_confirmed[core_index] {
            continue_huh!()
        }

        // --- Check New Privilege (Err: WHO)

        let Ok(core_assign_service) = vm.read_reg_as_service_id(9) else {
            continue_who!()
        };

        // --- OK

        x.assign_core_auth_queue(core_index as CoreIndex, new_core_auth_queue);
        x.assign_new_core_assign_service(core_index, core_assign_service);
        tracing::debug!("ASSIGN core={core_index} new_assigner={core_assign_service}",);
        continue_ok!()
    }

    /// Assigns `VALIDATOR_COUNT` new validators to the `StagingSet` in the accumulate context partial state.
    pub fn host_designate(
        vm: &VMState,
        context: &mut InvocationContext<S>,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: DESIGNATE");
        check_out_of_gas!(vm.gas_counter);
        let x = get_mut_accumulate_x!(context);

        // --- Read from Memory (Err: Panic)

        let Ok(offset) = vm.read_reg_as_mem_address(7) else {
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

        // --- Check Privilege (Err: HUH)

        // Only the privileged designate service is allowed to invoke this host call
        if x.accumulate_host != x.partial_state.designate_service.last_confirmed {
            continue_huh!()
        }

        // --- OK

        x.assign_new_staging_set(new_staging_set);
        continue_ok!()
    }

    /// Copies a snapshot of the current accumulate context state into
    /// the checkpoint context of the context pair.
    pub fn host_checkpoint(
        vm: &VMState,
        context: &mut InvocationContext<S>,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: CHECKPOINT");
        check_out_of_gas!(vm.gas_counter);
        let x_cloned = get_accumulate_x!(context).clone();
        let y_mut = get_mut_accumulate_y!(context);

        *y_mut = x_cloned; // assign the cloned `x` context to the `y` context

        if let Some(post_gas) = vm
            .gas_counter
            .checked_sub(HOSTCALL_BASE_GAS_CHARGE as SignedGas)
        {
            if post_gas >= 0 {
                continue_with_vm_change!(r7: post_gas as UnsignedGas)
            } else {
                out_of_gas!()
            }
        } else {
            out_of_gas!()
        }
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
        state_provider: Arc<S>,
        context: &mut InvocationContext<S>,
        curr_timeslot_index: TimeslotIndex,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: NEW");
        check_out_of_gas!(vm.gas_counter);
        let x = get_mut_accumulate_x!(context);

        // --- Read from Memory (Err: Panic)

        let Ok(offset) = vm.read_reg_as_mem_address(7) else {
            host_call_panic!()
        };
        let Ok(code_lookup_len) = vm.read_reg_as_u32(8) else {
            host_call_panic!()
        };

        if !vm.memory.is_address_range_readable(offset, HASH_SIZE) {
            host_call_panic!()
        }
        let Ok(code_hash_octets) = vm.memory.read_bytes(offset, HASH_SIZE) else {
            host_call_panic!()
        };

        // --- Check Privilege (Err: HUH)

        let Ok(gratis_storage_offset) = vm.read_reg_as_balance(11) else {
            unreachable!(
                "as_balance() conversion should not fail: both RegValue and Balance are u64"
            )
        };
        // Only the privileged manager service can create new accounts with gratis storage
        if gratis_storage_offset != 0 && x.accumulate_host != x.partial_state.manager_service {
            continue_huh!()
        }

        // --- Check Balance (Err: CASH)

        let new_account_threshold_balance =
            AccountMetadata::get_initial_threshold_balance(code_lookup_len, gratis_storage_offset);

        // Check if the accumulate host service account's balance is sufficient
        // and subtract by the initial threshold balance to be transferred to the new account.
        let accumulator_metadata = x.get_accumulator_metadata(state_provider.clone()).await?;
        let accumulator_balance = accumulator_metadata.balance();
        let accumulator_threshold_balance = accumulator_metadata.threshold_balance();

        if accumulator_balance.saturating_sub(accumulator_threshold_balance)
            < new_account_threshold_balance
        {
            continue_cash!()
        }

        // --- Check Small Service ID Validity (Err: FULL)

        // Not used if this value is larger than `MIN_PUBLIC_SERVICE_ID`
        let new_small_service_id = vm.read_reg_as_service_id(12).unwrap_or(ServiceId::MAX);
        let has_small_service_id = new_small_service_id < MIN_PUBLIC_SERVICE_ID
            && x.accumulate_host == x.partial_state.registrar_service.last_confirmed;
        let new_small_service_id_already_taken = x
            .partial_state
            .accounts_sandbox
            .account_exists_anywhere(state_provider.clone(), new_small_service_id)
            .await?;

        if has_small_service_id && new_small_service_id_already_taken {
            continue_full!()
        }

        // --- OK

        x.subtract_accumulator_balance(state_provider.clone(), new_account_threshold_balance)
            .await?;

        let code_hash = Hash32::decode(&mut code_hash_octets.as_slice())?;
        let gas_limit_g = vm.read_reg(9);
        let gas_limit_m = vm.read_reg(10);
        let new_account_fields = NewAccountFields {
            code_hash: code_hash.clone(),
            balance: new_account_threshold_balance,
            gas_limit_accumulate: gas_limit_g,
            gas_limit_on_transfer: gas_limit_m,
            code_lookups_key: (code_hash, code_lookup_len),
            gratis_storage_offset,
            created_at: curr_timeslot_index,
            last_accumulate_at: 0,
            parent_service_id: x.accumulate_host,
        };

        // Add a new account to the partial state
        let new_service_id = if has_small_service_id {
            // Taking small service ids doesn't require rotating the next new service id
            x.add_new_special_account(
                state_provider.clone(),
                new_account_fields,
                new_small_service_id,
            )
            .await?
        } else {
            let new_service_id = x
                .add_new_regular_account(state_provider.clone(), new_account_fields)
                .await?;

            // Update the next new service account index in the partial state
            x.rotate_new_account_id(state_provider).await?;
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
        state_provider: Arc<S>,
        context: &mut InvocationContext<S>,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: UPGRADE");
        check_out_of_gas!(vm.gas_counter);
        let x = get_mut_accumulate_x!(context);

        // --- Read from Memory (Err: Panic)

        let Ok(offset) = vm.read_reg_as_mem_address(7) else {
            host_call_panic!()
        };
        if !vm.memory.is_address_range_readable(offset, HASH_SIZE) {
            host_call_panic!()
        }
        let Ok(code_hash_octets) = vm.memory.read_bytes(offset, HASH_SIZE) else {
            host_call_panic!()
        };

        // --- OK

        let gas_limit_g = vm.read_reg(8);
        let gas_limit_m = vm.read_reg(9);
        let code_hash = Hash32::decode(&mut code_hash_octets.as_slice())?;

        x.update_accumulator_metadata(state_provider, code_hash.clone(), gas_limit_g, gas_limit_m)
            .await?;
        tracing::debug!(
            "UPGRADE s={} code_hash={code_hash} g={gas_limit_g} m={gas_limit_m}",
            x.accumulate_host
        );
        continue_ok!()
    }

    // FIXME: GP v0.7.2 features (TRANSFER gas limit)
    /// Transfers tokens from the accumulating service account to another service account.
    pub async fn host_transfer(
        vm: &VMState,
        state_provider: Arc<S>,
        context: &mut InvocationContext<S>,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: TRANSFER");
        let x = get_mut_accumulate_x!(context);

        // --- Check Gas Charge (Err: OOG)

        let transfer_gas_limit = vm.read_reg(9);
        let gas_charge = HOSTCALL_BASE_GAS_CHARGE.saturating_add(transfer_gas_limit);
        check_out_of_gas!(vm.gas_counter, gas_charge);

        // --- Read from Memory (Err: Panic)

        let Ok(offset) = vm.read_reg_as_mem_address(10) else {
            host_call_panic!(gas_charge)
        };
        if !vm
            .memory
            .is_address_range_readable(offset, TRANSFER_MEMO_SIZE)
        {
            host_call_panic!(gas_charge)
        }
        let Ok(memo_encoded) = vm.memory.read_bytes(offset, TRANSFER_MEMO_SIZE) else {
            host_call_panic!(gas_charge)
        };
        let memo = ByteArray::<TRANSFER_MEMO_SIZE>::decode(&mut memo_encoded.as_slice())?;

        // --- Check Destination Service (Err: WHO)

        let Ok(dest) = vm.read_reg_as_service_id(7) else {
            continue_who!(gas_charge)
        };
        // Check the global state and the accumulate context partial state to confirm that the
        // destination account exists.
        let Some(dest_account_metadata) = x
            .partial_state
            .accounts_sandbox
            .get_account_metadata(state_provider.clone(), dest)
            .await?
            .cloned()
        else {
            continue_who!(gas_charge)
        };

        // --- Check Transfer Gas Limit (Err: LOW)

        let accumulator_metadata = x.get_accumulator_metadata(state_provider.clone()).await?;
        let accumulator_balance = accumulator_metadata.balance();
        let accumulator_threshold_balance = accumulator_metadata.threshold_balance();

        if transfer_gas_limit < dest_account_metadata.gas_limit_on_transfer {
            continue_low!(gas_charge)
        }

        // --- Check Sender Balance (Err: CASH)

        let amount = vm.read_reg(8);
        if accumulator_balance.saturating_sub(amount) < accumulator_threshold_balance {
            continue_cash!(gas_charge)
        }

        // --- OK

        x.subtract_accumulator_balance(state_provider, amount)
            .await?;

        let transfer = DeferredTransfer {
            from: x.accumulate_host,
            to: dest,
            amount,
            memo,
            gas_limit: transfer_gas_limit,
        };

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
        state_provider: Arc<S>,
        context: &mut InvocationContext<S>,
        curr_timeslot_index: TimeslotIndex,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: EJECT");
        check_out_of_gas!(vm.gas_counter);
        let x = get_mut_accumulate_x!(context);

        // --- Read from Memory (Err: Panic)

        let Ok(offset) = vm.read_reg_as_mem_address(8) else {
            host_call_panic!()
        };
        if !vm.memory.is_address_range_readable(offset, HASH_SIZE) {
            host_call_panic!()
        }
        let Ok(preimage_hash_octets) = vm.memory.read_bytes(offset, HASH_SIZE) else {
            host_call_panic!()
        };
        let preimage_hash = Hash32::decode(&mut preimage_hash_octets.as_slice())?;

        // --- Check Eject Privilege (Err: WHO)

        let Ok(eject_service_id) = vm.read_reg_as_service_id(7) else {
            continue_who!()
        };
        if eject_service_id == x.accumulate_host {
            continue_who!()
        }

        let Some(eject_account_metadata) = x
            .partial_state
            .accounts_sandbox
            .get_account_metadata(state_provider.clone(), eject_service_id)
            .await?
            .cloned()
        else {
            continue_who!()
        };

        let mut accumulate_host_encoded_32 = x.accumulate_host.encode_fixed(4)?;
        accumulate_host_encoded_32.resize(32, 0);
        let accumulate_host_as_hash = Hash32::decode(&mut accumulate_host_encoded_32.as_slice())?;
        if eject_account_metadata.code_hash != accumulate_host_as_hash {
            continue_who!()
        }

        // --- Check Eject Account Storage (Err: HUH)

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
            .get_account_lookups_entry(state_provider.clone(), eject_service_id, &lookups_key)
            .await?
        else {
            continue_huh!()
        };

        if entry.value.len() != 2
            || entry.value[1].slot() + PREIMAGE_EXPIRATION_PERIOD >= curr_timeslot_index
        {
            continue_huh!()
        }

        // --- OK

        x.add_accumulator_balance(state_provider.clone(), eject_account_metadata.balance())
            .await?;
        x.partial_state
            .accounts_sandbox
            .eject_account(state_provider, eject_service_id, lookups_key)
            .await?;
        tracing::debug!(
            "EJECT eject_s={eject_service_id} accumulate_s={}",
            x.accumulate_host
        );
        continue_ok!()
    }

    /// Queries the lookups storage's timeslot scopes to determine the availability of a preimage entry.
    pub async fn host_query(
        vm: &VMState,
        state_provider: Arc<S>,
        context: &mut InvocationContext<S>,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: QUERY");
        check_out_of_gas!(vm.gas_counter);
        let x = get_mut_accumulate_x!(context);

        // --- Read from Memory (Err: Panic)

        let Ok(offset) = vm.read_reg_as_mem_address(7) else {
            host_call_panic!()
        };
        if !vm.memory.is_address_range_readable(offset, HASH_SIZE) {
            host_call_panic!()
        }
        let Ok(preimage_hash_octets) = vm.memory.read_bytes(offset, HASH_SIZE) else {
            host_call_panic!()
        };
        let preimage_hash = Hash32::decode(&mut preimage_hash_octets.as_slice())?;

        // --- Check Preimage Lookups Manifest Entry (Err: NONE)

        let Ok(preimage_size) = vm.read_reg_as_u32(8) else {
            return Ok(HostCallResult::continue_with_vm_change(
                HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(HostCallReturnCode::NONE as RegValue),
                    r8_write: Some(0),
                    memory_write: None,
                },
            ));
        };
        let lookups_key = (preimage_hash, preimage_size);
        let Some(entry) = x
            .partial_state
            .accounts_sandbox
            .get_account_lookups_entry(state_provider, x.accumulate_host, &lookups_key)
            .await?
        else {
            return Ok(HostCallResult::continue_with_vm_change(
                HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(HostCallReturnCode::NONE as RegValue),
                    r8_write: Some(0),
                    memory_write: None,
                },
            ));
        };

        // --- OK

        // for debugging
        let (r7, r8, slots) = match entry.value.len() {
            0 => (0, 0, vec![]),
            1 => {
                let slot_0 = entry.value[0].slot();
                (1 + slot_0 as u64 * (1 << 32), 0, vec![slot_0])
            }
            2 => {
                let slot_0 = entry.value[0].slot();
                let slot_1 = entry.value[1].slot();
                (
                    2 + slot_0 as u64 * (1 << 32),
                    slot_1 as u64,
                    vec![slot_0, slot_1],
                )
            }
            3 => {
                let slot_0 = entry.value[0].slot();
                let slot_1 = entry.value[1].slot();
                let slot_2 = entry.value[2].slot();
                (
                    3 + slot_0 as u64 * (1 << 32),
                    slot_1 as u64 + slot_2 as u64 * (1 << 32),
                    vec![slot_0, slot_1, slot_2],
                )
            }
            _ => panic!("Should not have more than 3 timeslot values"),
        };
        tracing::debug!(
            "QUERY key=({}, {}) state_key={} slots={slots:?}",
            lookups_key.0,
            lookups_key.1,
            get_account_lookups_state_key(x.accumulate_host, &lookups_key)?,
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
        state_provider: Arc<S>,
        context: &mut InvocationContext<S>,
        curr_timeslot_index: TimeslotIndex,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: SOLICIT");
        check_out_of_gas!(vm.gas_counter);
        let x = get_mut_accumulate_x!(context);

        // --- Read from Memory (Err: Panic)

        let Ok(offset) = vm.read_reg_as_mem_address(7) else {
            host_call_panic!()
        };
        if !vm.memory.is_address_range_readable(offset, HASH_SIZE) {
            host_call_panic!()
        }
        let Ok(lookup_hash_octets) = vm.memory.read_bytes(offset, HASH_SIZE) else {
            host_call_panic!()
        };
        let lookup_hash = Hash32::decode(&mut lookup_hash_octets.as_slice())?;

        // TODO: Determine whether lookups size larger than `u32::MAX` should be allowed.
        // TODO: For now, continues with `FULL` code with no further threshold balance check.
        // TODO: Also check `host_query`, `host_forget`, `host_eject` which assume those lookups entry doesn't exist.
        let Ok(lookups_size) = vm.read_reg_as_u32(8) else {
            continue_full!()
        };

        let lookups_key = (lookup_hash, lookups_size);
        let prev_lookups_entry = x
            .partial_state
            .accounts_sandbox
            .get_account_lookups_entry(state_provider.clone(), x.accumulate_host, &lookups_key)
            .await?;

        // --- Check Preimage Solicit Status & Accumulate Host Balance (Err: HUH & FULL)

        // Insert current timeslot if the entry exists and the timeslot vector length is 2.
        // If the key doesn't exist, insert a new empty Vec<Timeslot> with the key.
        // If the entry's timeslot vector length is not equal to 2, return with result constant `HUH`.
        let (new_lookups_entry, storage_usage_delta) = match prev_lookups_entry {
            Some(mut entry) => {
                if entry.value.len() != 2 {
                    continue_huh!()
                }
                // Add current timeslot to the timeslot vector.
                let Ok(_) = entry.value.try_push(Timeslot::new(curr_timeslot_index)) else {
                    continue_huh!()
                };
                // If the lookups entry is simply updated by adding a new timeslot, footprints remain unchanged.
                (entry, None)
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
                    x.get_accumulator_metadata(state_provider.clone()).await?;
                let simulated_threshold_balance = accumulator_metadata
                    .simulate_threshold_balance_after_mutation(None, Some(lookups_usage_delta));

                if simulated_threshold_balance > accumulator_metadata.balance() {
                    continue_full!()
                }

                (
                    AccountLookupsEntryExt::from_entry(lookups_key.clone(), new_lookups_entry),
                    Some(lookups_usage_delta),
                )
            }
        };

        // --- OK

        // Apply the state change
        x.partial_state
            .accounts_sandbox
            .insert_account_lookups_entry(
                state_provider.clone(),
                x.accumulate_host,
                lookups_key.clone(),
                new_lookups_entry.clone(),
            )
            .await?;

        // Update storage footprints (added a new lookups entry)
        if let Some(lookups_delta) = storage_usage_delta {
            x.partial_state
                .accounts_sandbox
                .update_account_footprints(
                    state_provider.clone(),
                    x.accumulate_host,
                    AccountStorageUsageDelta {
                        lookups_delta,
                        ..Default::default()
                    },
                )
                .await?;
        }

        tracing::debug!(
            "SOLICIT s={} key=({}, {}) state_key={} post_slots={:?}",
            x.accumulate_host,
            lookups_key.0,
            lookups_key.1,
            get_account_lookups_state_key(x.accumulate_host, &lookups_key)?,
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
        state_provider: Arc<S>,
        context: &mut InvocationContext<S>,
        curr_timeslot_index: TimeslotIndex,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: FORGET");
        check_out_of_gas!(vm.gas_counter);
        let x = get_mut_accumulate_x!(context);

        // --- Read from Memory (Err: Panic)

        let Ok(offset) = vm.read_reg_as_mem_address(7) else {
            host_call_panic!()
        };
        if !vm.memory.is_address_range_readable(offset, HASH_SIZE) {
            host_call_panic!()
        }
        let Ok(lookup_hash_octets) = vm.memory.read_bytes(offset, HASH_SIZE) else {
            host_call_panic!()
        };
        let lookup_hash = Hash32::decode(&mut lookup_hash_octets.as_slice())?;

        // --- Check Preimage Status (Err: HUH)

        let Ok(lookup_len) = vm.read_reg_as_u32(8) else {
            continue_huh!()
        };

        let lookups_key = (lookup_hash.clone(), lookup_len);
        let lookups_entry = x
            .partial_state
            .accounts_sandbox
            .get_account_lookups_entry(state_provider.clone(), x.accumulate_host, &lookups_key)
            .await?;

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
                                state_provider.clone(),
                                x.accumulate_host,
                                lookup_hash,
                            )
                            .await?;
                        x.partial_state
                            .accounts_sandbox
                            .remove_account_lookups_entry(
                                state_provider.clone(),
                                x.accumulate_host,
                                lookups_key.clone(),
                            )
                            .await?;

                        // Update storage footprints (removed lookups entry)
                        let lookups_usage_delta =
                            AccountMetadata::calculate_storage_usage_delta(Some(&entry), None)
                                .unwrap_or_default();

                        x.partial_state
                            .accounts_sandbox
                            .update_account_footprints(
                                state_provider,
                                x.accumulate_host,
                                AccountStorageUsageDelta {
                                    lookups_delta: lookups_usage_delta,
                                    ..Default::default()
                                },
                            )
                            .await?;

                        tracing::debug!(
                            "FORGET key=({}, {}) state_key={} prev=[], curr=None",
                            lookups_key.0,
                            lookups_key.1,
                            get_account_lookups_state_key(x.accumulate_host, &lookups_key)?,
                        );
                        continue_ok!()
                    }
                    1 => {
                        // Add current timeslot to the lookups entry timeslot vector
                        let updated_lookups_entry = x
                            .partial_state
                            .accounts_sandbox
                            .push_timeslot_to_account_lookups_entry(
                                state_provider,
                                x.accumulate_host,
                                lookups_key.clone(),
                                Timeslot::new(curr_timeslot_index),
                            )
                            .await?
                            .ok_or(HostCallError::AccountLookupsEntryNotFound(
                                lookups_key.0.encode_hex(),
                                lookups_key.1,
                            ))?
                            .value
                            .as_slice()
                            .iter()
                            .map(Timeslot::slot)
                            .collect::<Vec<_>>();
                        tracing::debug!(
                            "FORGET key=({}, {}) state_key={} prev={:?}, curr={:?}",
                            lookups_key.0,
                            lookups_key.1,
                            get_account_lookups_state_key(x.accumulate_host, &lookups_key)?,
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
                            < curr_timeslot_index;
                        if is_expired {
                            if len == 2 {
                                // Remove preimage and lookups storage entry
                                x.partial_state
                                    .accounts_sandbox
                                    .remove_account_preimages_entry(
                                        state_provider.clone(),
                                        x.accumulate_host,
                                        lookup_hash,
                                    )
                                    .await?;
                                x.partial_state
                                    .accounts_sandbox
                                    .remove_account_lookups_entry(
                                        state_provider.clone(),
                                        x.accumulate_host,
                                        lookups_key.clone(),
                                    )
                                    .await?;

                                // Update storage footprints (removed lookups entry)
                                let lookups_usage_delta =
                                    AccountMetadata::calculate_storage_usage_delta(
                                        Some(&entry),
                                        None,
                                    )
                                    .unwrap_or_default();

                                x.partial_state
                                    .accounts_sandbox
                                    .update_account_footprints(
                                        state_provider,
                                        x.accumulate_host,
                                        AccountStorageUsageDelta {
                                            lookups_delta: lookups_usage_delta,
                                            ..Default::default()
                                        },
                                    )
                                    .await?;

                                tracing::debug!(
                                    "FORGET key=({}, {}) state_key={} prev={:?}, curr=None",
                                    lookups_key.0,
                                    lookups_key.1,
                                    get_account_lookups_state_key(x.accumulate_host, &lookups_key)?,
                                    lookups_timeslots
                                        .as_slice()
                                        .iter()
                                        .map(Timeslot::slot)
                                        .collect::<Vec<_>>(),
                                );
                            } else {
                                let prev_last_timeslot = lookups_timeslots.last().cloned().ok_or(
                                    HostCallError::AccountLookupsEntryMalformed(
                                        lookups_key.0.encode_hex(),
                                        lookups_key.1,
                                    ),
                                )?;
                                x.partial_state
                                    .accounts_sandbox
                                    .drain_account_lookups_entry_timeslots(
                                        state_provider.clone(),
                                        x.accumulate_host,
                                        lookups_key.clone(),
                                    )
                                    .await?;
                                let updated_lookups_entry = x
                                    .partial_state
                                    .accounts_sandbox
                                    .extend_timeslots_to_account_lookups_entry(
                                        state_provider,
                                        x.accumulate_host,
                                        lookups_key.clone(),
                                        vec![
                                            prev_last_timeslot,
                                            Timeslot::new(curr_timeslot_index),
                                        ],
                                    )
                                    .await?
                                    .ok_or(HostCallError::AccountLookupsEntryNotFound(
                                        lookups_key.0.encode_hex(),
                                        lookups_key.1,
                                    ))?
                                    .value
                                    .as_slice()
                                    .iter()
                                    .map(Timeslot::slot)
                                    .collect::<Vec<_>>();

                                tracing::debug!(
                                    "FORGET key=({}, {}) state_key={} prev={:?}, curr={:?}",
                                    lookups_key.0,
                                    lookups_key.1,
                                    get_account_lookups_state_key(x.accumulate_host, &lookups_key)?,
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
        context: &mut InvocationContext<S>,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: YIELD");
        check_out_of_gas!(vm.gas_counter);
        let x = get_mut_accumulate_x!(context);

        // --- Read from Memory (Err: Panic)

        let Ok(offset) = vm.read_reg_as_mem_address(7) else {
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

        // --- OK

        x.yielded_accumulate_hash = Some(commitment_hash.clone());
        tracing::debug!("YIELD commitment={commitment_hash}");
        continue_ok!()
    }

    /// Provides preimage data requested by services.
    pub async fn host_provide(
        service_id: ServiceId,
        vm: &VMState,
        state_provider: Arc<S>,
        context: &mut InvocationContext<S>,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: PROVIDE");
        check_out_of_gas!(vm.gas_counter);
        let x = get_mut_accumulate_x!(context);

        // --- Read from Memory (Err: Panic)

        let Ok(offset) = vm.read_reg_as_mem_address(8) else {
            host_call_panic!()
        };
        let Ok(preimage_size) = vm.read_reg_as_usize(9) else {
            host_call_panic!()
        };
        if !vm.memory.is_address_range_readable(offset, preimage_size) {
            host_call_panic!()
        }
        let Ok(preimage_data) = vm.memory.read_bytes(offset, preimage_size) else {
            host_call_panic!()
        };

        // --- Check Service Account Exists (Err: WHO)

        let service_id_reg = vm.read_reg(7);
        let service_id = if service_id_reg == u64::MAX {
            service_id
        } else {
            service_id_reg as ServiceId
        };

        // Service account not found
        if x.partial_state
            .accounts_sandbox
            .get_account_metadata(state_provider.clone(), service_id)
            .await?
            .is_none()
        {
            continue_who!()
        }

        // --- Check Preimage Solicit Status (Err: HUH)

        // Check current lookups entry
        let lookups_key = (hash::<Blake2b256>(&preimage_data)?, preimage_size as u32);
        let Some(lookups_entry) = x
            .partial_state
            .accounts_sandbox
            .get_account_lookups_entry(state_provider.clone(), service_id, &lookups_key)
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

        // --- OK

        // Insert the preimage entry
        x.provided_preimages.insert(provided_preimage_entry);
        tracing::debug!(
            "PROVIDE s={service_id} key=({}, {}) state_key={} len={data_len}",
            lookups_key.0,
            lookups_key.1,
            get_account_lookups_state_key(x.accumulate_host, &lookups_key)?,
        );
        continue_ok!()
    }
}
