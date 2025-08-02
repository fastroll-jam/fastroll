#[cfg(test)]
mod tests;

use crate::{
    context::InvocationContext,
    error::HostCallError,
    host_functions::{HostCallResult, HostCallReturnCode},
    macros::*,
};
use fr_codec::prelude::*;
use fr_common::{
    utils::constants_encoder::encode_constants_for_fetch_hostcall, workloads::WorkPackage, Octets,
    ServiceId, SignedGas, UnsignedGas,
};
use fr_crypto::octets_to_hash32;
use fr_pvm_core::state::{
    register::Register, state_change::HostCallVMStateChange, vm_state::VMState,
};
use fr_pvm_types::{
    common::RegValue, constants::HOSTCALL_BASE_GAS_CHARGE, invoke_args::RefineInvokeArgs,
};
use fr_state::{
    provider::HostStateProvider,
    types::{AccountMetadata, AccountStorageEntry, AccountStorageEntryExt},
};
use std::{marker::PhantomData, sync::Arc};

pub struct GeneralHostFunction<S> {
    _phantom: PhantomData<S>,
}
impl<S: HostStateProvider> GeneralHostFunction<S> {
    /// Retrieves the current remaining gas limit of the VM state after deducting the base gas charge
    /// for executing this instruction.
    pub fn host_gas(vm: &VMState) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: GAS");
        check_out_of_gas!(vm.gas_counter);
        let gas_remaining =
            (vm.gas_counter as UnsignedGas).saturating_sub(HOSTCALL_BASE_GAS_CHARGE);
        tracing::debug!("GAS gas={gas_remaining}");
        continue_with_vm_change!(r7: gas_remaining)
    }

    /// Fetches various data types introduced as arguments of PVM entry-point invocations.
    pub fn host_fetch(
        vm: &VMState,
        context: &mut InvocationContext<S>,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: FETCH");
        let Ok(data_id) = vm.regs[10].as_usize() else {
            continue_none!()
        };

        let data: &[u8] = match context {
            InvocationContext::X_I(ctx) => match data_id {
                0 => &encode_constants_for_fetch_hostcall()?,
                id @ 7..=13 => {
                    let work_package = &ctx.invoke_args.package;
                    match Self::fetch_work_package_data(work_package, id, &vm.regs) {
                        Some(data) => &data.clone(),
                        None => continue_none!(),
                    }
                }
                _ => continue_none!(),
            },
            InvocationContext::X_R(ctx) => match data_id {
                0 => &encode_constants_for_fetch_hostcall()?,
                1 => ctx.refine_entropy.as_slice(),
                2 => &ctx.invoke_args.auth_trace,
                id @ 3..=6 => {
                    match Self::fetch_imports_extrinsics_data(&ctx.invoke_args, id, &vm.regs) {
                        Some(data) => &data.clone(),
                        None => continue_none!(),
                    }
                }
                id @ 7..=13 => {
                    let work_package = &ctx.invoke_args.package;
                    match Self::fetch_work_package_data(work_package, id, &vm.regs) {
                        Some(data) => &data.clone(),
                        None => continue_none!(),
                    }
                }
                _ => continue_none!(),
            },
            InvocationContext::X_A(pair) => {
                let x = pair.get_x();
                match data_id {
                    0 => &encode_constants_for_fetch_hostcall()?,
                    1 => x.curr_entropy.as_slice(),
                    14 => &x.invoke_args.inputs.inputs().encode()?,
                    15 => {
                        let acc_inputs = x.invoke_args.inputs.inputs();
                        let Ok(acc_input_idx) = vm.regs[11].as_usize() else {
                            continue_none!()
                        };
                        if acc_input_idx < acc_inputs.len() {
                            &acc_inputs[acc_input_idx].encode()?
                        } else {
                            continue_none!()
                        }
                    }
                    _ => continue_none!(),
                }
            }
        };

        let Ok(buf_offset) = vm.regs[7].as_mem_address() else {
            host_call_panic!()
        };
        let data_read_offset = vm.regs[8].as_usize().unwrap_or(data.len()).min(data.len());
        let min_data_read_size = data.len().saturating_sub(data_read_offset);
        let data_read_size = vm.regs[9]
            .as_usize()
            .unwrap_or(min_data_read_size)
            .min(min_data_read_size);

        if !vm
            .memory
            .is_address_range_writable(buf_offset, data_read_size)
        {
            host_call_panic!()
        }

        tracing::debug!("FETCH id={data_id} len={data_read_size}");
        continue_with_vm_change!(
            r7: data.len(),
            mem_offset: buf_offset,
            mem_data: data[data_read_offset..data_read_offset + data_read_size].to_vec()
        )
    }

    fn fetch_work_package_data(
        package: &WorkPackage,
        data_id: usize,
        regs: &[Register],
    ) -> Option<Vec<u8>> {
        match data_id {
            7 => package.encode().ok(),
            8 => {
                let mut buf = vec![];
                if package.auth_code_hash.encode_to(&mut buf).is_err() {
                    return None;
                }
                if package.config_blob.encode_to(&mut buf).is_err() {
                    return None;
                };
                Some(buf)
            }
            9 => Some(package.auth_token.clone().into_vec()),
            10 => package.context.encode().ok(),
            11 => {
                let mut work_items_buf = Vec::with_capacity(package.work_items.len());
                for item in package.work_items.iter() {
                    let work_item_encoded = match item.encode_for_fetch_hostcall() {
                        Ok(encoded) => encoded,
                        Err(_) => return None,
                    };
                    work_items_buf.push(work_item_encoded);
                }
                work_items_buf.encode().ok()
            }
            12 => {
                let work_item_idx = regs[11].as_usize().expect("11 is a valid reg index");
                if work_item_idx >= package.work_items.len() {
                    return None;
                }
                let work_item = &package.work_items[work_item_idx];
                work_item.encode_for_fetch_hostcall().ok()
            }
            13 => {
                let work_item_idx = regs[11].as_usize().expect("11 is a valid reg index");
                if work_item_idx >= package.work_items.len() {
                    return None;
                }
                let work_item = &package.work_items[work_item_idx];
                Some(work_item.payload_blob.clone().into_vec())
            }
            _ => None,
        }
    }

    fn fetch_imports_extrinsics_data(
        invoke_args: &RefineInvokeArgs,
        data_id: usize,
        regs: &[Register],
    ) -> Option<Vec<u8>> {
        match data_id {
            3 => {
                let items = &invoke_args.package.work_items;
                let item_idx = regs[11].as_usize().expect("11 is a valid reg index");
                let xt_idx = regs[12].as_usize().expect("12 is a valid reg index");
                if item_idx < items.len() && xt_idx < items[item_idx].extrinsic_data_info.len() {
                    let xt_info = &items[item_idx].extrinsic_data_info[xt_idx];
                    invoke_args.extrinsic_data_map.get(xt_info).cloned()
                } else {
                    None
                }
            }
            4 => {
                let items = &invoke_args.package.work_items;
                let item_idx = invoke_args.item_idx;
                let xt_idx = regs[11].as_usize().expect("11 is a valid reg index");
                if xt_idx < items[item_idx].extrinsic_data_info.len() {
                    let xt_info = &items[item_idx].extrinsic_data_info[xt_idx];
                    invoke_args.extrinsic_data_map.get(xt_info).cloned()
                } else {
                    None
                }
            }
            5 => {
                let item_idx = regs[11].as_usize().expect("11 is a valid reg index");
                let segment_idx = regs[12].as_usize().expect("12 is a valid reg index");
                let imports = &invoke_args.import_segments;
                if item_idx < imports.len() && segment_idx < imports[item_idx].len() {
                    Some(imports[item_idx][segment_idx].as_ref().to_vec())
                } else {
                    None
                }
            }
            6 => {
                let item_idx = invoke_args.item_idx;
                let segment_idx = regs[11].as_usize().expect("11 is a valid reg index");
                let imports = &invoke_args.import_segments;
                if segment_idx < imports[item_idx].len() {
                    Some(imports[item_idx][segment_idx].as_ref().to_vec())
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Fetches the preimage of the specified hash from the given service account's preimage storage
    /// and writes it into memory.
    pub async fn host_lookup(
        service_id: ServiceId,
        vm: &VMState,
        state_provider: Arc<S>,
        context: &mut InvocationContext<S>,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: LOOKUP");
        check_out_of_gas!(vm.gas_counter);
        let accounts_sandbox = get_mut_accounts_sandbox!(context);

        let service_id_reg = vm.regs[7].value();
        let Ok(hash_offset) = vm.regs[8].as_mem_address() else {
            host_call_panic!()
        };
        let Ok(buf_offset) = vm.regs[9].as_mem_address() else {
            host_call_panic!()
        };

        let service_id = if service_id_reg == u64::MAX || service_id_reg == service_id as u64 {
            service_id
        } else {
            service_id_reg as ServiceId
        };

        if !vm.memory.is_address_range_readable(hash_offset, 32) {
            host_call_panic!()
        }

        // Read preimage storage key (hash) from the memory
        let Ok(hash_octets) = vm.memory.read_bytes(hash_offset, 32) else {
            host_call_panic!()
        };
        let hash = octets_to_hash32(&hash_octets)
            .expect("Should not fail to convert 32-byte octets to Hash32 type");

        let Ok(Some(entry)) = accounts_sandbox
            .get_account_preimages_entry(state_provider, service_id, &hash)
            .await
        else {
            continue_none!()
        };

        let preimage_size = entry.value.len();
        let preimage_offset = vm.regs[10]
            .as_usize()
            .unwrap_or(preimage_size)
            .min(preimage_size);
        let min_lookup_size = preimage_size.saturating_sub(preimage_offset);
        let lookup_size = vm.regs[11]
            .as_usize()
            .unwrap_or(min_lookup_size)
            .min(min_lookup_size);

        if !vm.memory.is_address_range_writable(buf_offset, lookup_size) {
            host_call_panic!()
        }

        tracing::debug!("LOOKUP key={hash} len={lookup_size}");
        continue_with_vm_change!(
            r7: preimage_size,
            mem_offset: buf_offset,
            mem_data: entry.value[preimage_offset..preimage_offset + lookup_size].to_vec()
        )
    }

    /// Fetches the storage entry value of the specified storage key from the given service account's
    /// storage and writes it into memory.
    pub async fn host_read(
        service_id: ServiceId,
        vm: &VMState,
        state_provider: Arc<S>,
        context: &mut InvocationContext<S>,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: READ");
        check_out_of_gas!(vm.gas_counter);
        let accounts_sandbox = get_mut_accounts_sandbox!(context);

        let service_id_reg = vm.regs[7].value();
        let Ok(key_offset) = vm.regs[8].as_mem_address() else {
            host_call_panic!()
        };
        let Ok(key_size) = vm.regs[9].as_usize() else {
            host_call_panic!()
        };
        let Ok(buf_offset) = vm.regs[10].as_mem_address() else {
            host_call_panic!()
        };

        let service_id = if service_id_reg == u64::MAX {
            service_id
        } else {
            service_id_reg as ServiceId
        };

        if !vm.memory.is_address_range_readable(key_offset, key_size) {
            host_call_panic!()
        }

        let Ok(storage_key) = vm.memory.read_bytes(key_offset, key_size) else {
            host_call_panic!()
        };
        let storage_key = Octets::from_vec(storage_key);

        let Ok(Some(entry)) = accounts_sandbox
            .get_account_storage_entry(state_provider, service_id, &storage_key)
            .await
        else {
            continue_none!()
        };

        let storage_val_size = entry.value.len();
        let storage_val_offset = vm.regs[11]
            .as_usize()
            .unwrap_or(storage_val_size)
            .min(storage_val_size);
        let min_read_len = storage_val_size.saturating_sub(storage_val_offset);
        let read_len = vm.regs[12]
            .as_usize()
            .unwrap_or(min_read_len)
            .min(min_read_len);

        if !vm.memory.is_address_range_writable(buf_offset, read_len) {
            host_call_panic!()
        }

        tracing::debug!("READ key={storage_key} len={read_len}");
        continue_with_vm_change!(
            r7: storage_val_size,
            mem_offset: buf_offset,
            mem_data: entry.value[storage_val_offset..storage_val_offset + read_len].to_vec()
        )
    }

    /// Writes an entry to the storage of the service account hosting the code being executed,
    /// using a key and value read from the memory.
    /// If the value size is zero, the entry corresponding to the key is removed.
    /// The size of the previous value, if any, is returned via the register.
    pub async fn host_write(
        service_id: ServiceId,
        vm: &VMState,
        state_provider: Arc<S>,
        context: &mut InvocationContext<S>,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: WRITE");
        check_out_of_gas!(vm.gas_counter);
        let accounts_sandbox = get_mut_accounts_sandbox!(context);

        let Ok(key_offset) = vm.regs[7].as_mem_address() else {
            host_call_panic!()
        };
        let Ok(key_size) = vm.regs[8].as_usize() else {
            host_call_panic!()
        };
        let Ok(value_offset) = vm.regs[9].as_mem_address() else {
            host_call_panic!()
        };
        let Ok(value_size) = vm.regs[10].as_usize() else {
            host_call_panic!()
        };

        if !vm.memory.is_address_range_readable(key_offset, key_size)
            || (value_size > 0
                && !vm
                    .memory
                    .is_address_range_readable(value_offset, value_size))
        {
            host_call_panic!()
        }

        let Ok(storage_key) = vm.memory.read_bytes(key_offset, key_size) else {
            host_call_panic!()
        };
        let storage_key = Octets::from_vec(storage_key);

        // Threshold balance change simulation
        let maybe_prev_storage_entry = accounts_sandbox
            .get_account_storage_entry(state_provider.clone(), service_id, &storage_key)
            .await
            .ok()
            .flatten();

        let prev_storage_val_size_or_return_code = if let Some(ref entry) = maybe_prev_storage_entry
        {
            entry.value.len() as u64
        } else {
            HostCallReturnCode::NONE as u64
        };

        let new_storage_entry = if value_size == 0 {
            None
        } else {
            let Ok(write_val) = vm.memory.read_bytes(value_offset, value_size) else {
                host_call_panic!()
            };

            Some(AccountStorageEntryExt::from_entry(
                &storage_key,
                AccountStorageEntry {
                    value: Octets::from_vec(write_val),
                },
            ))
        };

        let storage_usage_delta = AccountMetadata::calculate_storage_usage_delta(
            maybe_prev_storage_entry.as_ref(),
            new_storage_entry.as_ref(),
        )
        .unwrap_or_default(); // Attempting to delete a storage entry that doesn't exist is basically a no-op

        if !storage_usage_delta.is_zero() {
            let metadata = accounts_sandbox
                .get_account_metadata(state_provider.clone(), service_id)
                .await?
                .ok_or(HostCallError::AccountNotFound)?; // unreachable (accumulate host / transfer subject account not found)

            let simulated_threshold_balance =
                metadata.simulate_threshold_balance_after_mutation(Some(storage_usage_delta), None);

            if simulated_threshold_balance > metadata.balance {
                continue_full!()
            }
        }

        // Apply the state change
        if let Some(new_entry) = new_storage_entry {
            accounts_sandbox
                .insert_account_storage_entry(
                    state_provider,
                    service_id,
                    storage_key.clone(),
                    new_entry,
                )
                .await
                .map_err(|_| HostCallError::AccountStorageInsertionFailed)?; // unreachable (accumulate host / transfer subject account not found)
        } else {
            // Remove the entry if the size of the new entry value is zero
            accounts_sandbox
                .remove_account_storage_entry(state_provider, service_id, storage_key.clone())
                .await
                .map_err(|_| HostCallError::AccountStorageRemovalFailed)?; // unreachable (accumulate host / transfer subject account not found)
        }

        tracing::debug!("WRITE key={storage_key} len={value_size}");
        continue_with_vm_change!(r7: prev_storage_val_size_or_return_code)
    }

    /// Retrieves the metadata of the specified account in a serialized format.
    pub async fn host_info(
        service_id: ServiceId,
        vm: &VMState,
        state_provider: Arc<S>,
        context: &mut InvocationContext<S>,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: INFO");
        check_out_of_gas!(vm.gas_counter);
        let accounts_sandbox = get_mut_accounts_sandbox!(context);

        let service_id_reg = vm.regs[7].value();
        let Ok(buf_offset) = vm.regs[8].as_mem_address() else {
            host_call_panic!()
        };

        let service_id = if service_id_reg == u64::MAX {
            service_id
        } else {
            service_id_reg as ServiceId
        };

        let Ok(Some(metadata)) = accounts_sandbox
            .get_account_metadata(state_provider, service_id)
            .await
        else {
            continue_none!()
        };

        // Encode account metadata with JAM Codec
        let info = metadata.encode_for_info_hostcall()?;

        // f
        let info_read_offset = match vm.regs[11].as_usize() {
            Ok(info_read_offset_reg) => info_read_offset_reg.min(info.len()),
            Err(_) => info.len(),
        };
        let info_blob_len_minus_offset = info
            .len()
            .checked_sub(info_read_offset)
            .expect("info_read_offset is less than info blob length");

        // l
        let info_write_len = match vm.regs[12].as_usize() {
            Ok(info_write_len_reg) => info_write_len_reg.min(info_blob_len_minus_offset),
            Err(_) => info_blob_len_minus_offset,
        };

        if !vm
            .memory
            .is_address_range_writable(buf_offset, info_write_len)
        {
            host_call_panic!()
        }

        let info_write = info[info_read_offset..info_read_offset + info_write_len].to_vec();
        tracing::debug!("INFO service_id={service_id} len={info_write_len}");
        continue_with_vm_change!(
            r7: info.len() as RegValue,
            mem_offset: buf_offset,
            mem_data: info_write
        )
    }
}
