use crate::{
    accumulate::{AccumulateInvocation, AccumulateResult},
    error::PVMInvokeError,
};
use fr_common::{
    workloads::work_report::WorkReport, LookupsKey, Octets, ServiceId, TimeslotIndex, UnsignedGas,
};
use fr_crypto::{hash, Blake2b256};
use fr_pvm_host::context::partial_state::{
    AccumulatePartialState, SandboxEntryAccessor, SandboxEntryStatus,
};
use fr_pvm_types::{
    invoke_args::{AccumulateInputs, AccumulateInvokeArgs, AccumulateOperand, DeferredTransfer},
    invoke_results::{
        AccumulationGasPair, AccumulationGasPairs, AccumulationOutputPair, AccumulationOutputPairs,
    },
};
use fr_state::{
    manager::StateManager,
    types::{AccountPreimagesEntry, Timeslot},
};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    sync::Arc,
};
use tracing::instrument;

#[derive(Default)]
pub struct OuterAccumulationResult {
    /// `n`: The total number of work reports accumulated.
    pub accumulated_reports_count: usize,
    /// **`o′`**: The union of posterior partial state of all service accounts.
    pub partial_state_union: AccumulatePartialState<StateManager>,
    /// **`b`**: The posterior accumulation output log; pairs of service ids and accumulation output hashes.
    pub service_output_pairs: AccumulationOutputPairs,
    /// **`u`**: Pairs of service ids and gas usages.
    pub service_gas_pairs: AccumulationGasPairs,
}

#[inline]
fn max_processable_reports(reports: &[WorkReport], gas_limit: UnsignedGas) -> usize {
    let mut max_processable = 0;
    let mut gas_counter = 0;

    for report in reports {
        let report_gas_usage: UnsignedGas = report
            .digests
            .iter()
            .map(|wd| wd.accumulate_gas_limit)
            .sum();

        if gas_counter + report_gas_usage > gas_limit {
            break;
        }

        gas_counter += report_gas_usage;
        max_processable += 1
    }

    max_processable
}

/// Represents `Δ+` of the GP.
#[instrument(level = "debug", skip_all, name = "acc_seq")]
pub async fn accumulate_outer(
    state_manager: Arc<StateManager>,
    gas_limit: UnsignedGas,
    reports: &[WorkReport],
    always_accumulate_services: &BTreeMap<ServiceId, UnsignedGas>,
) -> Result<OuterAccumulationResult, PVMInvokeError> {
    let mut always_accumulate_services = Some(always_accumulate_services.clone());
    let mut report_idx = 0usize; // i
    let mut remaining_gas_limit = gas_limit;

    let mut service_gas_pairs_flattened = Vec::new();
    let mut service_output_pairs_flattened = BTreeSet::new();

    // Initialize accumulate partial state
    let mut partial_state_union = AccumulatePartialState::new(state_manager.clone()).await?;

    // There is no deferred transfers in the initial round of `Δ+`
    let mut deferred_transfers = Vec::new();

    loop {
        let has_reports_remaining = report_idx < reports.len();
        let has_deferred_transfers = !deferred_transfers.is_empty();
        if !has_reports_remaining && !has_deferred_transfers && always_accumulate_services.is_none()
        {
            break;
        }

        // All always-accumulate services must be processed in the initial loop.
        let always_accumulate_services = always_accumulate_services.take().unwrap_or_default();

        let processable_reports_prediction = if has_reports_remaining {
            max_processable_reports(&reports[report_idx..], remaining_gas_limit)
        } else {
            0
        };

        if processable_reports_prediction == 0
            && !has_deferred_transfers
            && always_accumulate_services.is_empty()
        {
            break;
        }

        let reports_to_process = if processable_reports_prediction > 0 {
            reports[report_idx..report_idx + processable_reports_prediction].to_vec()
        } else {
            Vec::new()
        };

        let ParallelAccumulationResult {
            service_gas_pairs,
            new_deferred_transfers,
            service_output_pairs: output_pairs,
        } = accumulate_parallel(
            state_manager.clone(),
            Arc::new(deferred_transfers),
            Arc::new(reports_to_process),
            Arc::new(always_accumulate_services),
            &mut partial_state_union,
        )
        .await?;

        tracing::info!(
            "Δ* Executed:\n\tservice_gas_pairs: {service_gas_pairs:?}\n\tdeferred_xfers: {new_deferred_transfers:?}\n\toutput_pairs: {output_pairs:?}",
        );

        deferred_transfers = new_deferred_transfers;
        report_idx += processable_reports_prediction;
        let gas_used = service_gas_pairs.iter().map(|pair| pair.gas).sum();
        remaining_gas_limit = remaining_gas_limit.saturating_sub(gas_used);
        service_gas_pairs_flattened.extend(service_gas_pairs);
        service_output_pairs_flattened.extend(output_pairs.0);
    }

    let service_output_pairs = AccumulationOutputPairs(service_output_pairs_flattened);

    Ok(OuterAccumulationResult {
        accumulated_reports_count: report_idx,
        service_gas_pairs: service_gas_pairs_flattened,
        service_output_pairs,
        partial_state_union,
    })
}

struct ParallelAccumulationResult {
    /// **`u*`**: Amount of gas used for each service while executing `Δ*`.
    service_gas_pairs: AccumulationGasPairs,
    /// **`t*`**: All deferred transfers created while executing `Δ*`.
    new_deferred_transfers: Vec<DeferredTransfer>,
    /// **`b*`**: All accumulation outputs created while executing `Δ*`.
    service_output_pairs: AccumulationOutputPairs,
}

/// Merges changes produced by a single-service accumulation into the `partial_state_union`.
async fn merge_partial_state_change(
    state_manager: Arc<StateManager>,
    accumulate_host: ServiceId,
    partial_state_union: &mut AccumulatePartialState<StateManager>,
    mut accumulate_result_partial_state: AccumulatePartialState<StateManager>,
) -> Result<(), PVMInvokeError> {
    // Accumulating service sandbox
    let accumulate_host_sandbox = partial_state_union
        .accounts_sandbox
        .get_mut_account_sandbox(state_manager.clone(), accumulate_host)
        .await?
        .ok_or(PVMInvokeError::MissingAccumulateHostSandbox(
            accumulate_host,
        ))?;

    // Ejected accounts cannot produce state diff (no code)
    if accumulate_host_sandbox.is_ejected().await {
        return Ok(());
    }

    // Merge StagingSet changes
    if accumulate_host == partial_state_union.designate_service.last_confirmed {
        if let Some(new_staging_set) = accumulate_result_partial_state.new_staging_set {
            partial_state_union.new_staging_set = Some(new_staging_set);
        }
    }

    // Merge AuthQueue changes
    let original_assigners = &accumulate_result_partial_state
        .assign_services
        .last_confirmed;

    // Update per-core auth queues for cores whose assigner matches the current accumulate host.
    for (core_idx, original_assigner) in original_assigners.iter().enumerate() {
        if *original_assigner == accumulate_host {
            if let (Some(source_queue), Some(union_queue)) = (
                accumulate_result_partial_state.auth_queue.0.get(core_idx),
                partial_state_union.auth_queue.0.get_mut(core_idx),
            ) {
                if union_queue != source_queue {
                    *union_queue = source_queue.clone();
                }
            }
        }
    }

    // Merge PrivilegedServices changes

    // Extra check - only manager can mutate manager / always-accumulate services
    let manager_invoked_bless = accumulate_result_partial_state
        .assign_services
        .change_by_manager
        .is_some();
    if manager_invoked_bless {
        partial_state_union.manager_service = accumulate_result_partial_state.manager_service;
        partial_state_union.always_accumulate_services = accumulate_result_partial_state
            .always_accumulate_services
            .clone();
    }

    partial_state_union
        .assign_services
        .merge_changes_from(&accumulate_result_partial_state.assign_services)?;

    partial_state_union
        .designate_service
        .merge_changes_from(&accumulate_result_partial_state.designate_service);

    partial_state_union
        .registrar_service
        .merge_changes_from(&accumulate_result_partial_state.registrar_service);

    // Accumulate host state change
    *accumulate_host_sandbox = accumulate_result_partial_state
        .accounts_sandbox
        .get_account_sandbox(state_manager, accumulate_host)
        .await?
        .cloned()
        .ok_or(PVMInvokeError::MissingAccumulateHostSandbox(
            accumulate_host,
        ))?;

    // Integrate new accounts and ejected accounts.
    // Note: no account other than the accumulate host is ever touched except for the
    // `NEW` & `EJECT` hostcalls.
    accumulate_result_partial_state
        .accounts_sandbox
        .iter()
        .filter(|(&service_id, _)| service_id != accumulate_host)
        .for_each(|(&service_id, sandbox)| {
            match sandbox.metadata.status() {
                SandboxEntryStatus::Added => {
                    // Additional guard to avoid entries from the `partial_state_union` with `Added`
                    // status being copied into the later accumulations and overwriting any updates.
                    #[allow(clippy::map_entry)]
                    if !partial_state_union
                        .accounts_sandbox
                        .contains_key(&service_id)
                    {
                        partial_state_union
                            .accounts_sandbox
                            .insert(service_id, sandbox.clone());
                    }
                }
                SandboxEntryStatus::Removed => {
                    partial_state_union
                        .accounts_sandbox
                        .insert(service_id, sandbox.clone());
                }
                _ => {}
            }
        });

    Ok(())
}

/// Integrates all provided preimages by a single-service accumulation into the partial state accounts sandbox.
async fn add_provided_preimages(
    state_manager: Arc<StateManager>,
    partial_state_union: &mut AccumulatePartialState<StateManager>,
    provided_images: HashSet<(ServiceId, Octets)>,
    curr_timeslot_index: TimeslotIndex,
) -> Result<(), PVMInvokeError> {
    for (service_id, octets) in provided_images {
        // Construct storage keys
        let preimages_key = hash::<Blake2b256>(&octets)?;
        let lookups_key: LookupsKey = (preimages_key.clone(), octets.len() as u32);

        // Insert an entry to the preimages storage
        partial_state_union
            .accounts_sandbox
            .insert_account_preimages_entry(
                state_manager.clone(),
                service_id,
                preimages_key,
                AccountPreimagesEntry::new(octets),
            )
            .await?;

        // Push a timeslot value to the corresponding preimages lookups entry
        partial_state_union
            .accounts_sandbox
            .push_timeslot_to_account_lookups_entry(
                state_manager.clone(),
                service_id,
                lookups_key,
                Timeslot::new(curr_timeslot_index),
            )
            .await?;
    }
    Ok(())
}

/// Represents `Δ*` of the GP.
#[instrument(level = "debug", skip_all, name = "acc_par")]
async fn accumulate_parallel(
    state_manager: Arc<StateManager>,
    prev_deferred_transfers: Arc<Vec<DeferredTransfer>>,
    reports: Arc<Vec<WorkReport>>,
    always_accumulate_services: Arc<BTreeMap<ServiceId, UnsignedGas>>,
    partial_state_union: &mut AccumulatePartialState<StateManager>,
) -> Result<ParallelAccumulationResult, PVMInvokeError> {
    tracing::info!("Δ* invoked");
    let curr_timeslot_index = state_manager.get_timeslot().await?.slot();

    // Accumulating service groups: 1) With Digests 2) Transfer Receivers 3) Always-accumulates 4) Privileged Services
    let services_with_digests: BTreeSet<ServiceId> = reports
        .iter()
        .flat_map(|wr| wr.digests.iter())
        .map(|wd| wd.service_id)
        .collect();
    let services_with_transfers: BTreeSet<ServiceId> =
        prev_deferred_transfers.iter().map(|t| t.to).collect();
    let always_accumulate_service_ids: BTreeSet<ServiceId> =
        always_accumulate_services.keys().cloned().collect();
    let privileged_services = BTreeSet::from_iter(
        partial_state_union
            .assign_services
            .last_confirmed
            .iter()
            .cloned()
            .chain([
                partial_state_union.registrar_service.last_confirmed,
                partial_state_union.designate_service.last_confirmed,
                partial_state_union.manager_service,
            ]),
    );
    tracing::info!("Δ* Services:\n\tWithDigests: {services_with_digests:?},\n\tWithXfers: {services_with_transfers:?},\n\tAlwaysAccumulates: {always_accumulate_service_ids:?},\n\tPrivileges: {privileged_services:?}");

    // **s** of `Δ*` equation
    let mut metered_services = services_with_digests.clone();
    metered_services.extend(services_with_transfers.clone());
    metered_services.extend(always_accumulate_service_ids.clone());

    let mut all_service_ids: BTreeSet<ServiceId> = services_with_digests;
    all_service_ids.extend(always_accumulate_service_ids);
    all_service_ids.extend(services_with_transfers);
    all_service_ids.extend(privileged_services);

    let mut service_gas_pairs = Vec::new();
    let mut service_output_pairs = BTreeSet::new();
    let mut new_deferred_transfers = Vec::new();

    // Concurrent accumulate invocations grouped by service ids.
    let mut results = Vec::with_capacity(all_service_ids.len());
    for service_id in all_service_ids {
        let state_manager_cloned = state_manager.clone();
        let prev_transfers_cloned = prev_deferred_transfers.clone();
        let reports_cloned = reports.clone();
        let always_accumulate_services_cloned = always_accumulate_services.clone();
        // each `Δ1` within the same `Δ*` batch has isolated view of the partial state
        let partial_state_cloned = partial_state_union.clone();

        // Note: Running sequentially for easier debugging
        let acc_result = accumulate_single_service(
            state_manager_cloned,
            partial_state_cloned,
            prev_transfers_cloned,
            reports_cloned,
            always_accumulate_services_cloned,
            service_id,
            curr_timeslot_index,
        )
        .await?;
        results.push(acc_result);
    }

    for accumulate_result in results.into_iter().flatten() {
        // Merge partial state changes for all accumulated services
        merge_partial_state_change(
            state_manager.clone(),
            accumulate_result.accumulate_host,
            partial_state_union,
            accumulate_result.partial_state,
        )
        .await?;

        // Note: Accumulations of privileged services are not metered (accumulate outputs / gas usages)
        if metered_services.contains(&accumulate_result.accumulate_host) {
            // Add service gas usage stats entry
            service_gas_pairs.push(AccumulationGasPair {
                service: accumulate_result.accumulate_host,
                gas: accumulate_result.gas_used,
            });

            // Add service accumulate output
            if let Some(output_hash) = accumulate_result.yielded_accumulate_hash {
                service_output_pairs.insert(AccumulationOutputPair {
                    service: accumulate_result.accumulate_host,
                    output_hash,
                });
            }

            // Add deferred transfers
            new_deferred_transfers.extend(accumulate_result.deferred_transfers);

            // Add provided preimages
            add_provided_preimages(
                state_manager.clone(),
                partial_state_union,
                accumulate_result.provided_preimages,
                curr_timeslot_index,
            )
            .await?;
        }
    }

    // Multiple services that are accumulated in the same `Δ*` round can produce conflicting
    // changes to the privileged services: assigners, designate and registrar.
    // So at this point, `partial_state_union` may hold `Some` variants for both `change_by_manager`
    // and `change_by_self` fields for partial state of the privileged services.
    //
    // If such conflicts happen, changes by the manager services should be prioritized over changes
    // by the privileged services themselves. This behavior is described in the `R(o, a, b)` util
    // function of the Graypaper.
    //
    // Once the state change is confirmed, partial state change fields of the union should be cleared.

    // Confirm the new assign services
    if let Some(new_assign_services_by_manager) =
        &partial_state_union.assign_services.change_by_manager
    {
        partial_state_union.assign_services.last_confirmed = new_assign_services_by_manager.clone();
    } else {
        for (core_idx, new_assign_service_by_self) in
            &partial_state_union.assign_services.change_by_self
        {
            if let Some(assign) = partial_state_union
                .assign_services
                .last_confirmed
                .get_mut(*core_idx as usize)
            {
                *assign = *new_assign_service_by_self;
            }
        }
    }

    // Confirm the new designate service
    if let Some(new_designate_service_by_manager) =
        partial_state_union.designate_service.change_by_manager
    {
        partial_state_union.designate_service.last_confirmed = new_designate_service_by_manager;
    } else if let Some(new_designate_service_by_self) =
        partial_state_union.designate_service.change_by_self
    {
        partial_state_union.designate_service.last_confirmed = new_designate_service_by_self;
    }

    // Confirm the new registrar service
    if let Some(new_registrar_service_by_manager) =
        partial_state_union.registrar_service.change_by_manager
    {
        partial_state_union.registrar_service.last_confirmed = new_registrar_service_by_manager;
    } else if let Some(new_registrar_service_by_self) =
        partial_state_union.registrar_service.change_by_self
    {
        partial_state_union.registrar_service.last_confirmed = new_registrar_service_by_self;
    }

    // Clear state changes marked in `partial_state_union`, since they are resolved
    partial_state_union.clear_privileged_services_changes();

    Ok(ParallelAccumulationResult {
        service_gas_pairs,
        new_deferred_transfers,
        service_output_pairs: AccumulationOutputPairs(service_output_pairs),
    })
}

#[inline]
fn build_operands(reports: &[WorkReport], service_id: ServiceId) -> Vec<AccumulateOperand> {
    reports
        .iter()
        .flat_map(|wr| {
            wr.digests
                .iter()
                .filter(|wd| wd.service_id == service_id)
                .map(move |wd| AccumulateOperand {
                    work_package_hash: wr.work_package_hash().clone(),
                    segment_root: wr.segment_root().clone(),
                    authorizer_hash: wr.authorizer_hash.clone(),
                    work_item_payload_hash: wd.payload_hash.clone(),
                    accumulate_gas_limit: wd.accumulate_gas_limit,
                    refine_result: wd.refine_result.clone(),
                    auth_trace: wr.auth_trace.to_vec(),
                })
        })
        .collect()
}

#[inline]
fn extract_transfers(
    transfers: &[DeferredTransfer],
    service_id: ServiceId,
) -> Vec<DeferredTransfer> {
    transfers
        .iter()
        .filter(|&t| t.to == service_id)
        .cloned()
        .collect()
}

/// Invokes the `accumulate` PVM entrypoint for a single service.
///
/// Represents `Δ1` of the GP.
#[instrument(level = "debug", skip_all, name = "acc_one")]
async fn accumulate_single_service(
    state_manager: Arc<StateManager>,
    partial_state: AccumulatePartialState<StateManager>,
    prev_deferred_transfers: Arc<Vec<DeferredTransfer>>,
    reports: Arc<Vec<WorkReport>>,
    always_accumulate_services: Arc<BTreeMap<ServiceId, UnsignedGas>>,
    service_id: ServiceId,
    curr_timeslot_index: TimeslotIndex,
) -> Result<Option<AccumulateResult<StateManager>>, PVMInvokeError> {
    let mut gas_limit = always_accumulate_services
        .get(&service_id)
        .cloned()
        .unwrap_or(0);

    let reports_gas_aggregated: UnsignedGas = reports
        .iter()
        .flat_map(|wr| wr.digests.iter())
        .filter(|wd| wd.service_id == service_id)
        .map(|wd| wd.accumulate_gas_limit)
        .sum();

    gas_limit += reports_gas_aggregated;

    let deferred_transfers_gas_aggregated: UnsignedGas = prev_deferred_transfers
        .iter()
        .filter(|&transfer| transfer.to == service_id)
        .map(|transfer| transfer.gas_limit)
        .sum();

    gas_limit += deferred_transfers_gas_aggregated;

    AccumulateInvocation::<StateManager>::accumulate(
        state_manager,
        partial_state,
        &AccumulateInvokeArgs {
            curr_timeslot_index,
            accumulate_host: service_id,
            gas_limit,
            inputs: AccumulateInputs::new(
                extract_transfers(&prev_deferred_transfers, service_id),
                build_operands(&reports, service_id),
            ),
        },
    )
    .await
}
