use crate::entrypoints::accumulate::{AccumulateInvocation, AccumulateResult};
use fr_common::{
    workloads::work_report::WorkReport, LookupsKey, Octets, ServiceId, TimeslotIndex, UnsignedGas,
};
use fr_crypto::{hash, Blake2b256};
use fr_pvm_host::context::partial_state::AccumulatePartialState;
use fr_pvm_interface::error::PVMError;
use fr_pvm_types::{
    invoke_args::{AccumulateInvokeArgs, AccumulateOperand, DeferredTransfer},
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

pub mod utils;

#[derive(Default)]
pub struct OuterAccumulationResult {
    /// `n`: The total number of work reports accumulated.
    pub accumulated_reports_count: usize,
    /// **`o′`**: The union of posterior partial state of all service accounts.
    pub partial_state_union: AccumulatePartialState,
    /// **`t`**: The deferred transfers created by the accumulation.
    pub deferred_transfers: Vec<DeferredTransfer>,
    /// **`b`**: The posterior accumulation output log; pairs of service ids and accumulation output hashes.
    pub service_output_pairs: AccumulationOutputPairs,
    /// **`u`**: Pairs of service ids and gas usages.
    pub service_gas_pairs: AccumulationGasPairs,
}

struct ParallelAccumulationResult {
    /// **`u*`**: Amount of gas used for each service while executing `Δ*`.
    service_gas_pairs: AccumulationGasPairs,
    /// **`t*`**: All deferred transfers created while executing `Δ*`.
    deferred_transfers: Vec<DeferredTransfer>,
    /// **`b*`**: All accumulation outputs created while executing `Δ*`.
    service_output_pairs: AccumulationOutputPairs,
}

/// Represents `Δ+` of the GP.
pub async fn accumulate_outer(
    state_manager: Arc<StateManager>,
    gas_limit: UnsignedGas,
    reports: &[WorkReport],
    always_accumulate_services: &BTreeMap<ServiceId, UnsignedGas>,
) -> Result<OuterAccumulationResult, PVMError> {
    let mut always_accumulate_services = Some(always_accumulate_services.clone());
    let mut report_idx = 0usize; // i
    let mut remaining_gas_limit = gas_limit;

    let mut deferred_transfers_flattened = Vec::new();
    let mut service_gas_pairs_flattened = Vec::new();
    let mut service_output_pairs_flattened = BTreeSet::new();

    // Initialize accumulate partial state
    let mut partial_state_union = AccumulatePartialState::default();

    loop {
        // All always-accumulate services must be processed in the initial loop.
        let always_accumulate_services = always_accumulate_services.take().unwrap_or_default();

        let processable_reports_prediction =
            max_processable_reports(&reports[report_idx..], remaining_gas_limit);
        if processable_reports_prediction == 0 {
            break;
        }

        let ParallelAccumulationResult {
            service_gas_pairs,
            deferred_transfers,
            service_output_pairs: output_pairs,
        } = accumulate_parallel(
            state_manager.clone(),
            Arc::new(reports[report_idx..report_idx + processable_reports_prediction].to_vec()),
            Arc::new(always_accumulate_services),
            &mut partial_state_union,
        )
        .await?;

        report_idx += processable_reports_prediction;
        remaining_gas_limit =
            remaining_gas_limit.saturating_sub(service_gas_pairs.iter().map(|pair| pair.gas).sum());
        deferred_transfers_flattened.extend(deferred_transfers);
        service_gas_pairs_flattened.extend(service_gas_pairs);
        service_output_pairs_flattened.extend(output_pairs.0);
    }

    let service_output_pairs = AccumulationOutputPairs(service_output_pairs_flattened);

    Ok(OuterAccumulationResult {
        accumulated_reports_count: report_idx,
        deferred_transfers: deferred_transfers_flattened,
        service_gas_pairs: service_gas_pairs_flattened,
        service_output_pairs,
        partial_state_union,
    })
}

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

/// Represents `Δ*` of the GP.
async fn accumulate_parallel(
    state_manager: Arc<StateManager>,
    reports: Arc<Vec<WorkReport>>,
    always_accumulate_services: Arc<BTreeMap<ServiceId, UnsignedGas>>,
    partial_state_union: &mut AccumulatePartialState,
) -> Result<ParallelAccumulationResult, PVMError> {
    let curr_timeslot_index = state_manager.get_timeslot().await?.slot();

    let mut service_ids: BTreeSet<ServiceId> = reports
        .iter()
        .flat_map(|wr| wr.digests.iter())
        .map(|wd| wd.service_id)
        .collect();
    service_ids.extend(always_accumulate_services.keys().cloned());

    let services_count = service_ids.len();

    let mut service_gas_pairs = Vec::with_capacity(services_count);
    let mut service_output_pairs = BTreeSet::new();
    let mut deferred_transfers = Vec::new();

    // Concurrent accumulate invocations grouped by service ids.
    let mut handles = Vec::with_capacity(services_count);
    for service_id in service_ids {
        let state_manager_cloned = state_manager.clone();
        let reports_cloned = reports.clone();
        let always_accumulate_services_cloned = always_accumulate_services.clone();
        // each `Δ1` within the same `Δ*` batch has isolated view of the partial state
        let partial_state_cloned = partial_state_union.clone();

        let handle = tokio::spawn(async move {
            accumulate_single_service(
                state_manager_cloned,
                partial_state_cloned,
                reports_cloned,
                always_accumulate_services_cloned,
                service_id,
                curr_timeslot_index,
            )
            .await
        });
        handles.push(handle);
    }

    for handle in handles {
        let accumulate_result = handle
            .await
            .map_err(|_| PVMError::AccumulateTaskPanicked)??;
        service_gas_pairs.push(AccumulationGasPair {
            service: accumulate_result.accumulate_host,
            gas: accumulate_result.gas_used,
        });
        if let Some(output_hash) = accumulate_result.yielded_accumulate_hash {
            service_output_pairs.insert(AccumulationOutputPair {
                service: accumulate_result.accumulate_host,
                output_hash,
            });
        }
        deferred_transfers.extend(accumulate_result.deferred_transfers);
        add_partial_state_change(
            state_manager.clone(),
            accumulate_result.accumulate_host,
            partial_state_union,
            accumulate_result.partial_state,
        )
        .await;
        add_provided_preimages(
            state_manager.clone(),
            partial_state_union,
            accumulate_result.provided_preimages,
            curr_timeslot_index,
        )
        .await;
    }

    let service_output_pairs = AccumulationOutputPairs(service_output_pairs);

    Ok(ParallelAccumulationResult {
        service_gas_pairs,
        deferred_transfers,
        service_output_pairs,
    })
}

async fn add_partial_state_change(
    state_manager: Arc<StateManager>,
    accumulate_host: ServiceId,
    partial_state_union: &mut AccumulatePartialState,
    mut accumulate_result_partial_state: AccumulatePartialState,
) {
    if let (None, Some(new_staging_set)) = (
        &partial_state_union.new_staging_set,
        accumulate_result_partial_state.new_staging_set,
    ) {
        partial_state_union.new_staging_set = Some(new_staging_set);
    }
    if let (None, Some(new_auth_queue)) = (
        &partial_state_union.new_auth_queue,
        accumulate_result_partial_state.new_auth_queue,
    ) {
        partial_state_union.new_auth_queue = Some(new_auth_queue);
    }

    if partial_state_union.manager_service != accumulate_result_partial_state.manager_service {
        partial_state_union.manager_service = accumulate_result_partial_state.manager_service;
    }
    if partial_state_union.assign_services != accumulate_result_partial_state.assign_services {
        partial_state_union.assign_services = accumulate_result_partial_state.assign_services
    }
    if partial_state_union.designate_service != accumulate_result_partial_state.designate_service {
        partial_state_union.designate_service = accumulate_result_partial_state.designate_service;
    }
    if partial_state_union.always_accumulate_services
        != accumulate_result_partial_state.always_accumulate_services
    {
        partial_state_union.always_accumulate_services =
            accumulate_result_partial_state.always_accumulate_services;
    }

    let accumulate_host_sandbox = partial_state_union
        .accounts_sandbox
        .get_mut_account_sandbox(state_manager.clone(), accumulate_host)
        .await
        .unwrap()
        .expect("should not be None");
    *accumulate_host_sandbox = accumulate_result_partial_state
        .accounts_sandbox
        .get_account_sandbox(state_manager, accumulate_host)
        .await
        .unwrap()
        .cloned()
        .expect("should not be None");
}

/// Integrates all provided preimages by a single-service accumulation into the partial state accounts sandbox.
async fn add_provided_preimages(
    state_manager: Arc<StateManager>,
    partial_state_union: &mut AccumulatePartialState,
    provided_images: HashSet<(ServiceId, Octets)>,
    curr_timeslot_index: TimeslotIndex,
) {
    for (service_id, octets) in provided_images {
        // Construct storage keys
        let preimages_key =
            hash::<Blake2b256>(&octets).expect("should be able to hash some octets");
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
            .await
            .unwrap();

        // Push a timeslot value to the corresponding preimages lookups entry
        partial_state_union
            .accounts_sandbox
            .push_timeslot_to_account_lookups_entry(
                state_manager.clone(),
                service_id,
                lookups_key,
                Timeslot::new(curr_timeslot_index),
            )
            .await
            .unwrap();
    }
}

/// Invokes the `accumulate` PVM entrypoint for a single service.
///
/// Represents `Δ1` of the GP.
async fn accumulate_single_service(
    state_manager: Arc<StateManager>,
    partial_state: AccumulatePartialState,
    reports: Arc<Vec<WorkReport>>,
    always_accumulate_services: Arc<BTreeMap<ServiceId, UnsignedGas>>,
    service_id: ServiceId,
    curr_timeslot_index: TimeslotIndex,
) -> Result<AccumulateResult, PVMError> {
    let operands = build_operands(&reports, service_id);
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

    AccumulateInvocation::accumulate(
        state_manager,
        partial_state,
        &AccumulateInvokeArgs {
            curr_timeslot_index,
            accumulate_host: service_id,
            gas_limit,
            operands,
        },
    )
    .await
}

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
