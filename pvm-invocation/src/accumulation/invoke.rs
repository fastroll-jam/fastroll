#![allow(dead_code)]
use crate::{AccumulateResult, PVMInvocation};
use rjam_common::{Hash32, ServiceId, UnsignedGas};
use rjam_pvm_core::types::{
    accumulation::AccumulateOperand, error::PVMError, invoke_args::AccumulateInvokeArgs,
};
use rjam_state::StateManager;
use rjam_types::common::{transfers::DeferredTransfer, workloads::WorkReport};
use std::collections::HashMap;

type AccumulationOutputHash = Hash32;
type AccumulationOutputPairs = Vec<(ServiceId, AccumulationOutputHash)>;

struct ParallelAccumulationResult {
    /// `g*`: Total amount of gas used while executing `Δ*`.
    gas_used: UnsignedGas,
    /// **`t*`**: All deferred transfers created while executing `Δ*`.
    deferred_transfers: Vec<DeferredTransfer>,
    /// **`b*`**: All accumulation outputs created while executing `Δ*`.
    output_pairs: AccumulationOutputPairs,
}

#[derive(Default)]
pub struct OuterAccumulationResult {
    accumulated_reports_count: usize,
    deferred_transfers: Vec<DeferredTransfer>,
    /// The BEEFY commitment map of the accumulation
    output_pairs: AccumulationOutputPairs,
}

fn build_operands(reports: &[WorkReport], service_id: ServiceId) -> Vec<AccumulateOperand> {
    reports
        .iter()
        .flat_map(|wr| {
            wr.results()
                .iter()
                .filter(|wir| wir.service_id == service_id)
                .map(move |wir| AccumulateOperand {
                    work_output: wir.refine_output.clone(),
                    work_output_payload_hash: wir.payload_hash,
                    work_package_hash: wr.work_package_hash(),
                    authorization_output: wr.authorization_output().to_vec(),
                })
        })
        .collect()
}

/// Invokes the `accumulate` PVM entrypoint for a single service.
///
/// Represents `Δ1` of the GP.
async fn accumulate_single_service(
    state_manager: &StateManager,
    reports: &[WorkReport],
    always_accumulate_services: &HashMap<ServiceId, UnsignedGas>,
    service_id: ServiceId,
) -> Result<AccumulateResult, PVMError> {
    let operands = build_operands(reports, service_id);
    let mut gas_limit = always_accumulate_services
        .get(&service_id)
        .cloned()
        .unwrap_or(0);

    let reports_gas_aggregated: UnsignedGas = reports
        .iter()
        .flat_map(|wr| wr.results().iter())
        .filter(|wir| wir.service_id == service_id)
        .map(|wir| wir.gas_prioritization_ratio)
        .sum();

    gas_limit += reports_gas_aggregated;

    PVMInvocation::accumulate(
        state_manager,
        &AccumulateInvokeArgs {
            accumulate_host: service_id,
            gas_limit,
            operands,
        },
    )
    .await
}

/// Represents `Δ*` of the GP.
async fn accumulate_parallel(
    state_manager: &StateManager,
    reports: &[WorkReport],
    always_accumulate_services: &HashMap<ServiceId, UnsignedGas>,
) -> Result<ParallelAccumulationResult, PVMError> {
    let mut services: Vec<ServiceId> = reports
        .iter()
        .flat_map(|wr| wr.results().iter())
        .map(|wir| wir.service_id)
        .collect();

    services.extend(always_accumulate_services.keys().cloned());

    let mut gas_used: UnsignedGas = 0;
    let mut output_pairs = Vec::with_capacity(services.len());
    let mut deferred_transfers = Vec::new();

    // TODO: partial state accumulation
    // Accumulate invocations grouped by service ids.
    for service in services {
        let accumulate_result =
            accumulate_single_service(state_manager, reports, always_accumulate_services, service)
                .await?;
        gas_used += accumulate_result.gas_used;

        if let Some(output_hash) = accumulate_result.yielded_accumulate_hash {
            output_pairs.push((service, output_hash));
        }

        deferred_transfers.extend(accumulate_result.deferred_transfers);
    }

    Ok(ParallelAccumulationResult {
        gas_used,
        deferred_transfers,
        output_pairs,
    })
}

/// Represents `Δ+` of the GP.
pub async fn accumulate_outer(
    state_manager: &StateManager,
    gas_limit: UnsignedGas,
    reports: &[WorkReport],
    always_accumulate_services: &HashMap<ServiceId, UnsignedGas>,
) -> Result<OuterAccumulationResult, PVMError> {
    let mut always_accumulate_services = Some(always_accumulate_services.clone());
    let mut report_idx = 0usize; // i
    let mut remaining_gas_limit = gas_limit;

    let mut deferred_transfers_flattened = Vec::new();
    let mut output_pairs_flattened = Vec::new();

    loop {
        // All always accumulate services must be processed in the initial loop.
        let always_accumulate_services = always_accumulate_services.take().unwrap_or_default();

        let processable_reports_prediction =
            max_processable_reports(&reports[report_idx..], remaining_gas_limit);
        if processable_reports_prediction == 0 {
            break;
        }

        let ParallelAccumulationResult {
            gas_used,
            deferred_transfers,
            output_pairs,
        } = accumulate_parallel(
            state_manager,
            &reports[report_idx..report_idx + processable_reports_prediction],
            &always_accumulate_services,
        )
        .await?;

        report_idx += processable_reports_prediction;
        remaining_gas_limit = remaining_gas_limit.saturating_sub(gas_used);
        deferred_transfers_flattened.extend(deferred_transfers);
        output_pairs_flattened.extend(output_pairs);
    }

    Ok(OuterAccumulationResult {
        accumulated_reports_count: report_idx,
        deferred_transfers: deferred_transfers_flattened,
        output_pairs: output_pairs_flattened,
    })
}

fn max_processable_reports(reports: &[WorkReport], gas_limit: UnsignedGas) -> usize {
    let mut max_processable = 0;
    let mut gas_counter = 0;

    for report in reports {
        let report_gas_usage: UnsignedGas = report
            .results()
            .iter()
            .map(|wir| wir.gas_prioritization_ratio)
            .sum();

        if gas_counter + report_gas_usage > gas_limit {
            break;
        }

        gas_counter += report_gas_usage;
        max_processable += 1
    }

    max_processable
}
