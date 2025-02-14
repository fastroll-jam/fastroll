#![allow(dead_code)]
use crate::{AccumulateResult, PVMInvocation};
use rjam_common::{Address, Hash32, UnsignedGas};
use rjam_pvm_core::types::{
    accumulation::AccumulateOperand, error::PVMError, invoke_args::AccumulateInvokeArgs,
};
use rjam_state::StateManager;
use rjam_types::common::{transfers::DeferredTransfer, workloads::WorkReport};
use std::collections::HashMap;

type AccumulationOutputHash = Hash32;
type AccumulationOutputPairs = Vec<(Address, AccumulationOutputHash)>;

struct ParallelAccumulationResult {
    gas_used: UnsignedGas,
    deferred_transfers: Vec<DeferredTransfer>,
    output_pairs: AccumulationOutputPairs,
}

#[derive(Default)]
pub struct OuterAccumulationResult {
    accumulation_counter: usize,
    deferred_transfers: Vec<DeferredTransfer>,
    output_pairs: AccumulationOutputPairs,
}

fn build_operands(reports: &[WorkReport], service_index: Address) -> Vec<AccumulateOperand> {
    reports
        .iter()
        .flat_map(|report| {
            report
                .results()
                .iter()
                .filter(|result| result.service_index == service_index)
                .map(move |result| AccumulateOperand {
                    work_output: result.refine_output.clone(),
                    work_output_payload_hash: result.payload_hash,
                    work_package_hash: report.work_package_hash(),
                    authorization_output: report.authorization_output().to_vec(),
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
    always_accumulate_services: &HashMap<Address, UnsignedGas>,
    service_index: Address,
) -> Result<AccumulateResult, PVMError> {
    let operands = build_operands(reports, service_index);
    let mut gas = always_accumulate_services
        .get(&service_index)
        .cloned()
        .unwrap_or(0);

    let reports_gas_aggregated: UnsignedGas = reports
        .iter()
        .flat_map(|report| report.results().iter())
        .filter(|result| result.service_index == service_index)
        .map(|result| result.gas_prioritization_ratio)
        .sum();

    gas += reports_gas_aggregated;

    PVMInvocation::accumulate(
        state_manager,
        &AccumulateInvokeArgs {
            accumulate_host: service_index,
            gas_limit: gas,
            operands,
        },
    )
    .await
}

/// Represents `Δ*` of the GP.
async fn accumulate_parallelized(
    state_manager: &StateManager,
    reports: &[WorkReport],
    always_accumulate_services: &HashMap<Address, UnsignedGas>,
) -> Result<ParallelAccumulationResult, PVMError> {
    let mut services: Vec<Address> = reports
        .iter()
        .flat_map(|report| report.results().iter())
        .map(|result| result.service_index)
        .collect();

    services.append(&mut always_accumulate_services.keys().cloned().collect());

    let mut gas_used: UnsignedGas = 0; // u
    let mut output_pairs = Vec::with_capacity(services.len()); // b
    let mut deferred_transfers = Vec::new(); // t

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

// FIXME: Update recursion to iteration
// /// Represents `Δ+` of the GP.
// pub async fn accumulate_outer(
//     state_manager: &StateManager,
//     gas_limit: UnsignedGas,
//     reports: Vec<WorkReport>,
//     always_accumulate_services: &HashMap<Address, UnsignedGas>,
// ) -> Result<OuterAccumulationResult, PVMError> {
//     if reports.is_empty() {
//         return Ok(OuterAccumulationResult::default());
//     }
//
//     let mut accumulated_reports = 0;
//     let mut current_gas = 0;
//     let mut current_reports = Vec::new();
//
//     // Find the maximum number of reports that can be accumulated within the gas limit
//     for report in reports.iter() {
//         let report_gas: UnsignedGas = report
//             .results()
//             .iter()
//             .map(|r| r.gas_prioritization_ratio)
//             .sum();
//         if current_gas + report_gas > gas_limit {
//             break;
//         }
//         current_gas += report_gas;
//         current_reports.push(report.clone());
//         accumulated_reports += 1;
//     }
//
//     // Accumulate the reports that fit within the gas limit
//     let ParallelAccumulationResult {
//         gas_used,               // g*
//         mut deferred_transfers, // t*
//         mut output_pairs,       // b*
//     } = accumulate_parallelized(state_manager, &current_reports, always_accumulate_services).await?;
//
//     // Recursively process remaining reports
//     if accumulated_reports < reports.len() {
//         let result = accumulate_outer(
//             state_manager,
//             gas_limit - gas_used,
//             &reports[accumulated_reports..],
//             &HashMap::new(),
//         ).await?;
//
//         accumulated_reports += result.accumulation_counter;
//         deferred_transfers.extend(result.deferred_transfers);
//         output_pairs.extend(result.output_pairs);
//     }
//
//     Ok(OuterAccumulationResult {
//         accumulation_counter: accumulated_reports,
//         deferred_transfers,
//         output_pairs,
//     })
// }
