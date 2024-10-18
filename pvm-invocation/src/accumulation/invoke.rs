use rjam_common::{Address, WorkReport};
use rjam_pvm_core::types::accumulation::AccumulateOperand;

fn build_operands(reports: &[WorkReport], service_index: Address) -> Vec<AccumulateOperand> {
    reports
        .iter()
        .flat_map(|report| {
            report
                .results()
                .iter()
                .filter(|result| result.service_index == service_index)
                .map(move |result| AccumulateOperand {
                    work_output: result.refinement_output.clone(),
                    work_output_payload_hash: result.payload_hash,
                    work_package_hash: report.work_package_hash(),
                    authorization_output: report.authorization_output().to_vec(),
                })
        })
        .collect()
}
