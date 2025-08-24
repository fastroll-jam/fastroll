use crate::{
    error::PVMInvokeError,
    is_authorized::{IsAuthorizedInvocation, IsAuthorizedResult},
    refine::{
        auditable_bundle::{
            build_auditable_bundle, construct_extrinsic_data_info_map, construct_import_segments,
        },
        avail_spec::build_avail_specs,
        RefineInvocation, RefineResult,
    },
};
use fr_common::{
    workloads::{
        RefineStats, SegmentRootLookupTable, WorkDigest, WorkDigests, WorkExecutionResult,
        WorkItem, WorkPackage, WorkPackageId, WorkReport,
    },
    AuthHash, CoreIndex, UnsignedGas, MAX_REPORT_DEPENDENCIES, WORK_REPORT_OUTPUT_SIZE_LIMIT,
};
use fr_crypto::{hash, Blake2b256};
use fr_pvm_types::{
    common::ExportDataSegment,
    invoke_args::{IsAuthorizedInvokeArgs, RefineInvokeArgs},
};
use fr_state::manager::StateManager;
use std::sync::Arc;

/// Converts a work item and its associated execution result into a work digest.
fn work_item_to_digest(
    item: &WorkItem,
    result: WorkExecutionResult,
    refine_gas_used: UnsignedGas,
) -> WorkDigest {
    WorkDigest {
        service_id: item.service_id,
        service_code_hash: item.service_code_hash.clone(),
        payload_hash: hash::<Blake2b256>(item.payload_blob.as_slice())
            .expect("Hashing a payload blob should be successful"),
        accumulate_gas_limit: item.accumulate_gas_limit,
        refine_result: result,
        refine_stats: RefineStats {
            refine_gas_used,
            imports_count: item.import_segment_ids.len() as u16,
            extrinsics_count: item.extrinsic_data_info.len() as u16,
            extrinsics_octets: item
                .extrinsic_data_info
                .iter()
                .map(|xt| xt.blob_length)
                .sum::<u32>(),
            exports_count: item.export_segment_count,
        },
    }
}

fn work_package_authorizer(package: &WorkPackage) -> AuthHash {
    hash::<Blake2b256>(
        &[
            package.auth_code_hash.as_slice(),
            package.config_blob.as_slice(),
        ]
        .concat(),
    )
    .expect("Hashing blobs should be successful")
}

fn build_segment_roots_lookup_table(
    package: &WorkPackage,
) -> Result<SegmentRootLookupTable, PVMInvokeError> {
    let lookup_entries_count = package.work_items.iter().fold(0, |acc, wi| {
        acc + wi
            .import_segment_ids
            .iter()
            .filter(|&import_info| {
                matches!(
                    import_info.work_package_id,
                    WorkPackageId::WorkPackageHash(_)
                )
            })
            .count()
    });
    if lookup_entries_count > MAX_REPORT_DEPENDENCIES {
        return Err(PVMInvokeError::SegmentLookupTableTooLarge);
    }
    unimplemented!("Recover work-packages being referenced and execute `compute_work_report` function to get erasure-roots corresponding to provided work-package hashes")
}

/// Replace export segments with zeros to nullify exported data
fn zeroize_export_segments(exports: &mut Vec<ExportDataSegment>) {
    exports.iter_mut().for_each(|export_segment| {
        *export_segment = ExportDataSegment::default();
    })
}

/// Computes a work-package into a corresponding work-report, invoking `refine` PVM entry-point (`Ψ_R`).
///
/// Represents `Ξ` of the GP.
pub async fn compute_work_report(
    state_manager: Arc<StateManager>,
    package: WorkPackage,
    core_idx: CoreIndex,
) -> Result<WorkReport, PVMInvokeError> {
    let is_authorized_args = IsAuthorizedInvokeArgs {
        package: package.clone(),
        core_index: core_idx,
    };
    let IsAuthorizedResult {
        gas_used: auth_gas_used,
        work_execution_result,
    } = IsAuthorizedInvocation::is_authorized(state_manager.clone(), &is_authorized_args).await?;

    let auth_trace = match work_execution_result {
        WorkExecutionResult::Output(octets) => {
            if octets.len() > WORK_REPORT_OUTPUT_SIZE_LIMIT {
                return Err(PVMInvokeError::WorkReportBlobTooLarge);
            }
            octets
        }
        WorkExecutionResult::Error(e) => {
            return Err(PVMInvokeError::WorkPackageNotAuthorized(e));
        }
    };

    // Invoke Refine entry-point for each work-item
    let work_items_count = package.work_items.len();
    let mut export_segments_offset = 0usize;
    let mut work_report_blob_size = auth_trace.len();
    let mut digests: WorkDigests = Vec::with_capacity(work_items_count).try_into().unwrap();
    let mut exports = Vec::with_capacity(work_items_count);

    for item_idx in 0..work_items_count {
        // Construct Refine invoke args
        let args = RefineInvokeArgs {
            item_idx,
            package: package.clone(),
            auth_trace: auth_trace.clone().into_vec(),
            import_segments: construct_import_segments(),
            export_segments_offset,
            extrinsic_data_map: construct_extrinsic_data_info_map(),
        };

        let RefineResult {
            gas_used: refine_gas_used,
            mut output,
            mut export_segments,
        } = RefineInvocation::refine(state_manager.clone(), &args).await?;

        if let WorkExecutionResult::Output(octets) = &output {
            work_report_blob_size += octets.len();
        }

        export_segments_offset += package.work_items[item_idx].export_segment_count as usize;

        // Handle error cases
        if work_report_blob_size > WORK_REPORT_OUTPUT_SIZE_LIMIT {
            // Work report blob size exceeds the limit
            output = WorkExecutionResult::oversize();
            zeroize_export_segments(&mut export_segments);
        } else if export_segments.len()
            != package.work_items[item_idx].export_segment_count as usize
        {
            // Export items count mismatch
            output = WorkExecutionResult::wrong_exports_count();
            zeroize_export_segments(&mut export_segments);
        } else if let WorkExecutionResult::Error(_) = output {
            // Work execution error
            zeroize_export_segments(&mut export_segments);
        } else {
            exports.push(export_segments);
        }

        let digest = work_item_to_digest(&package.work_items[item_idx], output, refine_gas_used);
        digests
            .try_push(digest)
            .expect("Number of work-items and digests are bounded by LimitedVec types");
    }

    Ok(WorkReport {
        specs: build_avail_specs(
            &package,
            build_auditable_bundle(package.clone()),
            exports.into_iter().flatten().collect(),
        )?,
        refinement_context: package.context.clone(),
        core_index: core_idx,
        authorizer_hash: work_package_authorizer(&package),
        auth_gas_used,
        auth_trace,
        segment_roots_lookup: build_segment_roots_lookup_table(&package)?,
        digests,
    })
}
