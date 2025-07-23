use fr_common::{
    workloads::{RefineStats, WorkDigest, WorkExecutionResult, WorkItem},
    UnsignedGas,
};
use fr_crypto::{hash, Blake2b256};

/// Converts a work item and its associated execution result into a work digest.
pub fn work_item_to_digest(
    item: WorkItem,
    result: WorkExecutionResult,
    refine_gas_used: UnsignedGas,
) -> WorkDigest {
    WorkDigest {
        service_id: item.service_id,
        service_code_hash: item.service_code_hash,
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
