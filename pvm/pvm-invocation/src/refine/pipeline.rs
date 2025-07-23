use fr_codec::prelude::*;
use fr_common::{
    workloads::{RefineStats, WorkDigest, WorkExecutionResult, WorkItem, WorkPackage, WorkReport},
    CoreIndex, NodeHash, Octets, UnsignedGas, SEGMENT_SIZE,
};
use fr_crypto::{hash, Blake2b256};
use fr_pvm_types::common::ExportDataSegment;

/// A work bundle ready for auditing, with all reference data collected along with a work-package.
pub struct AuditableBundle {
    pub package: WorkPackage,
    pub extrinsic_data: Vec<Vec<Octets>>,
    pub imports: Vec<Vec<ExportDataSegment>>,
    /// Collection of sibling (opposite) node hashes along the merkle path of each import segment
    pub imports_justifications: Vec<Vec<Vec<NodeHash>>>,
}

impl JamEncode for AuditableBundle {
    fn size_hint(&self) -> usize {
        self.package.size_hint()
            + self
                .package
                .work_items
                .iter()
                .map(|wi| {
                    wi.extrinsic_data_info
                        .iter()
                        .map(|xt| xt.blob_length as usize)
                        .sum::<usize>()
                        + wi.import_segment_ids.len() * SEGMENT_SIZE
                })
                .sum::<usize>()
            + self
                .imports_justifications
                .iter()
                .map(|wi_justifications| {
                    wi_justifications
                        .iter()
                        .map(|justification| justification.size_hint())
                        .sum::<usize>()
                })
                .sum::<usize>()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.package.encode_to(dest)?;
        // No length prefixes except for the justifications' merkle paths

        // Iterate on extrinsic data field of all work-items in a work-package.
        for work_item_xts in &self.extrinsic_data {
            for work_item_xt in work_item_xts {
                dest.write(work_item_xt.as_slice());
            }
        }
        // Iterate on import segments field of all work-items in a work-package.
        for work_item_segments in &self.imports {
            for segment in work_item_segments {
                segment.encode_to(dest)?;
            }
        }
        // Iterate on import justifications field of all work-items in a work-package.
        for work_item_justifications in &self.imports_justifications {
            for justification in work_item_justifications {
                justification.encode_to(dest)?; // Vec<T> is length-prefixed by default
            }
        }
        Ok(())
    }
}

impl JamDecode for AuditableBundle {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        let package = WorkPackage::decode(input)?;
        let work_items_count = package.work_items.len();

        // Decode extrinsic data
        let mut extrinsic_data = Vec::with_capacity(work_items_count);
        for work_item in &package.work_items {
            let mut work_item_xts = Vec::with_capacity(work_item.extrinsic_data_info.len());
            for xt_info in &work_item.extrinsic_data_info {
                let blob_length = xt_info.blob_length as usize;
                let mut blob = vec![0u8; blob_length];
                input.read(&mut blob)?;
                work_item_xts.push(Octets::from_vec(blob));
            }
            extrinsic_data.push(work_item_xts);
        }

        // Decode imports segments
        let mut imports = Vec::with_capacity(work_items_count);
        for work_item in &package.work_items {
            let mut work_item_segments = Vec::with_capacity(work_item.import_segment_ids.len());
            for _ in &work_item.import_segment_ids {
                let segment = ExportDataSegment::decode(input)?;
                work_item_segments.push(segment);
            }
            imports.push(work_item_segments);
        }

        // Decode justifications of imports segments
        let mut imports_justifications = Vec::with_capacity(work_items_count);
        for work_item in &package.work_items {
            let mut work_item_justifications =
                Vec::with_capacity(work_item.import_segment_ids.len());
            for _ in &work_item.import_segment_ids {
                let justification = Vec::<NodeHash>::decode(input)?;
                work_item_justifications.push(justification);
            }
            imports_justifications.push(work_item_justifications);
        }

        Ok(Self {
            package,
            extrinsic_data,
            imports,
            imports_justifications,
        })
    }
}

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

/// Computes a work-package into a corresponding work-report, invoking `refine` PVM entry-point (`Ψ_R`).
///
/// Represents `Ξ` of the GP.
pub fn compute_work_report(_package: WorkPackage, _core_index: CoreIndex) -> WorkReport {
    unimplemented!()
}
