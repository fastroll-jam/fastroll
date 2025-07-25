use fr_codec::prelude::*;
use fr_common::{
    workloads::{ExtrinsicInfo, WorkPackage},
    NodeHash, Octets, SEGMENT_SIZE,
};
use fr_pvm_types::common::{ExportDataSegment, WorkPackageImportSegments};
use std::collections::HashMap;

/// A work bundle ready for auditing, with all reference data collected along with a work-package.
///
/// This should be collected by guarantors and then placed in Audit DA so that auditors can execute
/// refinement of work-packages without interacting with D3L.
pub struct AuditableBundle {
    pub package: WorkPackage,
    pub extrinsic_data: Vec<Vec<Octets>>,
    pub imports: WorkPackageImportSegments,
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

pub(crate) fn construct_extrinsic_data_info_map() -> HashMap<ExtrinsicInfo, Vec<u8>> {
    unimplemented!()
}

/// `X`: Collects extrinsic data, which are refine arguments. This should be submitted by builders
/// and therefore known by guarantors.
fn construct_extrinsic_data() -> Vec<Vec<Octets>> {
    unimplemented!()
}

/// `S`: Collects imports segments data from sufficient number of validators (D3L) and recovers the whole
/// imports segments from the segment root and item indices. Returns import segments used by an
/// entire work-package.
pub(crate) fn construct_import_segments() -> WorkPackageImportSegments {
    unimplemented!()
}

/// `J`: Constructs import segments justifications, which are useful data for verifying correctness
/// of imports segments data using Merkle proof.
fn construct_import_justifications() -> Vec<Vec<Vec<NodeHash>>> {
    unimplemented!()
}

pub(crate) fn build_auditable_bundle(package: WorkPackage) -> AuditableBundle {
    AuditableBundle {
        package,
        extrinsic_data: construct_extrinsic_data(),
        imports: construct_import_segments(),
        imports_justifications: construct_import_justifications(),
    }
}
