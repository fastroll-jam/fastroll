use crate::{
    error::PVMInvokeError,
    is_authorized::{IsAuthorizedInvocation, IsAuthorizedResult},
    refine::{RefineInvocation, RefineResult},
};
use fr_codec::prelude::*;
use fr_common::{
    utils::zero_pad::zero_pad,
    workloads::{
        AvailSpecs, ExtrinsicInfo, RefineStats, SegmentRootLookupTable, WorkDigest, WorkDigests,
        WorkExecutionResult, WorkItem, WorkPackage, WorkPackageId, WorkReport,
    },
    AuthHash, CoreIndex, ErasureRoot, NodeHash, Octets, UnsignedGas, ERASURE_CHUNK_SIZE,
    MAX_REPORT_DEPENDENCIES, SEGMENT_SIZE, VALIDATOR_COUNT, WORK_REPORT_OUTPUT_SIZE_LIMIT,
};
use fr_crypto::{hash, Blake2b256};
use fr_erasure_coding::{Chunk, ErasureCodec};
use fr_merkle::{
    constant_depth_tree::ConstantDepthMerkleTree, well_balanced_tree::WellBalancedMerkleTree,
};
use fr_pvm_types::{
    common::{ExportDataSegment, WorkPackageImportSegments},
    invoke_args::{IsAuthorizedInvokeArgs, RefineInvokeArgs},
};
use fr_state::manager::StateManager;
use std::{collections::HashMap, sync::Arc};

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

/// Paged-proofs function (`P`) which accepts export segments and returns justification data
/// which will be placed in D3L and are required for future verification.
fn generate_paged_proofs(
    export_segments: Vec<ExportDataSegment>,
) -> Result<Vec<ExportDataSegment>, PVMInvokeError> {
    const PAGE_DEPTH: usize = 6;
    const PAGE_SIZE: usize = 1 << PAGE_DEPTH; // 64

    let exports_vec = export_segments
        .into_iter()
        .map(Vec::<u8>::from)
        .collect::<Vec<_>>();

    let pages_count = exports_vec.len().div_ceil(PAGE_SIZE);
    let mut page_proofs = Vec::with_capacity(pages_count);
    for page_idx in 0..pages_count {
        let mut buf = Vec::new();
        let justification = ConstantDepthMerkleTree::<Blake2b256>::single_page_justification(
            &exports_vec,
            page_idx,
            PAGE_DEPTH,
        )?;
        let leaf_hashes = ConstantDepthMerkleTree::<Blake2b256>::subtree_page_leaf_hashes(
            &exports_vec,
            page_idx,
            PAGE_DEPTH,
        );
        justification.encode_to(&mut buf)?;
        leaf_hashes.encode_to(&mut buf)?;
        // TODO: check if the buffer always fits in a single block of size `SEGMENT_SIZE`.
        page_proofs.push(zero_pad::<SEGMENT_SIZE>(buf));
    }

    let page_proofs = page_proofs
        .into_iter()
        .map(|octets| {
            ExportDataSegment::try_from(octets)
                .expect("Zero padded justification data size exceeds SEGMENT_SIZE")
        })
        .collect::<Vec<_>>();
    Ok(page_proofs)
}

fn compute_erasure_root(
    work_bundle_encoded: Vec<u8>,
    export_segments: Vec<ExportDataSegment>,
) -> Result<ErasureRoot, PVMInvokeError> {
    const SINGLE_CHUNK_OCTETS: usize = 12; // 6 octet pairs as a single chunk unit for export segments erasure coding

    let erasure_codec = ErasureCodec::new_from_chain_spec();
    let bundle_chunked_hashed = erasure_codec
        .erasure_encode(&zero_pad::<ERASURE_CHUNK_SIZE>(work_bundle_encoded))?
        .into_iter()
        .map(|chunk| hash::<Blake2b256>(&chunk).expect("Hashing data chunks should be successful"))
        .collect::<Vec<_>>();

    let proof = generate_paged_proofs(export_segments.clone())?;
    let segments_with_proofs = [export_segments, proof].concat();
    let segments_with_proofs_len = segments_with_proofs.len();
    let segments_with_proofs_chunked = segments_with_proofs
        .into_iter()
        .map(|data| erasure_codec.erasure_encode(data.as_slice()))
        .collect::<Result<Vec<_>, _>>()?;

    // Transpose `Vec<Vec<Chunk>>` FROM:
    // `Vec<Vec<Chunk>>` where outer Vec having `segments_with_proofs_len` elements,
    // and inner Vecs each having `VALIDATOR_COUNT` elements
    //
    // INTO
    // `Vec<Vec<Chunk>>` where outer Vec has `VALIDATOR_COUNT` elements,
    // and inner Vecs each have `segments_with_proofs_len` elements.
    let mut segments_transposed: Vec<Vec<Chunk>> = (0..VALIDATOR_COUNT)
        .map(|_| {
            (0..segments_with_proofs_len)
                .map(|_| vec![0u8; SINGLE_CHUNK_OCTETS])
                .collect::<Vec<_>>()
        })
        .collect();

    for (i, single_segment_chunks) in segments_with_proofs_chunked.into_iter().enumerate() {
        for (j, chunk) in single_segment_chunks.into_iter().enumerate() {
            segments_transposed[j][i] = chunk;
        }
    }

    // Merklize each chunk group
    let segment_group_hashes = segments_transposed
        .into_iter()
        .map(|chunk_group| WellBalancedMerkleTree::<Blake2b256>::compute_root(&chunk_group))
        .collect::<Result<Vec<_>, _>>()?;

    let bundle_segment_chunks_paired = bundle_chunked_hashed
        .into_iter()
        .zip(segment_group_hashes)
        .map(|(b, s)| [b.as_slice(), s.as_slice()].concat())
        .collect::<Vec<_>>();

    let erasure_root =
        WellBalancedMerkleTree::<Blake2b256>::compute_root(&bundle_segment_chunks_paired)?;
    Ok(erasure_root)
}

fn build_avail_specs(
    package: &WorkPackage,
    auditable_bundle: AuditableBundle,
    export_segments: Vec<ExportDataSegment>,
) -> Result<AvailSpecs, PVMInvokeError> {
    let work_package_hash = hash::<Blake2b256>(&package.encode()?)?;

    let bundle_encoded = auditable_bundle.encode()?;
    let work_bundle_length = bundle_encoded.len() as u32;
    let segment_count = export_segments.len() as u16;
    let exports_vec = export_segments
        .clone()
        .into_iter()
        .map(Vec::<u8>::from)
        .collect::<Vec<_>>();
    let segment_root = ConstantDepthMerkleTree::<Blake2b256>::compute_root(&exports_vec)?;
    let erasure_root = compute_erasure_root(bundle_encoded, export_segments)?;

    Ok(AvailSpecs {
        work_package_hash,
        work_bundle_length,
        erasure_root,
        segment_root,
        segment_count,
    })
}

fn construct_extrinsic_data_info_map() -> HashMap<ExtrinsicInfo, Vec<u8>> {
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
fn construct_import_segments() -> WorkPackageImportSegments {
    unimplemented!()
}

/// `J`: Constructs import segments justifications, which are useful data for verifying correctness
/// of imports segments data using Merkle proof.
fn construct_import_justifications() -> Vec<Vec<Vec<NodeHash>>> {
    unimplemented!()
}

fn build_auditable_bundle(package: WorkPackage) -> AuditableBundle {
    AuditableBundle {
        package,
        extrinsic_data: construct_extrinsic_data(),
        imports: construct_import_segments(),
        imports_justifications: construct_import_justifications(),
    }
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
    core_index: CoreIndex,
) -> Result<WorkReport, PVMInvokeError> {
    let is_authorized_args = IsAuthorizedInvokeArgs {
        package: package.clone(),
        core_index,
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
        core_index,
        authorizer_hash: work_package_authorizer(&package),
        auth_gas_used,
        auth_trace,
        segment_roots_lookup: build_segment_roots_lookup_table(&package)?,
        digests,
    })
}
