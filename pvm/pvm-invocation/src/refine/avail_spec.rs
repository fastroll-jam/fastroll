use crate::{error::PVMInvokeError, refine::auditable_bundle::AuditableBundle};
use fr_codec::prelude::*;
use fr_common::{
    is_validator_set_size,
    utils::zero_pad::zero_pad,
    workloads::{AvailSpecs, WorkPackage},
    ErasureRoot, SEGMENT_SIZE,
};
use fr_crypto::{hash, Blake2b256};
use fr_erasure_coding::{Chunk, ErasureCodec};
use fr_merkle::{
    constant_depth_tree::ConstantDepthMerkleTree, well_balanced_tree::WellBalancedMerkleTree,
};
use fr_pvm_types::common::ExportDataSegment;

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
        )?;
        justification.encode_to(&mut buf)?;
        leaf_hashes.encode_to(&mut buf)?;
        // TODO: check if the buffer always fits in a single block of size `SEGMENT_SIZE`.
        page_proofs.push(zero_pad::<SEGMENT_SIZE>(buf));
    }

    let page_proofs = page_proofs
        .into_iter()
        .map(|octets| {
            ExportDataSegment::try_from(octets)
                .map_err(|_| PVMInvokeError::PagedProofJustificationBlobTooLarge)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(page_proofs)
}

/// Computes the erasure root `u` over `erasure_shards` chunks, one per assuring validator.
fn compute_erasure_root(
    work_bundle_encoded: Vec<u8>,
    export_segments: Vec<ExportDataSegment>,
    erasure_shards: usize,
) -> Result<ErasureRoot, PVMInvokeError> {
    let erasure_codec = ErasureCodec::new(erasure_shards);
    // Octets per chunk of an export segment, e.g. 12 with 1023 validators
    let single_chunk_octets = SEGMENT_SIZE / erasure_codec.msg_chunks();

    // The codec zero-pads the bundle to a multiple of `2 * d(v)` octets.
    let bundle_chunked_hashed = erasure_codec
        .erasure_encode(&work_bundle_encoded)?
        .into_iter()
        .map(|chunk| hash::<Blake2b256>(&chunk))
        .collect::<Result<Vec<_>, _>>()?;

    let proof = generate_paged_proofs(export_segments.clone())?;
    let segments_with_proofs = [export_segments, proof].concat();
    let segments_with_proofs_len = segments_with_proofs.len();
    let segments_with_proofs_chunked = segments_with_proofs
        .into_iter()
        .map(|data| erasure_codec.erasure_encode(data.as_slice()))
        .collect::<Result<Vec<_>, _>>()?;

    // Transpose `Vec<Vec<Chunk>>` FROM:
    // `Vec<Vec<Chunk>>` where outer Vec having `segments_with_proofs_len` elements,
    // and inner Vecs each having `erasure_shards` elements
    //
    // INTO
    // `Vec<Vec<Chunk>>` where outer Vec has `erasure_shards` elements,
    // and inner Vecs each have `segments_with_proofs_len` elements.
    let mut segments_transposed: Vec<Vec<Chunk>> = (0..erasure_shards)
        .map(|_| {
            (0..segments_with_proofs_len)
                .map(|_| vec![0u8; single_chunk_octets])
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

/// Builds the availability specifier `A` of a work package, erasure-coded into `erasure_shards` chunks.
pub(crate) fn build_avail_specs(
    package: &WorkPackage,
    auditable_bundle: AuditableBundle,
    export_segments: Vec<ExportDataSegment>,
    erasure_shards: u16,
) -> Result<AvailSpecs, PVMInvokeError> {
    if !is_validator_set_size(erasure_shards as usize) {
        return Err(PVMInvokeError::InvalidErasureShards(erasure_shards));
    }
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
    let erasure_root =
        compute_erasure_root(bundle_encoded, export_segments, erasure_shards as usize)?;

    Ok(AvailSpecs {
        work_package_hash,
        work_bundle_length,
        erasure_root,
        erasure_shards,
        segment_root,
        segment_count,
    })
}
