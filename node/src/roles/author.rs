//! Block author actor

use rjam_block::types::block::{BlockHeader, BlockHeaderData};
use rjam_codec::JamEncode;
use rjam_common::{ticket::Ticket, BandersnatchSignature, Hash32, X_F, X_T};
use rjam_crypto::IetfVrfProver;
use std::error::Error;

#[allow(dead_code)]
pub(crate) fn seal_header(
    header_data: BlockHeaderData,
    used_ticket: Ticket,
    entropy_3: &Hash32,
    seed: &[u8],
) -> Result<BlockHeader, Box<dyn Error>> {
    let prover = IetfVrfProver::new(seed);
    let mut vrf_input = Vec::with_capacity(X_T.len() + entropy_3.len() + 1);
    vrf_input.extend_from_slice(X_T);
    vrf_input.extend_from_slice(entropy_3.as_slice());
    vrf_input.push(used_ticket.attempt);
    let aux_data = header_data.encode()?;
    let block_seal =
        BandersnatchSignature::try_from_vec(prover.ietf_vrf_sign(&vrf_input, &aux_data))?;

    // TODO: Check this matches `used_ticket.id`

    Ok(BlockHeader {
        header_data,
        block_seal,
    })
}

#[allow(dead_code)]
pub(crate) fn seal_header_fallback(
    header_data: BlockHeaderData,
    entropy_3: &Hash32,
    seed: &[u8],
) -> Result<BlockHeader, Box<dyn Error>> {
    let prover = IetfVrfProver::new(seed);
    let mut vrf_input = Vec::with_capacity(X_F.len() + entropy_3.len());
    vrf_input.extend_from_slice(X_F);
    vrf_input.extend_from_slice(entropy_3.as_slice());
    let aux_data = header_data.encode()?;
    let block_seal =
        BandersnatchSignature::try_from_vec(prover.ietf_vrf_sign(&vrf_input, &aux_data))?;

    Ok(BlockHeader {
        header_data,
        block_seal,
    })
}
