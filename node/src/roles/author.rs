//! Block author actor
use rjam_block::types::block::{BlockHeaderData, BlockSeal, VrfSig};
use rjam_codec::{JamCodecError, JamEncode};
use rjam_common::{ticket::Ticket, CommonTypeError, Hash32, HASH_SIZE, X_E, X_F, X_T};
use rjam_crypto::{
    types::BandersnatchSecretKey,
    vrf::bandersnatch_vrf::{entropy_hash_ietf_vrf, VrfProver},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BlockSealError {
    #[error("Block seal output hash doesn't match ticket proof output hash")]
    InvalidBlockSealOutput,
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("CommonTypeError: {0}")]
    CommonTypeError(#[from] CommonTypeError),
}

/// Verifies output hash of the block seal matches the ticket used for the author selection.
pub fn author_block_seal_is_valid(seal: &BlockSeal, ticket: &Ticket) -> bool {
    let seal_output_hash = entropy_hash_ietf_vrf(seal);
    let ticket_output_hash = ticket.id;
    seal_output_hash == ticket_output_hash
}

pub fn generate_block_seal(
    header_data: BlockHeaderData,
    used_ticket: &Ticket,
    entropy_3: &Hash32,
    secret_key: &BandersnatchSecretKey,
) -> Result<BlockSeal, BlockSealError> {
    let prover = VrfProver::from_secret_key(*secret_key);
    let mut vrf_input = Vec::with_capacity(X_T.len() + entropy_3.len() + 1);
    vrf_input.extend_from_slice(X_T);
    vrf_input.extend_from_slice(entropy_3.as_slice());
    vrf_input.push(used_ticket.attempt);
    let aux_data = header_data.encode()?;
    let seal = prover.sign_vrf(&vrf_input, &aux_data);

    if !author_block_seal_is_valid(&seal, used_ticket) {
        return Err(BlockSealError::InvalidBlockSealOutput);
    }
    Ok(seal)
}

pub fn generate_fallback_block_seal(
    header_data: BlockHeaderData,
    entropy_3: &Hash32,
    secret_key: &BandersnatchSecretKey,
) -> Result<BlockSeal, BlockSealError> {
    let prover = VrfProver::from_secret_key(*secret_key);
    let mut vrf_input = Vec::with_capacity(X_F.len() + entropy_3.len());
    vrf_input.extend_from_slice(X_F);
    vrf_input.extend_from_slice(entropy_3.as_slice());
    let aux_data = header_data.encode()?;
    Ok(prover.sign_vrf(&vrf_input, &aux_data))
}

pub fn generate_entropy_source_vrf_signature(
    block_seal: BlockSeal,
    secret_key: &BandersnatchSecretKey,
) -> Result<VrfSig, BlockSealError> {
    let prover = VrfProver::from_secret_key(*secret_key);
    let mut vrf_input = Vec::with_capacity(X_E.len() + HASH_SIZE);
    let seal_output_hash = entropy_hash_ietf_vrf(&block_seal);
    vrf_input.extend_from_slice(X_E);
    vrf_input.extend_from_slice(seal_output_hash.as_slice());
    let aux_data = vec![]; // no message to sign
    Ok(prover.sign_vrf(&vrf_input, &aux_data))
}
