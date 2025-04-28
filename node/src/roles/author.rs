//! Block author actor
use rjam_block::types::block::{BlockHeaderData, BlockSeal, VrfSig};
use rjam_codec::prelude::*;
use rjam_common::{ticket::Ticket, CommonTypeError, Hash32, HASH_SIZE, X_E, X_F, X_T};
use rjam_crypto::{
    traits::VrfSignature, types::BandersnatchSecretKey, vrf::bandersnatch_vrf::VrfProver,
};
use rjam_state::types::SlotSealer;
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
    let seal_output_hash = seal.output_hash();
    let ticket_output_hash = ticket.id.clone();
    seal_output_hash == ticket_output_hash
}

/// Seals the block header as the block author, in regular (ticket) mode.
///
/// Note: This signing should be done ***after*** signing the VRF signature of the header.
pub fn sign_block_seal(
    header_data: BlockHeaderData,
    used_ticket: &Ticket,
    entropy_3: &Hash32,
    secret_key: &BandersnatchSecretKey,
) -> Result<BlockSeal, BlockSealError> {
    let prover = VrfProver::from_secret_key(secret_key);
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

/// Seals the block header as the block author, in fallback mode.
///
/// Note: This signing should be done ***after*** signing the VRF signature of the header.
pub fn sign_fallback_block_seal(
    header_data: BlockHeaderData,
    entropy_3: &Hash32,
    secret_key: &BandersnatchSecretKey,
) -> Result<BlockSeal, BlockSealError> {
    let prover = VrfProver::from_secret_key(secret_key);
    let mut vrf_input = Vec::with_capacity(X_F.len() + entropy_3.len());
    vrf_input.extend_from_slice(X_F);
    vrf_input.extend_from_slice(entropy_3.as_slice());
    let aux_data = header_data.encode()?;
    Ok(prover.sign_vrf(&vrf_input, &aux_data))
}

/// Produces VRF signature as the block author.
/// This is later used as the epochal entropy source.
///
/// According to the GP, the block seal's output hash is used to sign the entropy source vrf signature.
/// However, since the VRF signature must be produced prior to the block seal,
/// this function uses VRF output hash values which are equivalent to the seal output.
///
/// In regular (ticket) mode, this is the ticket id used in the contest.
/// In fallback mode, this can be produced by conducting the same signing for the block sealing with
/// the aux data (message) omitted.
///
/// Note: The aux data (message) doesn't affect the VRF output hash value.
pub fn sign_entropy_source_vrf_signature(
    slot_sealer: &SlotSealer,
    entropy_3: &Hash32,
    secret_key: &BandersnatchSecretKey,
) -> Result<VrfSig, BlockSealError> {
    let prover = VrfProver::from_secret_key(secret_key);

    // This value is equivalent to `Y` hash output of the block seal.
    let seal_output_hash = match slot_sealer {
        SlotSealer::Ticket(ticket) => ticket.id.clone(),
        SlotSealer::BandersnatchPubKeys(_key) => {
            // Sign with an empty aux data (message) to get the output hash
            let mut fallback_seal_vrf_input = Vec::with_capacity(X_E.len() + HASH_SIZE);
            fallback_seal_vrf_input.extend_from_slice(X_F);
            fallback_seal_vrf_input.extend_from_slice(entropy_3.as_slice());
            let aux_data = vec![];
            prover
                .sign_vrf(&fallback_seal_vrf_input, &aux_data)
                .output_hash()
        }
    };

    let mut vrf_input = Vec::with_capacity(X_E.len() + HASH_SIZE);
    vrf_input.extend_from_slice(X_E);
    vrf_input.extend_from_slice(seal_output_hash.as_slice());
    let aux_data = vec![]; // no message to sign
    Ok(prover.sign_vrf(&vrf_input, &aux_data))
}
