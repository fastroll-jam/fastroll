use crate::{ring_context, CryptoError, RingCommitment, Verifier};
use ark_ec_vrfs::{
    codec::point_decode, prelude::ark_serialize::CanonicalSerialize,
    suites::bandersnatch::edwards::BandersnatchSha512Ell2, Public,
};
use rjam_common::{BandersnatchRingRoot, ByteArray, ValidatorKeySet};

/// Generates Bandersnatch Ring Root from the known validator set (ring)
pub fn generate_ring_root(
    validator_set: &ValidatorKeySet,
) -> Result<BandersnatchRingRoot, CryptoError> {
    let commitment = generate_ring_root_internal(validator_set)?;
    let mut bytes: Vec<u8> = vec![];
    commitment
        .serialize_compressed(&mut bytes)
        .map_err(CryptoError::SerializationError)?;
    bytes
        .try_into()
        .map(ByteArray::new)
        .map_err(|_| CryptoError::RingRootError)
}

fn generate_ring_root_internal(
    validator_set: &ValidatorKeySet,
) -> Result<RingCommitment, CryptoError> {
    let ring = validator_set_to_bandersnatch_ring(validator_set)?;
    let verifier = Verifier::new(ring);
    Ok(verifier.commitment)
}

/// Converts JAM ValidatorKeySet type into Vec<Public> type.
pub fn validator_set_to_bandersnatch_ring(
    validator_set: &ValidatorKeySet,
) -> Result<Vec<Public<BandersnatchSha512Ell2>>, CryptoError> {
    let mut public_keys = vec![];
    validator_set.iter().for_each(|validator_key| {
        match point_decode::<BandersnatchSha512Ell2>(&*validator_key.bandersnatch_key) {
            Ok(decoded_point) => {
                public_keys.push(Public(decoded_point));
            }
            Err(_) => {
                public_keys.push(Public(ring_context().padding_point()));
            } // Use the padding point if the decoding fails.
        };
    });
    Ok(public_keys)
}
