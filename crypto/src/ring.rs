use crate::{CryptoError, RingCommitment, Verifier};
use ark_ec_vrfs::{
    codec::point_decode, reexports::ark_serialize::CanonicalSerialize, ring::RingContext,
    suites::bandersnatch,
};
use bandersnatch::{BandersnatchSha512Ell2, Public};
use rjam_common::{BandersnatchRingRoot, ValidatorKeySet};

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
        .map(BandersnatchRingRoot::new)
        .map_err(|_| CryptoError::RingRootError)
}

fn generate_ring_root_internal(
    validator_set: &ValidatorKeySet,
) -> Result<RingCommitment, CryptoError> {
    let ring = validator_set_to_bandersnatch_ring(validator_set)?;
    let verifier = Verifier::new(ring);
    Ok(verifier.commitment)
}

/// Converts `ValidatorKeySet` type into `Vec<Public>` type.
pub fn validator_set_to_bandersnatch_ring(
    validator_set: &ValidatorKeySet,
) -> Result<Vec<Public>, CryptoError> {
    let mut public_keys = vec![];
    validator_set.iter().for_each(|validator_key| {
        match point_decode::<BandersnatchSha512Ell2>(&*validator_key.bandersnatch_key) {
            Ok(decoded_point) => {
                public_keys.push(Public::from(decoded_point));
            }
            Err(_) => {
                public_keys.push(Public::from(
                    RingContext::<BandersnatchSha512Ell2>::padding_point(),
                ));
            } // Use the padding point if the decoding fails.
        };
    });
    Ok(public_keys)
}
