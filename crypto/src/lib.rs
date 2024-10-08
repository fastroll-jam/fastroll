pub mod utils;
pub mod vrf;

use crate::vrf::{ring_context, RingCommitment, Verifier};
use ark_ec_vrfs::{
    codec::point_decode,
    prelude::ark_serialize::{CanonicalSerialize, SerializationError},
    suites::bandersnatch::edwards::BandersnatchSha512Ell2,
    Public,
};

use rjam_common::{BandersnatchRingRoot, ValidatorSet};

/// Generates Bandersnatch Ring Root from the known validator set (ring)
pub fn generate_ring_root(
    validator_set: &ValidatorSet,
) -> Result<BandersnatchRingRoot, SerializationError> {
    let commitment = generate_ring_root_internal(validator_set)?;
    let mut bytes: Vec<u8> = vec![];
    commitment.serialize_compressed(&mut bytes)?;
    Ok(bytes
        .try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("Expected a Vec of length 144 but it was {}", v.len())))
}

fn generate_ring_root_internal(
    validator_set: &ValidatorSet,
) -> Result<RingCommitment, SerializationError> {
    let ring = validator_set_to_bandersnatch_ring(validator_set)?;
    let verifier = Verifier::new(ring);
    Ok(verifier.commitment)
}

/// Converts JAM ValidatorSet type into Vec<Public> type.
pub fn validator_set_to_bandersnatch_ring(
    validator_set: &ValidatorSet,
) -> Result<Vec<Public<BandersnatchSha512Ell2>>, SerializationError> {
    let mut public_keys = vec![];
    validator_set.iter().for_each(|validator_key| {
        match point_decode::<BandersnatchSha512Ell2>(&validator_key.bandersnatch_key) {
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
