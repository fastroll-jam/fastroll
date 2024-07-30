pub(crate) mod utils;
pub(crate) mod vrf;

use crate::{
    common::BandersnatchRingRoot,
    crypto::vrf::{RingCommitment, Verifier},
    state::components::validators::ValidatorSet,
};
use ark_ec_vrfs::{
    codec::point_decode,
    prelude::ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError},
    suites::bandersnatch::{edwards as bandersnatch, edwards::BandersnatchSha512Ell2},
    Public, Suite,
};

pub(crate) fn validator_set_to_ring<S: Suite>(
    validator_set: &ValidatorSet,
) -> Result<Vec<Public<S>>, SerializationError> {
    let mut public_keys = vec![];
    let _ = validator_set.iter().map(|validator_key| {
        let point = point_decode::<S>(&validator_key.bandersnatch_key).unwrap();
        public_keys.push(Public(point));
    });
    Ok(public_keys)
}

// Generates Bandersnatch Ring Root from the known validator set (ring)
pub(crate) fn generate_ring_root_internal(
    validator_set: &ValidatorSet,
) -> Result<RingCommitment, SerializationError> {
    let ring = validator_set_to_ring::<BandersnatchSha512Ell2>(validator_set)?;
    let verifier = Verifier::new(ring);
    Ok(verifier.commitment)
}

pub(crate) fn generate_ring_root_hexstring(
    validator_set: &ValidatorSet,
) -> Result<String, SerializationError> {
    let commitment = generate_ring_root_internal(validator_set)?;
    let mut bytes: Vec<u8> = vec![];
    let _ = commitment.serialize_compressed(&mut bytes);
    Ok(hex::encode(bytes.as_slice()))
}

pub(crate) fn generate_ring_root(
    validator_set: &ValidatorSet,
) -> Result<BandersnatchRingRoot, SerializationError> {
    let commitment = generate_ring_root_internal(validator_set)?;
    let mut bytes: Vec<u8> = vec![];
    commitment.serialize_compressed(&mut bytes)?;
    Ok(bytes
        .try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("Expected a Vec of length 144 but it was {}", v.len())))
}
