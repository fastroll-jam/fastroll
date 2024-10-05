pub mod utils;
pub mod vrf;

use crate::vrf::{RingCommitment, Verifier};
use ark_ec_vrfs::{
    codec::point_decode,
    prelude::ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError},
    suites::bandersnatch::edwards::BandersnatchSha512Ell2,
    Public, Suite,
};
use rjam_common::{BandersnatchRingRoot, ValidatorSet};
use std::fmt::Debug;

/// Converts JAM ValidatorSet type into Vec<Public> type.
pub fn validator_set_to_ring<S: Suite + Debug>(
    validator_set: &ValidatorSet,
) -> Result<Vec<Public<S>>, SerializationError> {
    let mut public_keys = vec![];
    validator_set.iter().for_each(|validator_key| {
        let point = point_decode::<S>(&validator_key.bandersnatch_key).unwrap();
        public_keys.push(Public(point));
    });
    Ok(public_keys)
}

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
    let ring = validator_set_to_ring::<BandersnatchSha512Ell2>(validator_set)?;
    let verifier = Verifier::new(ring);
    Ok(verifier.commitment)
}
