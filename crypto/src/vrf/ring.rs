use crate::{error::CryptoError, types::*};
use ark_vrf::{codec::point_decode, suites::bandersnatch};
use bandersnatch::{BandersnatchSha512Ell2, Public, RingProofParams};
use fr_common::ByteEncodable;
use tracing::instrument;

/// Converts `ValidatorKeySet` type into `Vec<Public>` type.
#[instrument(level = "debug", skip_all, name = "construct_ring")]
pub(crate) fn validator_set_to_bandersnatch_ring(
    validator_set: &ValidatorKeySet,
) -> Result<Vec<Public>, CryptoError> {
    let mut public_keys = vec![];
    validator_set.iter().for_each(|validator_key| {
        match point_decode::<BandersnatchSha512Ell2>(validator_key.bandersnatch.as_slice()) {
            Ok(decoded_point) => {
                public_keys.push(Public::from(decoded_point));
            }
            Err(_) => {
                public_keys.push(Public::from(RingProofParams::padding_point()));
            } // Use the padding point if the decoding fails.
        };
    });
    Ok(public_keys)
}
