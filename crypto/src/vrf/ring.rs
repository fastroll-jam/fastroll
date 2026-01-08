use crate::{error::CryptoError, types::*};
use ark_vrf::{reexports::ark_serialize::CanonicalDeserialize, suites::bandersnatch};
use bandersnatch::{Public, RingProofParams};
use fr_common::ByteEncodable;
use tracing::instrument;

/// Converts `ValidatorKeySet` type into `Vec<Public>` type.
#[instrument(level = "debug", skip_all, name = "construct_ring")]
pub(crate) fn validator_set_to_bandersnatch_ring(
    validator_set: &ValidatorKeySet,
) -> Result<Vec<Public>, CryptoError> {
    let mut public_keys = vec![];
    validator_set.iter().for_each(|validator_key| {
        // Use the padding point if the decoding fails.
        let pk = Public::deserialize_compressed_unchecked(validator_key.bandersnatch.as_slice())
            .unwrap_or(Public::from(RingProofParams::padding_point()));
        public_keys.push(pk);
    });
    Ok(public_keys)
}
