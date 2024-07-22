use crate::{
    codec::utils::{
        decode_length_discriminated_sorted_field, encode_length_discriminated_sorted_field,
        size_hint_length_discriminated_sorted_field,
    },
    common::{Ed25519PubKey, Hash32},
};
use parity_scale_codec::{Decode, Encode, Error, Input, Output};

pub(crate) struct VerdictsState {
    good_set: Vec<Hash32>,          // psi_g; recording hash of correct work-reports
    bad_set: Vec<Hash32>,           // psi_b; recording hash of incorrect work-reports
    wonky_set: Vec<Hash32>,         // psi_w; recording hash of work-reports that cannot be judged
    punish_set: Vec<Ed25519PubKey>, // psi_p; recording Ed25519 public keys of validators which have misjudged.
}

impl Encode for VerdictsState {
    fn size_hint(&self) -> usize {
        size_hint_length_discriminated_sorted_field(&self.good_set)
            + size_hint_length_discriminated_sorted_field(&self.bad_set)
            + size_hint_length_discriminated_sorted_field(&self.wonky_set)
            + size_hint_length_discriminated_sorted_field(&self.punish_set)
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        encode_length_discriminated_sorted_field(&self.good_set, dest);
        encode_length_discriminated_sorted_field(&self.bad_set, dest);
        encode_length_discriminated_sorted_field(&self.wonky_set, dest);
        encode_length_discriminated_sorted_field(&self.punish_set, dest);
    }
}

impl Decode for VerdictsState {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let good_set = decode_length_discriminated_sorted_field(input)?;
        let bad_set = decode_length_discriminated_sorted_field(input)?;
        let wonky_set = decode_length_discriminated_sorted_field(input)?;
        let punish_set = decode_length_discriminated_sorted_field(input)?;

        Ok(Self {
            good_set,
            bad_set,
            wonky_set,
            punish_set,
        })
    }
}
