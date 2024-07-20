use crate::{
    codec::{encode_length_discriminated_field, size_hint_length_discriminated_field},
    common::{Hash32, CORE_COUNT},
};
use parity_scale_codec::{Encode, Output};

pub(crate) struct AuthorizationPool {
    entries: [Vec<Hash32>; CORE_COUNT], // Vec<Hash32> length up to `O = 8`
}

impl Encode for AuthorizationPool {
    fn size_hint(&self) -> usize {
        self.entries
            .iter()
            .map(|entry| size_hint_length_discriminated_field(entry))
            .sum()
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        for entry in &self.entries {
            encode_length_discriminated_field(entry, dest);
        }
    }
}
