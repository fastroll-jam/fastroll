use crate::{
    codec::utils::{
        decode_length_discriminated_field, encode_length_discriminated_field,
        size_hint_length_discriminated_field,
    },
    common::{Hash32, CORE_COUNT},
};
use parity_scale_codec::{Decode, Encode, Error, Input, Output};
use std::array;

fn create_empty_entries() -> [Vec<Hash32>; CORE_COUNT] {
    array::from_fn(|_| Vec::new())
}

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

impl Decode for AuthorizationPool {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let mut entries: [Vec<Hash32>; CORE_COUNT] = create_empty_entries();

        for entry in &mut entries {
            *entry = decode_length_discriminated_field(input)?;
        }

        Ok(Self { entries })
    }
}
