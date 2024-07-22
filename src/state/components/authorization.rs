use crate::{
    codec::{
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

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to create a sample AuthorizationPool
    fn create_sample_pool() -> AuthorizationPool {
        let mut entries = create_empty_entries();
        entries[0] = vec![Hash32::from([1; 32]), Hash32::from([2; 32])];
        entries[1] = vec![Hash32::from([3; 32])];
        AuthorizationPool { entries }
    }

    // Expected:
    // prefix 0 + length 2 + (1, 1, 1, ...) + (2, 2, 2, ...)
    // prefix 0 + length 1 + (3, 3, 3, ...)
    // padding -> No!

    #[test]
    fn test_encode() {
        let pool = create_sample_pool();
        let encoded = pool.encode(); // length = 2, 1 for each entry
        println!("encoded: {:?}", encoded);
        println!("length of encoded: {:?}", encoded.len());
    }
}
