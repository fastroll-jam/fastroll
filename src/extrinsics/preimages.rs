use crate::{
    codec::{
        decode_length_discriminated_field, encode_length_discriminated_field,
        size_hint_length_discriminated_field,
    },
    common::Octets,
};
use parity_scale_codec::{Decode, Encode, Error, Input, Output};

pub(crate) struct PreimageLookupExtrinsicEntry {
    service_index: u32, // N_S
    preimage_data: Octets,
}

impl Encode for PreimageLookupExtrinsicEntry {
    fn size_hint(&self) -> usize {
        self.service_index.size_hint() + size_hint_length_discriminated_field(&self.preimage_data)
    }

    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        self.service_index.encode_to(dest);
        encode_length_discriminated_field(&self.preimage_data, dest);
    }
}

impl Decode for PreimageLookupExtrinsicEntry {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let service_index = u32::decode(input)?;
        let preimage_data: Octets = decode_length_discriminated_field(input)?;

        Ok(Self {
            service_index,
            preimage_data,
        })
    }
}
