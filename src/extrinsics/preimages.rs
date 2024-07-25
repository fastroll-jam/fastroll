use crate::{
    codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput},
    common::Octets,
};

pub(crate) struct PreimageLookupExtrinsicEntry {
    service_index: u32, // N_S
    preimage_data: Octets,
}

impl JamEncode for PreimageLookupExtrinsicEntry {
    fn size_hint(&self) -> usize {
        self.service_index.size_hint() + self.preimage_data.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.service_index.encode_to(dest)?;
        self.preimage_data.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for PreimageLookupExtrinsicEntry {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        Ok(Self {
            service_index: u32::decode(input)?,
            preimage_data: Octets::decode(input)?,
        })
    }
}
