use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::{AccountAddress, Octets};

#[derive(Clone, Ord, PartialOrd, PartialEq, Eq)]
pub struct PreimageLookupExtrinsicEntry {
    service_index: AccountAddress, // N_S
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
            service_index: AccountAddress::decode(input)?,
            preimage_data: Octets::decode(input)?,
        })
    }
}
