use jam_codec::{
    impl_jam_codec_for_newtype, JamCodecError, JamDecode, JamEncode, JamInput, JamOutput,
};
use jam_common::VALIDATOR_COUNT;

#[derive(Clone, Copy)]
pub struct ValidatorStatEntry {
    block_production_count: u32, // b; the number of blocks produced by the validator.
    ticket_count: u32,           // t; the number of tickets introduced by the validator.
    preimage_count: u32,         // p; the number of preimages introduced by the validator.
    preimage_data_octet_count: u32, // d; the total number of octets across all preimages introduced by the validator.
    guarantee_count: u32,           // g; the number of reports guaranteed by the validator.
    assurance_count: u32, // a; the number of availability assurances made by the validator.
}

pub struct ValidatorStats(pub [[ValidatorStatEntry; VALIDATOR_COUNT]; 2]);
impl_jam_codec_for_newtype!(ValidatorStats, [[ValidatorStatEntry; VALIDATOR_COUNT]; 2]);

impl JamEncode for ValidatorStatEntry {
    fn size_hint(&self) -> usize {
        self.block_production_count.size_hint()
            + self.ticket_count.size_hint()
            + self.preimage_count.size_hint()
            + self.preimage_data_octet_count.size_hint()
            + self.guarantee_count.size_hint()
            + self.assurance_count.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.block_production_count.encode_to(dest)?;
        self.ticket_count.encode_to(dest)?;
        self.preimage_count.encode_to(dest)?;
        self.preimage_data_octet_count.encode_to(dest)?;
        self.guarantee_count.encode_to(dest)?;
        self.assurance_count.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for ValidatorStatEntry {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            block_production_count: u32::decode(input)?,
            ticket_count: u32::decode(input)?,
            preimage_count: u32::decode(input)?,
            preimage_data_octet_count: u32::decode(input)?,
            guarantee_count: u32::decode(input)?,
            assurance_count: u32::decode(input)?,
        })
    }
}
