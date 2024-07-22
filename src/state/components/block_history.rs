use crate::{
    codec::utils::{
        decode_length_discriminated_field, decode_length_discriminated_optional_field,
        encode_length_discriminated_field, encode_length_discriminated_optional_field,
        size_hint_length_discriminated_field, size_hint_length_discriminated_optional_field,
    },
    common::Hash32,
};
use parity_scale_codec::{Decode, Encode, Error, Input, Output};

pub(crate) struct BlockHistoryEntry {
    header_hash: Hash32,
    accumulation_result_root: Vec<Option<Hash32>>, // MMR
    state_root: Hash32,
    work_report_hashes: Vec<Hash32>, // length up to `C = 341`.
}

impl Encode for BlockHistoryEntry {
    fn size_hint(&self) -> usize {
        self.header_hash.size_hint()
            + size_hint_length_discriminated_optional_field(&self.accumulation_result_root)
            + self.state_root.size_hint()
            + size_hint_length_discriminated_field(&self.work_report_hashes)
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        self.header_hash.encode_to(dest);
        encode_length_discriminated_optional_field(&self.accumulation_result_root, dest); // E_M; MMR encoding
        self.state_root.encode_to(dest);
        encode_length_discriminated_field(&self.work_report_hashes, dest);
    }
}

impl Decode for BlockHistoryEntry {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let header_hash = Hash32::decode(input)?;
        let accumulation_result_root = decode_length_discriminated_optional_field(input)?; // E_M; MMR decoding
        let state_root = Hash32::decode(input)?;
        let work_report_hashes = decode_length_discriminated_field(input)?;

        Ok(Self {
            header_hash,
            accumulation_result_root,
            state_root,
            work_report_hashes,
        })
    }
}
