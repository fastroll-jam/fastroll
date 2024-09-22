use rjam_codec::{
    impl_jam_codec_for_newtype, JamCodecError, JamDecode, JamEncode, JamInput, JamOutput,
};
use rjam_common::Hash32;

pub struct BlockHistories(pub Vec<BlockHistoryEntry>);
impl_jam_codec_for_newtype!(BlockHistories, Vec<BlockHistoryEntry>);

pub struct BlockHistoryEntry {
    header_hash: Hash32,
    accumulation_result_root: Vec<Option<Hash32>>, // MMR
    state_root: Hash32,
    work_report_hashes: Vec<Hash32>, // length up to `C = 341`.
}

impl JamEncode for BlockHistoryEntry {
    fn size_hint(&self) -> usize {
        self.header_hash.size_hint()
            + self.accumulation_result_root.size_hint()
            + self.state_root.size_hint()
            + self.work_report_hashes.size_hint()
    }

    fn encode_to<W: JamOutput>(&self, dest: &mut W) -> Result<(), JamCodecError> {
        self.header_hash.encode_to(dest)?;
        self.accumulation_result_root.encode_to(dest)?; // E_M; MMR encoding
        self.state_root.encode_to(dest)?;
        self.work_report_hashes.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for BlockHistoryEntry {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        Ok(Self {
            header_hash: Hash32::decode(input)?,
            accumulation_result_root: Vec::decode(input)?, // E_M; MMR decoding
            state_root: Hash32::decode(input)?,
            work_report_hashes: Vec::decode(input)?,
        })
    }
}
