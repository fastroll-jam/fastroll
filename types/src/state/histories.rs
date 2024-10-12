use rjam_codec::{
    impl_jam_codec_for_newtype, JamCodecError, JamDecode, JamEncode, JamInput, JamOutput,
};
use rjam_common::{Hash32, BLOCK_HISTORY_LENGTH};
use rjam_crypto::utils::Keccak256;
use rjam_merkle::mmr::MerkleMountainRange;

#[derive(Clone)]
pub struct BlockHistories(pub Vec<BlockHistoryEntry>); // Length up to H = 8.
impl_jam_codec_for_newtype!(BlockHistories, Vec<BlockHistoryEntry>);

impl BlockHistories {
    /// Appends a new block history entry to the `BlockHistories` vector.
    ///
    /// This appends a new `BlockHistoryEntry` to the vector. If the total number of entries
    /// exceeds the maximum allowed (`H = 8`), the oldest entry is removed. The history thus retains
    /// only the most recent `H` entries.
    pub fn append(&mut self, entry: BlockHistoryEntry) {
        self.0.push(entry);

        if self.0.len() > BLOCK_HISTORY_LENGTH {
            self.0.remove(0); // Remove the oldest history entry.
        }
    }

    /// Returns the most recent block history.
    ///
    /// Returns `None` if the block histories sequence is empty.
    pub fn get_latest_history(&self) -> Option<BlockHistoryEntry> {
        if self.0.is_empty() {
            return None;
        }

        let last_index = self.0.len() - 1;
        Some(self.0[last_index].clone())
    }
}

#[derive(Debug, Clone)]
pub struct BlockHistoryEntry {
    pub header_hash: Hash32,
    pub accumulation_result_mmr: MerkleMountainRange<Keccak256>,
    pub state_root: Hash32,
    pub work_package_hashes: Vec<Hash32>, // Length up to CORE_COUNT.
}

impl JamEncode for BlockHistoryEntry {
    fn size_hint(&self) -> usize {
        self.header_hash.size_hint()
            + self.accumulation_result_mmr.size_hint()
            + self.state_root.size_hint()
            + self.work_package_hashes.size_hint()
    }

    fn encode_to<W: JamOutput>(&self, dest: &mut W) -> Result<(), JamCodecError> {
        self.header_hash.encode_to(dest)?;
        self.accumulation_result_mmr.encode_to(dest)?;
        self.state_root.encode_to(dest)?;
        self.work_package_hashes.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for BlockHistoryEntry {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        Ok(Self {
            header_hash: Hash32::decode(input)?,
            accumulation_result_mmr: MerkleMountainRange::decode(input)?,
            state_root: Hash32::decode(input)?,
            work_package_hashes: Vec::decode(input)?,
        })
    }
}

impl BlockHistoryEntry {
    pub fn set_state_root(&mut self, root: Hash32) {
        self.state_root = root
    }
}
