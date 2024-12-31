use crate::{
    impl_simple_state_component,
    state_utils::{SimpleStateComponent, StateComponent, StateEntryType, StateKeyConstant},
};
use rjam_codec::{
    impl_jam_codec_for_newtype, JamCodecError, JamDecode, JamEncode, JamInput, JamOutput,
};
use rjam_common::{Hash32, BLOCK_HISTORY_LENGTH};
use rjam_crypto::Keccak256;
use rjam_merkle::mmr::MerkleMountainRange;
use std::fmt::{Display, Formatter};

#[derive(Clone)]
pub struct BlockHistory(pub Vec<BlockHistoryEntry>); // Length up to H = 8.
impl_jam_codec_for_newtype!(BlockHistory, Vec<BlockHistoryEntry>);
impl_simple_state_component!(BlockHistory, BlockHistory);

impl BlockHistory {
    /// Appends a new block history entry to the `BlockHistory` vector.
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
    /// Returns `None` if the block history sequence is empty.
    pub fn get_latest_history(&self) -> Option<&BlockHistoryEntry> {
        if self.0.is_empty() {
            return None;
        }

        let last_index = self.0.len() - 1;
        Some(&self.0[last_index])
    }

    pub fn get_by_header_hash(&self, header_hash: &Hash32) -> Option<&BlockHistoryEntry> {
        self.0
            .iter()
            .find(|entry| entry.header_hash == *header_hash)
    }

    pub fn check_work_package_hash_exists(&self, work_package_hash: &Hash32) -> bool {
        self.0.iter().any(|entry| {
            entry
                .reported_packages
                .iter()
                .map(|package| package.work_package_hash)
                .collect::<Vec<_>>()
                .contains(work_package_hash)
        })
    }

    pub fn get_reported_packages_flattened(&self) -> Vec<ReportedWorkPackage> {
        self.0
            .iter()
            .flat_map(|entry| entry.reported_packages.clone())
            .collect()
    }
}

#[derive(Debug, Clone, JamEncode, JamDecode)]
pub struct ReportedWorkPackage {
    pub work_package_hash: Hash32,
    pub segment_root: Hash32, // exports root
}

impl Display for ReportedWorkPackage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "package_hash: {}", self.work_package_hash)?;
        write!(f, "segment_root: {}", self.segment_root)
    }
}

#[derive(Debug, Clone)]
pub struct BlockHistoryEntry {
    pub header_hash: Hash32,
    pub accumulation_result_mmr: MerkleMountainRange<Keccak256>,
    pub state_root: Hash32,
    pub reported_packages: Vec<ReportedWorkPackage>, // Length up to CORE_COUNT.
}

impl JamEncode for BlockHistoryEntry {
    fn size_hint(&self) -> usize {
        self.header_hash.size_hint()
            + self.accumulation_result_mmr.size_hint()
            + self.state_root.size_hint()
            + self.reported_packages.size_hint()
    }

    fn encode_to<W: JamOutput>(&self, dest: &mut W) -> Result<(), JamCodecError> {
        self.header_hash.encode_to(dest)?;
        self.accumulation_result_mmr.encode_to(dest)?;
        self.state_root.encode_to(dest)?;
        self.reported_packages.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for BlockHistoryEntry {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        Ok(Self {
            header_hash: Hash32::decode(input)?,
            accumulation_result_mmr: MerkleMountainRange::decode(input)?,
            state_root: Hash32::decode(input)?,
            reported_packages: Vec::decode(input)?,
        })
    }
}

impl BlockHistoryEntry {
    pub fn set_state_root(&mut self, root: Hash32) {
        self.state_root = root
    }
}
