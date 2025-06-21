use crate::{
    impl_simple_state_component,
    state_utils::{SimpleStateComponent, StateComponent, StateEntryType, StateKeyConstant},
};
use fr_codec::prelude::*;
use fr_common::{workloads::work_report::ReportedWorkPackage, Hash32, BLOCK_HISTORY_LENGTH};
use fr_crypto::Keccak256;
use fr_limited_vec::LimitedVec;
use fr_merkle::mmr::MerkleMountainRange;

pub type BlockHistoryEntries = LimitedVec<BlockHistoryEntry, BLOCK_HISTORY_LENGTH>;

/// The recent block histories.
///
/// Represents `β` of the GP.
#[derive(Clone, Debug, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct BlockHistory(pub BlockHistoryEntries);
impl_simple_state_component!(BlockHistory, BlockHistory);

impl BlockHistory {
    /// Appends a new block history entry.
    ///
    /// The history retains the most recent `H` entries.
    pub fn append(&mut self, entry: BlockHistoryEntry) {
        self.0.shift_push(entry);
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
                .map(|package| package.work_package_hash.clone())
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockHistoryEntry {
    /// `h`: Header hash of the block.
    pub header_hash: Hash32,
    /// `b`: Accumulation result MMR root.
    pub accumulation_result_mmr: MerkleMountainRange<Keccak256>,
    /// `s`: Posterior state root of the block.
    pub state_root: Hash32,
    /// **`p`**: The set of all work reports introduced by the guarantees extrinsic of the block,
    /// providing a mapping of work package hashes and their corresponding segment roots.
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
