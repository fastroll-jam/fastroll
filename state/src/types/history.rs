use crate::{
    impl_simple_state_component,
    state_utils::{SimpleStateComponent, StateComponent, StateEntryType, StateKeyConstant},
};
use fr_codec::prelude::*;
use fr_common::{
    workloads::work_report::ReportedWorkPackage, AccumulateRoot, BeefyRoot, BlockHeaderHash,
    StateRoot, WorkPackageHash, BLOCK_HISTORY_LENGTH,
};
use fr_crypto::Keccak256;
use fr_limited_vec::LimitedVec;
use fr_merkle::{mmr::MerkleMountainRange, well_balanced_tree::WellBalancedMerkleTree};
use fr_pvm_types::invoke_results::{AccumulationOutputPair, AccumulationOutputPairs};

pub type BlockHistoryEntries = LimitedVec<BlockHistoryEntry, BLOCK_HISTORY_LENGTH>;

/// The recent block histories.
///
/// Represents `β` of the GP.
#[derive(Clone, Debug, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct BlockHistory {
    /// `β_H`: The block history of recent blocks.
    pub history: BlockHistoryEntries,
    /// `β_B`: The accumulation output log; BEEFY MMB.
    pub beefy_belt: MerkleMountainRange<Keccak256>,
}
impl_simple_state_component!(BlockHistory, BlockHistory);

impl BlockHistory {
    /// Appends a new block history entry.
    ///
    /// The history retains the most recent `H` entries.
    pub fn append(&mut self, entry: BlockHistoryEntry) {
        self.history.shift_push(entry);
    }

    /// Returns the most recent block history.
    ///
    /// Returns `None` if the block history sequence is empty.
    pub fn get_latest_history(&self) -> Option<&BlockHistoryEntry> {
        if self.history.is_empty() {
            return None;
        }

        let last_index = self.history.len() - 1;
        Some(&self.history[last_index])
    }

    pub fn get_by_header_hash(&self, header_hash: &BlockHeaderHash) -> Option<&BlockHistoryEntry> {
        self.history
            .iter()
            .find(|entry| entry.header_hash == *header_hash)
    }

    pub fn check_work_package_hash_exists(&self, work_package_hash: &WorkPackageHash) -> bool {
        self.history.iter().any(|entry| {
            entry
                .reported_packages
                .iter()
                .map(|package| &package.work_package_hash)
                .collect::<Vec<_>>()
                .contains(&work_package_hash)
        })
    }

    pub fn get_reported_packages_flattened(&self) -> Vec<ReportedWorkPackage> {
        self.history
            .iter()
            .flat_map(|entry| entry.reported_packages.clone())
            .collect()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockHistoryEntry {
    /// `h`: Header hash of the block.
    pub header_hash: BlockHeaderHash,
    /// `b`: Accumulation result MMR root.
    pub accumulation_result_mmr_root: BeefyRoot,
    /// `s`: Posterior state root of the block.
    pub state_root: StateRoot,
    /// **`p`**: The set of all work reports introduced by the guarantees extrinsic of the block,
    /// providing a mapping of work package hashes and their corresponding segment roots.
    pub reported_packages: Vec<ReportedWorkPackage>, // Length up to CORE_COUNT.
}

impl JamEncode for BlockHistoryEntry {
    fn size_hint(&self) -> usize {
        self.header_hash.size_hint()
            + self.accumulation_result_mmr_root.size_hint()
            + self.state_root.size_hint()
            + self.reported_packages.size_hint()
    }

    fn encode_to<W: JamOutput>(&self, dest: &mut W) -> Result<(), JamCodecError> {
        self.header_hash.encode_to(dest)?;
        self.accumulation_result_mmr_root.encode_to(dest)?;
        self.state_root.encode_to(dest)?;
        self.reported_packages.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for BlockHistoryEntry {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        Ok(Self {
            header_hash: BlockHeaderHash::decode(input)?,
            accumulation_result_mmr_root: BeefyRoot::decode(input)?,
            state_root: StateRoot::decode(input)?,
            reported_packages: Vec::decode(input)?,
        })
    }
}

impl BlockHistoryEntry {
    pub fn set_state_root(&mut self, root: StateRoot) {
        self.state_root = root
    }
}

/// The accumulation output pairs of the most recent block.
///
/// Represents `θ` of the GP.
#[derive(Clone, Debug, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct LastAccumulateOutputs(pub Vec<AccumulationOutputPair>);
impl_simple_state_component!(LastAccumulateOutputs, LastAccumulateOutputs);

impl LastAccumulateOutputs {
    pub fn from_output_pairs(output_pairs: AccumulationOutputPairs) -> Self {
        Self(output_pairs.0.into_iter().collect())
    }

    /// Generates a commitment to `LastAccumulateOutputs` using a simple binary merkle tree.
    /// Used for producing the BEEFY commitment after accumulation.
    pub fn accumulate_root(self) -> AccumulateRoot {
        // Note: `AccumulationOutputPairs` is already ordered by service id.
        let ordered_encoded_results = self
            .0
            .into_iter()
            .map(|pair| {
                let mut buf = Vec::with_capacity(36);
                pair.service
                    .encode_to_fixed(&mut buf, 4)
                    .expect("Should not fail");
                pair.output_hash
                    .encode_to(&mut buf)
                    .expect("Should not fail");
                buf
            })
            .collect::<Vec<_>>();
        WellBalancedMerkleTree::<Keccak256>::compute_root(&ordered_encoded_results).unwrap()
    }
}
