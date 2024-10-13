use crate::test_utils::{deserialize_hex, serialize_hex};
use rjam_crypto::utils::Hasher;
use rjam_merkle::mmr::MerkleMountainRange;
use rjam_types::state::history::{BlockHistory, BlockHistoryEntry};
use serde::{Deserialize, Serialize};
use std::{fmt, fmt::Debug};

// Define basic types

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq)]
pub struct Hash(
    #[serde(serialize_with = "serialize_hex", deserialize_with = "deserialize_hex")] pub [u8; 32],
);

impl Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

pub type MmrPeak = Option<Hash>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Mmr {
    peaks: Vec<MmrPeak>,
}

impl<H: Hasher> From<Mmr> for MerkleMountainRange<H> {
    fn from(value: Mmr) -> Self {
        let peaks = value
            .peaks
            .into_iter()
            .map(|peak| peak.map(|hash| hash.0))
            .collect();

        MerkleMountainRange::new_from_peaks(peaks)
    }
}

impl<H: Hasher> From<MerkleMountainRange<H>> for Mmr {
    fn from(value: MerkleMountainRange<H>) -> Self {
        let peaks = value.peaks.into_iter().map(|peak| peak.map(Hash)).collect();

        Mmr { peaks }
    }
}

pub type Reports = Vec<Hash>;

// Recorded disputes sequences and offenders
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct BlockInfo {
    header_hash: Hash,
    mmr: Mmr,
    state_root: Hash,
    reported: Reports,
}

impl From<BlockInfo> for BlockHistoryEntry {
    fn from(value: BlockInfo) -> Self {
        Self {
            header_hash: value.header_hash.0,
            accumulation_result_mmr: value.mmr.into(),
            state_root: value.state_root.0,
            work_package_hashes: value.reported.into_iter().map(|hash| hash.0).collect(),
        }
    }
}

impl From<BlockHistoryEntry> for BlockInfo {
    fn from(value: BlockHistoryEntry) -> Self {
        Self {
            header_hash: Hash(value.header_hash),
            mmr: value.accumulation_result_mmr.into(),
            state_root: Hash(value.state_root),
            reported: value.work_package_hashes.into_iter().map(Hash).collect(),
        }
    }
}

/// State relevant to History STF
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct State {
    /// Blocks history
    pub beta: Vec<BlockInfo>,
}

impl From<State> for BlockHistory {
    fn from(value: State) -> Self {
        BlockHistory(
            value
                .beta
                .into_iter()
                .map(BlockHistoryEntry::from)
                .collect(),
        )
    }
}

impl From<BlockHistory> for State {
    fn from(value: BlockHistory) -> Self {
        Self {
            beta: value.0.into_iter().map(BlockInfo::from).collect(),
        }
    }
}

/// Input for History STF.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Input {
    /// Current block's header hash
    pub header_hash: Hash,
    pub parent_state_root: Hash,
    pub accumulate_root: Hash,
    pub work_packages: Reports,
}

/// Output from History STF
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Output;

/// History STF execution dump
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TestCase {
    /// Input.
    pub input: Input,
    /// Pre-execution state.
    pub pre_state: State,
    /// Output.
    pub output: Output,
    /// Post-execution state.
    pub post_state: State,
}
