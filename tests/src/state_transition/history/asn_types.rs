use crate::asn_types::{AsnBlockInfo, AsnBlocksHistory, AsnOpaqueHash, Reports};
use rjam_common::Hash32;
use rjam_types::state::{
    history::{BlockHistory, BlockHistoryEntry},
    ReportedWorkPackage,
};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct State {
    /// Blocks history
    pub beta: AsnBlocksHistory,
}

impl From<State> for BlockHistory {
    fn from(value: State) -> Self {
        BlockHistory(
            value
                .beta
                .0
                .into_iter()
                .map(BlockHistoryEntry::from)
                .collect(),
        )
    }
}

impl From<BlockHistory> for State {
    fn from(value: BlockHistory) -> Self {
        Self {
            beta: AsnBlocksHistory(value.0.into_iter().map(AsnBlockInfo::from).collect()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Input {
    /// Current block's header hash
    pub header_hash: AsnOpaqueHash,
    pub parent_state_root: AsnOpaqueHash,
    pub accumulate_root: AsnOpaqueHash,
    pub work_packages: Reports,
}

pub struct JamInput {
    pub header_hash: Hash32,
    pub parent_state_root: Hash32,
    pub accumulate_root: Hash32,
    pub reported_packages: Vec<ReportedWorkPackage>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Output;
