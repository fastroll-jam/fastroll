use crate::types::common::*;
use fr_common::{workloads::ReportedWorkPackage, AccumulateRoot, BlockHeaderHash, StateRoot};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct State {
    /// Blocks history
    pub beta: AsnRecentBlocks,
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
    pub header_hash: BlockHeaderHash,
    pub parent_state_root: StateRoot,
    pub accumulate_root: AccumulateRoot,
    pub reported_packages: Vec<ReportedWorkPackage>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Output;
