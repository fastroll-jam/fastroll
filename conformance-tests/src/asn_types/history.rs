use crate::asn_types::common::*;
use fr_common::{workloads::ReportedWorkPackage, Hash32};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct State {
    /// Blocks history
    pub beta: AsnBlocksHistory,
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
