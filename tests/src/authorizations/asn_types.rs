use crate::asn_types::{AsnAuthPools, AsnAuthQueues, CoreIndex, OpaqueHash, TimeSlot};
use rjam_common::ByteArray;
use rjam_types::{
    common::workloads::WorkReport,
    extrinsics::guarantees::{GuaranteesExtrinsic, GuaranteesExtrinsicEntry},
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct State {
    pub auth_pools: AsnAuthPools,
    pub auth_queues: AsnAuthQueues,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CoreAuthorizer {
    pub core: CoreIndex,
    pub auth_hash: OpaqueHash,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Input {
    pub slot: TimeSlot,
    pub auths: Vec<CoreAuthorizer>,
}

/// Converts `Input` into `GuaranteesExtrinsic` type.
impl From<Input> for GuaranteesExtrinsic {
    fn from(value: Input) -> Self {
        let mut guarantees = Vec::with_capacity(value.auths.len());

        for auth in value.auths {
            let mut report = WorkReport::default();
            report.core_index = auth.core;
            report.authorizer_hash = ByteArray::new(auth.auth_hash.0);
            guarantees.push(GuaranteesExtrinsicEntry::new(report, value.slot));
        }
        Self { items: guarantees }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Output;

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
