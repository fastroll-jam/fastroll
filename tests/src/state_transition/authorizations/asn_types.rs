use crate::asn_types::{AsnAuthPools, AsnAuthQueues, AsnCoreIndex, AsnOpaqueHash, AsnTimeSlot};
use rjam_common::ByteArray;
use rjam_types::{
    common::workloads::WorkReport,
    extrinsics::guarantees::{GuaranteesExtrinsic, GuaranteesExtrinsicEntry},
    state::Timeslot,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct State {
    pub auth_pools: AsnAuthPools,
    pub auth_queues: AsnAuthQueues,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AsnCoreAuthorizer {
    pub core: AsnCoreIndex,
    pub auth_hash: AsnOpaqueHash,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Input {
    pub slot: AsnTimeSlot,
    pub auths: Vec<AsnCoreAuthorizer>,
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

pub struct JamInput {
    pub slot: Timeslot,
    pub extrinsic: GuaranteesExtrinsic,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Output;
