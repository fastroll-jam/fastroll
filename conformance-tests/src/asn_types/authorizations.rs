use crate::asn_types::common::*;
use fr_common::Hash32;

use fr_block::types::extrinsics::guarantees::{GuaranteesXt, GuaranteesXtEntry};
use fr_common::workloads::work_report::WorkReport;
use fr_state::types::Timeslot;
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

/// Converts `Input` into `GuaranteesXt` type.
impl From<Input> for GuaranteesXt {
    fn from(value: Input) -> Self {
        let mut guarantees = Vec::with_capacity(value.auths.len());

        for auth in value.auths {
            let report = WorkReport {
                core_index: auth.core,
                authorizer_hash: Hash32::from(auth.auth_hash),
                ..Default::default()
            };

            guarantees.push(GuaranteesXtEntry::new(report, value.slot));
        }
        Self { items: guarantees }
    }
}

pub struct JamInput {
    pub slot: Timeslot,
    pub extrinsic: GuaranteesXt,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Output;
