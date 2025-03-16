use crate::asn_types::{
    common::{
        AccumulateRoot, AsnAccumulateHistory, AsnAccumulateQueue, AsnEntropy,
        AsnPrivilegedServices, AsnServiceId, AsnServiceInfo, AsnTimeSlot, AsnWorkReport,
    },
    preimages::AsnPreimagesMapEntry,
};
use rjam_common::{workloads::work_report::WorkReport, Hash32};
use rjam_state::types::Timeslot;
use serde::{Deserialize, Serialize};

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum AccumulateErrorCode {
    reserved,
}

/// Subset of the `δ` relevant to the accumulate STF.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnAccount {
    pub service: AsnServiceInfo,
    pub preimages: Vec<AsnPreimagesMapEntry>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnAccountsMapEntry {
    pub id: AsnServiceId,
    pub data: AsnAccount,
}

pub type AsnServices = Vec<AsnAccountsMapEntry>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct State {
    pub slot: AsnTimeSlot,
    pub entropy: AsnEntropy,
    pub ready_queue: AsnAccumulateQueue,
    pub accumulated: AsnAccumulateHistory,
    pub privileges: AsnPrivilegedServices,
    pub accounts: AsnServices,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Input {
    pub slot: AsnTimeSlot,
    pub reports: Vec<AsnWorkReport>,
}

pub struct JamInput {
    pub slot: Timeslot,
    pub reports: Vec<WorkReport>,
}

#[derive(Clone)]
pub struct JamTransitionOutput {
    pub accumulate_root: Hash32,
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Output {
    ok(AccumulateRoot),
    err,
}
