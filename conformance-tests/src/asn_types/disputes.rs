use crate::asn_types::common::*;
use fr_block::types::extrinsics::disputes::DisputesXt;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum DisputesErrorCode {
    already_judged,
    bad_vote_split,
    verdicts_not_sorted_unique,
    judgements_not_sorted_unique,
    culprits_not_sorted_unique,
    faults_not_sorted_unique,
    not_enough_culprits,
    not_enough_faults,
    culprits_verdict_not_bad,
    fault_verdict_wrong,
    offender_already_reported, // not covered
    bad_judgement_age,
    bad_signature,
    bad_guarantor_key,
    bad_auditor_key,
    reserved,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct State {
    /// Disputes verdicts and offenders
    pub psi: AsnDisputesRecords,
    /// Availability cores assignments.
    pub rho: AsnAvailAssignments,
    /// Timeslot.
    pub tau: AsnTimeSlot,
    /// Validators active in the current epoch.
    pub kappa: AsnValidatorsData,
    /// Validators active in the previous epoch.
    pub lambda: AsnValidatorsData,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Input {
    pub disputes: AsnDisputesXt,
}

pub struct JamInput {
    pub extrinsic: DisputesXt,
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Output {
    ok(AsnDisputesOutputMarks),
    err(DisputesErrorCode),
}
