use crate::asn_types::{
    AsnDisputesExtrinsic, AvailabilityAssignments, DisputesOutputMarks, DisputesRecords, TimeSlot,
    ValidatorsData,
};
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
    reserved, // Note: not in ASN
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct State {
    pub psi: DisputesRecords,         // Disputes verdicts and offenders
    pub rho: AvailabilityAssignments, // Availability cores assignments
    pub tau: TimeSlot,                // Timeslot
    pub kappa: ValidatorsData,        // Validators active in the current epoch
    pub lambda: ValidatorsData,       // Validators active in the previous epoch
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Input {
    pub disputes: AsnDisputesExtrinsic,
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Output {
    ok(DisputesOutputMarks),
    err(DisputesErrorCode),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TestCase {
    pub input: Input,
    pub pre_state: State,
    pub output: Output,
    pub post_state: State,
}
