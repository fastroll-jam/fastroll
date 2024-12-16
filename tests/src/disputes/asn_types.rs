use crate::{
    asn_types::{
        ByteArray32, ByteArray64, Ed25519Key, Ed25519Signature, TimeSlot, ValidatorsData,
        CORE_COUNT, VALIDATORS_SUPER_MAJORITY,
    },
    codec::asn_types::AsnWorkReport,
};
use rjam_common::{ByteArray, FLOOR_TWO_THIRDS_VALIDATOR_COUNT};
use rjam_types::{
    extrinsics::disputes::{
        Culprit, DisputesExtrinsic, Fault, Judgment, OffendersHeaderMarker, Verdict,
    },
    state::{
        disputes::DisputesState,
        reports::{PendingReport, PendingReports},
        timeslot::Timeslot,
    },
};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

pub type WorkReportHash = ByteArray32;
pub type EpochIndex = u32;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AvailabilityAssignment {
    pub report: AsnWorkReport,
    pub timeout: u32,
}

impl From<PendingReport> for AvailabilityAssignment {
    fn from(value: PendingReport) -> Self {
        Self {
            report: value.work_report.into(),
            timeout: value.timeslot.0,
        }
    }
}

impl From<AvailabilityAssignment> for PendingReport {
    fn from(value: AvailabilityAssignment) -> Self {
        Self {
            work_report: value.report.into(),
            timeslot: Timeslot::new(value.timeout),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AvailabilityAssignments([Option<AvailabilityAssignment>; CORE_COUNT]);

impl From<AvailabilityAssignments> for PendingReports {
    fn from(value: AvailabilityAssignments) -> Self {
        let mut reports: [Option<PendingReport>; CORE_COUNT] = Default::default();

        for (i, item) in value.0.iter().enumerate() {
            reports[i] = match item {
                Some(assignment) => {
                    let work_report = assignment.clone().report.into();
                    let pending_report = PendingReport {
                        work_report,
                        timeslot: Timeslot::new(assignment.timeout),
                    };
                    Some(pending_report)
                }
                None => None,
            };
        }

        PendingReports(Box::new(reports))
    }
}

impl From<PendingReports> for AvailabilityAssignments {
    fn from(value: PendingReports) -> Self {
        let mut assignments: [Option<AvailabilityAssignment>; CORE_COUNT] = Default::default();

        for (i, report_option) in value.0.iter().enumerate() {
            assignments[i] = match report_option {
                Some(pending_report) => {
                    let report = pending_report.clone().work_report.into();
                    let assignment = AvailabilityAssignment {
                        report,
                        timeout: pending_report.timeslot.0,
                    };
                    Some(assignment)
                }
                None => None,
            };
        }

        AvailabilityAssignments(assignments)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DisputeJudgement {
    pub vote: bool,
    pub index: u16,
    pub signature: Ed25519Signature,
}

impl From<DisputeJudgement> for Judgment {
    fn from(value: DisputeJudgement) -> Self {
        Self {
            is_report_valid: value.vote,
            voter: value.index,
            voter_signature: ByteArray::new(value.signature.0),
        }
    }
}

impl From<Judgment> for DisputeJudgement {
    fn from(value: Judgment) -> Self {
        Self {
            vote: value.is_report_valid,
            index: value.voter,
            signature: ByteArray64(value.voter_signature.0),
        }
    }
}

pub type DisputeJudgements = [DisputeJudgement; VALIDATORS_SUPER_MAJORITY];

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DisputeVerdict {
    pub target: WorkReportHash,
    pub age: EpochIndex,
    pub votes: DisputeJudgements,
}

impl From<DisputeVerdict> for Verdict {
    fn from(value: DisputeVerdict) -> Self {
        let mut judgments: [Judgment; FLOOR_TWO_THIRDS_VALIDATOR_COUNT + 1] = Default::default();

        for (i, vote) in value.votes.into_iter().enumerate() {
            judgments[i] = vote.into()
        }

        Self {
            report_hash: ByteArray::new(value.target.0),
            epoch_index: value.age,
            judgments: Box::new(judgments),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DisputeCulpritProof {
    pub target: WorkReportHash,
    pub key: Ed25519Key,
    pub signature: Ed25519Signature,
}

impl From<DisputeCulpritProof> for Culprit {
    fn from(value: DisputeCulpritProof) -> Self {
        Self {
            report_hash: ByteArray::new(value.target.0),
            validator_key: ByteArray::new(value.key.0),
            signature: ByteArray::new(value.signature.0),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DisputeFaultProof {
    pub target: WorkReportHash,
    pub vote: bool,
    pub key: Ed25519Key,
    pub signature: Ed25519Signature,
}

impl From<DisputeFaultProof> for Fault {
    fn from(value: DisputeFaultProof) -> Self {
        Self {
            report_hash: ByteArray::new(value.target.0),
            is_report_valid: value.vote,
            validator_key: ByteArray::new(value.key.0),
            signature: ByteArray::new(value.signature.0),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DisputesXt {
    pub verdicts: Vec<DisputeVerdict>,
    pub culprits: Vec<DisputeCulpritProof>,
    pub faults: Vec<DisputeFaultProof>,
}

impl From<DisputesXt> for DisputesExtrinsic {
    fn from(value: DisputesXt) -> Self {
        Self {
            verdicts: value.verdicts.into_iter().map(Verdict::from).collect(),
            culprits: value.culprits.into_iter().map(Culprit::from).collect(),
            faults: value.faults.into_iter().map(Fault::from).collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DisputesOutputMarks {
    pub offenders_mark: Vec<Ed25519Key>,
}

impl From<OffendersHeaderMarker> for DisputesOutputMarks {
    fn from(value: OffendersHeaderMarker) -> Self {
        let offenders_mark = value.items.into_iter().map(ByteArray32::from).collect();
        Self { offenders_mark }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DisputesRecords {
    pub good: Vec<WorkReportHash>,  // Good verdicts
    pub bad: Vec<WorkReportHash>,   // Bad verdicts
    pub wonky: Vec<WorkReportHash>, // Wonky verdicts
    pub offenders: Vec<Ed25519Key>, // Offenders
}

impl From<DisputesRecords> for DisputesState {
    fn from(value: DisputesRecords) -> Self {
        Self {
            good_set: value
                .good
                .into_iter()
                .map(|hash| ByteArray::new(hash.0))
                .collect(),
            bad_set: value
                .bad
                .into_iter()
                .map(|hash| ByteArray::new(hash.0))
                .collect(),
            wonky_set: value
                .wonky
                .into_iter()
                .map(|hash| ByteArray::new(hash.0))
                .collect(),
            punish_set: value
                .offenders
                .into_iter()
                .map(|key| ByteArray::new(key.0))
                .collect(),
        }
    }
}

impl From<DisputesState> for DisputesRecords {
    fn from(value: DisputesState) -> Self {
        Self {
            good: value.good_set.into_iter().map(ByteArray32::from).collect(),
            bad: value.bad_set.into_iter().map(ByteArray32::from).collect(),
            wonky: value.wonky_set.into_iter().map(ByteArray32::from).collect(),
            offenders: value
                .punish_set
                .into_iter()
                .map(ByteArray32::from)
                .collect(),
        }
    }
}

/// State relevant to Disputes STF
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
    pub disputes: DisputesXt,
}

/// State transition function execution error
#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ErrorCode {
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

/// Output from Disputes STF
#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Output {
    ok(DisputesOutputMarks),
    err(ErrorCode),
}

/// Disputes STF execution dump
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TestCase {
    pub input: Input,
    pub pre_state: State,
    pub output: Output,
    pub post_state: State,
}
