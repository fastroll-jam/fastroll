use crate::{
    asn_types::{
        ByteArray32, ByteArray64, Ed25519Key, Ed25519Signature, TimeSlot, ValidatorsData,
        CORE_COUNT, VALIDATORS_SUPER_MAJORITY,
    },
    test_utils::{deserialize_hex_array, serialize_hex_array},
};
use rjam_codec::{JamDecode, JamEncode};
use rjam_common::FLOOR_TWO_THIRDS_VALIDATOR_COUNT;
use rjam_types::{
    common::workloads::WorkReport,
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
    #[serde(
        serialize_with = "serialize_hex_array",
        deserialize_with = "deserialize_hex_array"
    )]
    pub dummy_work_report: [u8; 353],
    pub timeout: u32,
}

fn encode_to_dummy_report<T>(data: T) -> [u8; 353]
where
    T: JamEncode + JamDecode,
{
    data.encode().unwrap().try_into().unwrap()
}

fn decode_from_dummy_report(data: &[u8; 353]) -> WorkReport {
    WorkReport::decode(&mut data.as_slice()).unwrap()
}

impl From<PendingReport> for AvailabilityAssignment {
    fn from(value: PendingReport) -> Self {
        Self {
            dummy_work_report: encode_to_dummy_report(value.work_report),
            timeout: value.timeslot.0,
        }
    }
}

impl From<AvailabilityAssignment> for PendingReport {
    fn from(value: AvailabilityAssignment) -> Self {
        Self {
            work_report: WorkReport::decode(&mut value.dummy_work_report.as_slice()).unwrap(),
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
                    let work_report = decode_from_dummy_report(&assignment.dummy_work_report);
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
                    let dummy_work_report =
                        encode_to_dummy_report(pending_report.work_report.clone());
                    let assignment = AvailabilityAssignment {
                        dummy_work_report,
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
            voter_signature: value.signature.0,
        }
    }
}

impl From<Judgment> for DisputeJudgement {
    fn from(value: Judgment) -> Self {
        Self {
            vote: value.is_report_valid,
            index: value.voter,
            signature: ByteArray64(value.voter_signature),
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
            report_hash: value.target.0,
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
            report_hash: value.target.0,
            validator_key: value.key.0,
            signature: value.signature.0,
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
            report_hash: value.target.0,
            is_report_valid: value.vote,
            validator_key: value.key.0,
            signature: value.signature.0,
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
    pub psi_g: Vec<WorkReportHash>, // Good verdicts
    pub psi_b: Vec<WorkReportHash>, // Bad verdicts
    pub psi_w: Vec<WorkReportHash>, // Wonky verdicts
    pub psi_o: Vec<Ed25519Key>,     // Offenders
}

impl From<DisputesRecords> for DisputesState {
    fn from(value: DisputesRecords) -> Self {
        Self {
            good_set: value.psi_g.into_iter().map(|hash| hash.0).collect(),
            bad_set: value.psi_b.into_iter().map(|hash| hash.0).collect(),
            wonky_set: value.psi_w.into_iter().map(|hash| hash.0).collect(),
            punish_set: value.psi_o.into_iter().map(|key| key.0).collect(),
        }
    }
}

impl From<DisputesState> for DisputesRecords {
    fn from(value: DisputesState) -> Self {
        Self {
            psi_g: value.good_set.into_iter().map(ByteArray32::from).collect(),
            psi_b: value.bad_set.into_iter().map(ByteArray32::from).collect(),
            psi_w: value.wonky_set.into_iter().map(ByteArray32::from).collect(),
            psi_o: value
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
