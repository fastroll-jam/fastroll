use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::{
    Ed25519PubKey, Ed25519Signature, Hash32, ValidatorIndex, FLOOR_ONE_THIRDS_VALIDATOR_COUNT,
    FLOOR_TWO_THIRDS_VALIDATOR_COUNT,
};
use std::{cmp::Ordering, collections::HashSet};

pub enum VerdictEvaluation {
    IsGood,
    IsBad,
    IsWonky,
}

pub struct OffendersHeaderMarker {
    pub items: Vec<Ed25519PubKey>,
}

/// Represents a collection of judgments regarding the validity of work reports and the misbehavior
/// of validators.
#[derive(Debug, JamEncode, JamDecode)]
pub struct DisputesExtrinsic {
    pub verdicts: Vec<Verdict>, // v
    pub culprits: Vec<Culprit>, // c
    pub faults: Vec<Fault>,     // f
}

impl DisputesExtrinsic {
    /// Used for extrinsic validation
    pub fn extract_offenders_from_verdicts(
        &self,
    ) -> (HashSet<Ed25519PubKey>, HashSet<ValidatorIndex>) {
        let extracted_culprits = HashSet::new();
        let extracted_faults = HashSet::new();

        for verdict in &self.verdicts {
            match verdict.evaluate_verdict() {
                VerdictEvaluation::IsGood => {
                    // Voters who voted as "false" should be in the faults set.
                    unimplemented!()
                }
                VerdictEvaluation::IsBad => {
                    // Guarantors of the work reports related to the judgment should be in the culprits set.
                    // Voters who voted as "true" should be in the faults set.
                    unimplemented!()
                }
                _ => {}
            }
        }

        (extracted_culprits, extracted_faults)
    }

    pub fn count_offenders_from_verdicts(&self) -> (usize, usize) {
        unimplemented!()
    }

    pub fn split_report_set(&self) -> (HashSet<Hash32>, HashSet<Hash32>, HashSet<Hash32>) {
        let mut good_set = HashSet::new();
        let mut bad_set = HashSet::new();
        let mut wonky_set = HashSet::new();

        for verdict in &self.verdicts {
            let _ = match verdict.evaluate_verdict() {
                VerdictEvaluation::IsGood => good_set.insert(verdict.report_hash),
                VerdictEvaluation::IsBad => bad_set.insert(verdict.report_hash),
                VerdictEvaluation::IsWonky => wonky_set.insert(verdict.report_hash),
            };
        }

        (good_set, bad_set, wonky_set)
    }

    pub fn collect_offender_keys(&self) -> OffendersHeaderMarker {
        let mut offenders_keys: Vec<Ed25519PubKey> = self
            .culprits
            .iter()
            .map(|culprit| culprit.validator_key)
            .collect();
        let faults_keys: Vec<Ed25519PubKey> = self
            .faults
            .iter()
            .map(|fault| fault.validator_key)
            .collect();

        offenders_keys.extend(faults_keys);

        OffendersHeaderMarker {
            items: offenders_keys,
        }
    }

    pub fn culprits_set(&self) -> HashSet<Hash32> {
        self.culprits
            .iter()
            .map(|culprit| culprit.report_hash)
            .collect()
    }

    pub fn faults_set(&self) -> HashSet<Hash32> {
        self.faults.iter().map(|fault| fault.report_hash).collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, JamEncode)]
pub struct Verdict {
    pub report_hash: Hash32,                                              // r
    pub epoch_index: u32,                                                 // a
    pub judgments: Box<[Judgment; FLOOR_TWO_THIRDS_VALIDATOR_COUNT + 1]>, // j
}

impl PartialOrd for Verdict {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Verdict {
    fn cmp(&self, other: &Self) -> Ordering {
        self.report_hash.cmp(&other.report_hash)
    }
}

impl JamDecode for Verdict {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        let mut judgments = Box::new([Judgment::default(); FLOOR_TWO_THIRDS_VALIDATOR_COUNT + 1]);
        for judgment in judgments.iter_mut() {
            *judgment = Judgment::decode(input)?;
        }
        Ok(Self {
            report_hash: Hash32::decode(input)?,
            epoch_index: u32::decode(input)?,
            judgments,
        })
    }
}

impl Verdict {
    pub fn evaluate_verdict(&self) -> VerdictEvaluation {
        let valid_judgments_count = self
            .judgments
            .iter()
            .filter(|judgment| judgment.is_report_valid)
            .count();
        if valid_judgments_count > FLOOR_TWO_THIRDS_VALIDATOR_COUNT {
            VerdictEvaluation::IsGood
        } else if valid_judgments_count < FLOOR_ONE_THIRDS_VALIDATOR_COUNT {
            VerdictEvaluation::IsBad
        } else {
            VerdictEvaluation::IsWonky
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, JamEncode, JamDecode)]
pub struct Judgment {
    pub is_report_valid: bool,             // v
    pub voter: ValidatorIndex,             // i
    pub voter_signature: Ed25519Signature, // s
}

impl Default for Judgment {
    fn default() -> Self {
        Self {
            is_report_valid: false,
            voter: 0,
            voter_signature: [0u8; 64], // Assuming this implements Default
        }
    }
}

impl PartialOrd for Judgment {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Judgment {
    fn cmp(&self, other: &Self) -> Ordering {
        self.voter.cmp(&other.voter)
    }
}

/// Set of validators which have guaranteed a wrong work report.
#[derive(Debug, Clone, PartialEq, Eq, JamEncode, JamDecode)]
pub struct Culprit {
    pub report_hash: Hash32,          // r
    pub validator_key: Ed25519PubKey, // k; the guarantor
    pub signature: Ed25519Signature,  // s
}

impl PartialOrd for Culprit {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Culprit {
    fn cmp(&self, other: &Self) -> Ordering {
        self.validator_key.cmp(&other.validator_key)
    }
}

/// Set of validators which have cast a wrong vote (judgment) for a dispute, either:
/// - Cast `is_valid=false` for a good report.
/// - Cast `is_valid=true` for a bad report.
#[derive(Debug, Clone, PartialEq, Eq, JamEncode, JamDecode)]
pub struct Fault {
    pub report_hash: Hash32,          // r
    pub is_report_valid: bool,        // v
    pub validator_key: Ed25519PubKey, // k; the voter
    pub signature: Ed25519Signature,  // s
}

impl PartialOrd for Fault {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Fault {
    fn cmp(&self, other: &Self) -> Ordering {
        self.validator_key.cmp(&other.validator_key)
    }
}
