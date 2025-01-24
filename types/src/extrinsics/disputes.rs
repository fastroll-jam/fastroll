use crate::extrinsics::{XtEntry, XtType};
use rjam_codec::{
    JamCodecError, JamDecode, JamDecodeFixed, JamEncode, JamEncodeFixed, JamInput, JamOutput,
};
use rjam_common::{
    Ed25519PubKey, Ed25519Signature, Hash32, ValidatorIndex, FLOOR_ONE_THIRDS_VALIDATOR_COUNT,
    VALIDATORS_SUPER_MAJORITY,
};
use std::{
    cmp::Ordering,
    fmt::{Debug, Display, Formatter},
};

pub enum VerdictEvaluation {
    IsGood,
    IsBad,
    IsWonky,
    Invalid(usize),
}

pub struct OffendersHeaderMarker {
    pub items: Vec<Ed25519PubKey>,
}

/// Represents a collection of judgments regarding the validity of work reports and the misbehavior
/// of validators.
#[derive(Debug, PartialEq, Eq, JamEncode, JamDecode)]
pub struct DisputesXt {
    pub verdicts: Vec<Verdict>, // v
    pub culprits: Vec<Culprit>, // c
    pub faults: Vec<Fault>,     // f
}

impl Display for DisputesXt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "verdicts:")?;
        for verdict in &self.verdicts {
            writeln!(f, "  - {}", verdict)?;
        }

        writeln!(f, "culprits:")?;
        for culprit in &self.culprits {
            writeln!(f, "  - {}", culprit)?;
        }

        writeln!(f, "faults:")?;
        for fault in &self.faults {
            writeln!(f, "  - {}", fault)?;
        }

        Ok(())
    }
}
impl DisputesXt {
    pub fn count_culprits_with_report_hash(&self, report_hash: &Hash32) -> usize {
        self.culprits
            .iter()
            .filter(|culprit| &culprit.report_hash == report_hash)
            .count()
    }

    pub fn count_faults_with_report_hash(&self, report_hash: &Hash32) -> usize {
        self.faults
            .iter()
            .filter(|fault| &fault.report_hash == report_hash)
            .count()
    }

    pub fn get_verdict_by_report_hash(&self, report_hash: &Hash32) -> Option<&Verdict> {
        self.verdicts
            .iter()
            .find(|verdict| &verdict.report_hash == report_hash)
    }

    pub fn split_report_set(&self) -> (Vec<Hash32>, Vec<Hash32>, Vec<Hash32>) {
        let mut good_set = Vec::new();
        let mut bad_set = Vec::new();
        let mut wonky_set = Vec::new();

        for verdict in &self.verdicts {
            match verdict.evaluate_verdict() {
                VerdictEvaluation::IsGood => good_set.push(verdict.report_hash),
                VerdictEvaluation::IsBad => bad_set.push(verdict.report_hash),
                VerdictEvaluation::IsWonky => wonky_set.push(verdict.report_hash),
                _ => (),
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

    pub fn culprits_keys(&self) -> Vec<Ed25519PubKey> {
        self.culprits
            .iter()
            .map(|culprit| culprit.validator_key)
            .collect()
    }

    pub fn faults_keys(&self) -> Vec<Ed25519PubKey> {
        self.faults
            .iter()
            .map(|fault| fault.validator_key)
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub report_hash: Hash32,                                   // r
    pub epoch_index: u32,                                      // a
    pub judgments: Box<[Judgment; VALIDATORS_SUPER_MAJORITY]>, // j
}

impl Display for Verdict {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "report_hash: {}", self.report_hash.encode_hex())?;
        writeln!(f, "epoch_index: {}", self.epoch_index)?;
        writeln!(f, "judgments:")?;
        for judgment in self.judgments.iter() {
            writeln!(f, "  - {}", judgment)?;
        }
        Ok(())
    }
}

impl XtEntry for Verdict {
    const XT_TYPE: XtType = XtType::Verdict;
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

impl JamEncode for Verdict {
    fn size_hint(&self) -> usize {
        self.report_hash.size_hint() + 4 + self.judgments.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.report_hash.encode_to(dest)?;
        self.epoch_index.encode_to_fixed(dest, 4)?;
        self.judgments.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for Verdict {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        // TODO: delete
        // let mut judgments = Box::new([Judgment::default(); VALIDATORS_SUPER_MAJORITY]);
        // for judgment in judgments.iter_mut() {
        //     *judgment = Judgment::decode(input)?;
        // }
        Ok(Self {
            report_hash: Hash32::decode(input)?,
            epoch_index: u32::decode_fixed(input, 4)?,
            judgments: Box::<[Judgment; VALIDATORS_SUPER_MAJORITY]>::decode(input)?,
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
        if valid_judgments_count == VALIDATORS_SUPER_MAJORITY {
            VerdictEvaluation::IsGood
        } else if valid_judgments_count == 0 {
            VerdictEvaluation::IsBad
        } else if valid_judgments_count == FLOOR_ONE_THIRDS_VALIDATOR_COUNT {
            VerdictEvaluation::IsWonky
        } else {
            VerdictEvaluation::Invalid(valid_judgments_count)
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Judgment {
    pub is_report_valid: bool,             // v
    pub voter: ValidatorIndex,             // i
    pub voter_signature: Ed25519Signature, // s
}

impl JamEncode for Judgment {
    fn size_hint(&self) -> usize {
        self.is_report_valid.size_hint() + 2 + self.voter_signature.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.is_report_valid.encode_to(dest)?;
        self.voter.encode_to_fixed(dest, 2)?;
        self.voter_signature.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for Judgment {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            is_report_valid: bool::decode(input)?,
            voter: ValidatorIndex::decode_fixed(input, 2)?,
            voter_signature: Ed25519Signature::decode(input)?,
        })
    }
}

impl Display for Judgment {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "vote: {}", self.is_report_valid)?;
        writeln!(f, "voter: {}", self.voter)?;
        write!(f, "signature: {}", self.voter_signature.encode_hex())
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
#[derive(Debug, Clone, PartialEq, Eq, JamEncode, JamDecode, Hash)]
pub struct Culprit {
    pub report_hash: Hash32,          // r
    pub validator_key: Ed25519PubKey, // k; the guarantor
    pub signature: Ed25519Signature,  // s
}

impl Display for Culprit {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "report_hash: {}", self.report_hash.encode_hex())?;
        writeln!(f, "validator_key: {}", self.validator_key.encode_hex())?;
        write!(f, "signature: {}", self.signature.encode_hex())
    }
}

impl XtEntry for Culprit {
    const XT_TYPE: XtType = XtType::Culprit;
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

impl Display for Fault {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "report_hash: {}", self.report_hash.encode_hex())?;
        writeln!(f, "is_report_valid: {}", self.is_report_valid)?;
        writeln!(f, "validator_key: {}", self.validator_key.encode_hex())?;
        write!(f, "signature: {}", self.signature.encode_hex())
    }
}

impl XtEntry for Fault {
    const XT_TYPE: XtType = XtType::Fault;
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
