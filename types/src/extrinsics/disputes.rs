use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::{
    Ed25519PubKey, Ed25519Signature, Hash32, ValidatorIndex, FLOOR_TWO_THIRDS_VALIDATOR_COUNT,
};
use std::cmp::Ordering;

/// Represents a collection of judgments regarding the validity of work reports and the misbehavior
/// of validators.
#[derive(Debug, JamEncode, JamDecode)]
pub struct DisputesExtrinsic {
    pub verdicts: Vec<Verdict>, // v
    pub culprits: Vec<Culprit>, // c
    pub faults: Vec<Fault>,     // f
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
