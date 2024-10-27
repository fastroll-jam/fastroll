use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::{
    Address, Ed25519PubKey, Ed25519SignatureWithKeyAndMessage, Hash32,
    FLOOR_TWO_THIRDS_VALIDATOR_COUNT,
};
use std::cmp::Ordering;

/// # Ordering and Validation Rules for extrinsic components
/// - `verdicts` must be ordered by report hash, and `judgments` of each `Verdict` must be ordered by
///   the voters' validator index.
/// - Offender signatures `culprits` and `faults` must each be ordered by the validator's Ed25519 key.
/// - No duplicate report hashes allowed within the extrinsic, nor amongst any past reported hashes.
#[derive(Debug, JamEncode, JamDecode)]
pub struct DisputesExtrinsic {
    pub verdicts: Vec<Verdict>, // v
    pub culprits: Vec<Culprit>, // c
    pub faults: Vec<Fault>,     // f
}

#[derive(Debug, Clone, PartialEq, Eq, JamEncode)]
pub struct Verdict {
    report_hash: Hash32,                                              // r
    epoch_index: u32,                                                 // a
    judgments: Box<[Judgment; FLOOR_TWO_THIRDS_VALIDATOR_COUNT + 1]>, // j
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
struct Judgment {
    is_report_valid: bool,                              // v
    voter: Address,                                     // i
    voter_signature: Ed25519SignatureWithKeyAndMessage, // s
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

#[derive(Debug, Clone, PartialEq, Eq, JamEncode, JamDecode)]
pub struct Culprit {
    report_hash: Hash32,
    validator_key: Ed25519PubKey,
    signature: Ed25519SignatureWithKeyAndMessage,
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

#[derive(Debug, Clone, PartialEq, Eq, JamEncode, JamDecode)]
pub struct Fault {
    report_hash: Hash32,
    is_report_valid: bool,
    validator_key: Ed25519PubKey,
    signature: Ed25519SignatureWithKeyAndMessage,
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
