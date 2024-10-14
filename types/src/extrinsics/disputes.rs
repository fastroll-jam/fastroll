use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::{
    Ed25519PubKey, Ed25519SignatureWithKeyAndMessage, Hash32, FLOOR_TWO_THIRDS_VALIDATOR_COUNT,
};
use std::cmp::Ordering;

#[derive(Debug, JamEncode, JamDecode)]
pub struct DisputesExtrinsic {
    verdicts: Vec<Verdict>, // v
    culprits: Vec<Culprit>, // c
    faults: Vec<Fault>,     // f
}

#[derive(Debug, Clone, PartialEq, Eq, JamEncode)]
pub struct Verdict {
    report_hash: Hash32,                                      // r
    epoch_index: u32,                                         // a
    votes: Box<[Vote; FLOOR_TWO_THIRDS_VALIDATOR_COUNT + 1]>, // j; must be ordered by validator index
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
        let mut votes = Box::new([Vote::default(); FLOOR_TWO_THIRDS_VALIDATOR_COUNT + 1]);
        for vote in votes.iter_mut() {
            *vote = Vote::decode(input)?;
        }
        Ok(Self {
            report_hash: Hash32::decode(input)?,
            epoch_index: u32::decode(input)?,
            votes,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, JamEncode, JamDecode)]
struct Vote {
    is_report_valid: bool,
    voter_index: u16, // N_V
    voter_signature: Ed25519SignatureWithKeyAndMessage,
}

// Implement Default for Vote to allow array initialization
impl Default for Vote {
    fn default() -> Self {
        Self {
            is_report_valid: false,
            voter_index: 0,
            voter_signature: [0u8; 64], // Assuming this implements Default
        }
    }
}

impl PartialOrd for Vote {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Vote {
    fn cmp(&self, other: &Self) -> Ordering {
        self.voter_index.cmp(&other.voter_index)
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
