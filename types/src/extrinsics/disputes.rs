use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::{
    Ed25519PubKey, Ed25519SignatureWithKeyAndMessage, Hash32, FLOOR_TWO_THIRDS_VALIDATOR_COUNT,
};

#[derive(Debug, JamEncode, JamDecode)]
pub struct DisputesExtrinsic {
    verdicts: Vec<Verdict>, // v
    culprits: Vec<Culprit>, // c
    faults: Vec<Fault>,     // f
}

#[derive(Debug, Clone, Ord, PartialOrd, PartialEq, Eq, JamEncode)]
pub struct Verdict {
    report_hash: Hash32,                                      // r
    epoch_index: u32,                                         // a
    votes: Box<[Vote; FLOOR_TWO_THIRDS_VALIDATOR_COUNT + 1]>, // j
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

#[derive(Debug, Clone, Copy, Ord, PartialOrd, PartialEq, Eq, JamEncode, JamDecode)]
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

#[derive(Debug, Clone, Ord, PartialOrd, PartialEq, Eq, JamEncode, JamDecode)]
pub struct Culprit {
    report_hash: Hash32,
    validator_key: Ed25519PubKey,
    signature: Ed25519SignatureWithKeyAndMessage,
}

#[derive(Debug, Clone, Ord, PartialOrd, PartialEq, Eq, JamEncode, JamDecode)]
pub struct Fault {
    report_hash: Hash32,
    validator_key: Ed25519PubKey,
    signature: Ed25519SignatureWithKeyAndMessage,
}
