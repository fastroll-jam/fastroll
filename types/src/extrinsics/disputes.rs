use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::{
    Ed25519PubKey, Ed25519SignatureWithKeyAndMessage, Hash32, FLOOR_TWO_THIRDS_VALIDATOR_COUNT,
};

pub struct DisputesExtrinsic {
    verdicts: Vec<Verdict>, // v
    culprits: Vec<Culprit>, // c
    faults: Vec<Fault>,     // f
}

impl JamEncode for DisputesExtrinsic {
    fn size_hint(&self) -> usize {
        self.verdicts.size_hint() + self.culprits.size_hint() + self.faults.size_hint()
    }

    fn encode_to<W: JamOutput>(&self, dest: &mut W) -> Result<(), JamCodecError> {
        self.verdicts.encode_to(dest)?;
        self.culprits.encode_to(dest)?;
        self.faults.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for DisputesExtrinsic {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        Ok(Self {
            verdicts: Vec::decode(input)?,
            culprits: Vec::decode(input)?,
            faults: Vec::decode(input)?,
        })
    }
}

#[derive(Clone, Ord, PartialOrd, PartialEq, Eq)]
pub struct Verdict {
    report_hash: Hash32,                                 // r
    epoch_index: u32,                                    // a
    votes: [Vote; FLOOR_TWO_THIRDS_VALIDATOR_COUNT + 1], // j
}

impl JamEncode for Verdict {
    fn size_hint(&self) -> usize {
        self.report_hash.size_hint() + self.epoch_index.size_hint() + self.votes.size_hint()
    }

    fn encode_to<W: JamOutput>(&self, dest: &mut W) -> Result<(), JamCodecError> {
        self.report_hash.encode_to(dest)?;
        self.epoch_index.encode_to(dest)?;
        self.votes.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for Verdict {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        let mut votes = [Vote::default(); FLOOR_TWO_THIRDS_VALIDATOR_COUNT + 1];
        for vote in &mut votes {
            *vote = Vote::decode(input)?;
        }
        Ok(Self {
            report_hash: Hash32::decode(input)?,
            epoch_index: u32::decode(input)?,
            votes,
        })
    }
}

#[derive(Clone, Copy, Ord, PartialOrd, PartialEq, Eq)]
struct Vote {
    is_report_valid: bool,
    voter_index: u16, // N_V
    voter_signature: Ed25519SignatureWithKeyAndMessage,
}

impl JamEncode for Vote {
    fn size_hint(&self) -> usize {
        self.is_report_valid.size_hint()
            + self.voter_index.size_hint()
            + self.voter_signature.size_hint()
    }

    fn encode_to<W: JamOutput>(&self, dest: &mut W) -> Result<(), JamCodecError> {
        self.is_report_valid.encode_to(dest)?;
        self.voter_index.encode_to(dest)?;
        self.voter_signature.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for Vote {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        Ok(Self {
            is_report_valid: bool::decode(input)?,
            voter_index: u16::decode(input)?,
            voter_signature: Ed25519SignatureWithKeyAndMessage::decode(input)?,
        })
    }
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

#[derive(Clone, Ord, PartialOrd, PartialEq, Eq)]
pub struct Culprit {
    report_hash: Hash32,
    validator_key: Ed25519PubKey,
    signature: Ed25519SignatureWithKeyAndMessage,
}

impl JamEncode for Culprit {
    fn size_hint(&self) -> usize {
        self.report_hash.size_hint() + self.validator_key.size_hint() + self.signature.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.report_hash.encode_to(dest)?;
        self.validator_key.encode_to(dest)?;
        self.signature.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for Culprit {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            report_hash: Hash32::decode(input)?,
            validator_key: Ed25519PubKey::decode(input)?,
            signature: Ed25519SignatureWithKeyAndMessage::decode(input)?,
        })
    }
}

#[derive(Clone, Ord, PartialOrd, PartialEq, Eq)]
pub struct Fault {
    report_hash: Hash32,
    validator_key: Ed25519PubKey,
    signature: Ed25519SignatureWithKeyAndMessage,
}

impl JamEncode for Fault {
    fn size_hint(&self) -> usize {
        self.report_hash.size_hint() + self.validator_key.size_hint() + self.signature.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.report_hash.encode_to(dest)?;
        self.validator_key.encode_to(dest)?;
        self.signature.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for Fault {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            report_hash: Hash32::decode(input)?,
            validator_key: Ed25519PubKey::decode(input)?,
            signature: Ed25519SignatureWithKeyAndMessage::decode(input)?,
        })
    }
}
