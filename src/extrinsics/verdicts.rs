use crate::{
    codec::{
        decode_length_discriminated_field, encode_length_discriminated_field,
        size_hint_length_discriminated_field,
    },
    common::{
        Ed25519PubKey, Ed25519SignatureWithKeyAndMessage, Hash32, FLOOR_TWO_THIRDS_VALIDATOR_COUNT,
    },
};
use parity_scale_codec::{Decode, Encode, Error, Input, Output};

pub(crate) struct VerdictsExtrinsic {
    verdicts: Vec<Verdict>, // j
    culprits: Vec<Culprit>, // c
    faults: Vec<Fault>,     // f
}

impl Encode for VerdictsExtrinsic {
    fn size_hint(&self) -> usize {
        size_hint_length_discriminated_field(&self.verdicts)
            + size_hint_length_discriminated_field(&self.culprits)
            + size_hint_length_discriminated_field(&self.faults)
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        encode_length_discriminated_field(&self.verdicts, dest);
        encode_length_discriminated_field(&self.culprits, dest);
        encode_length_discriminated_field(&self.faults, dest);
    }
}

impl Decode for VerdictsExtrinsic {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        Ok(Self {
            verdicts: decode_length_discriminated_field(input)?,
            culprits: decode_length_discriminated_field(input)?,
            faults: decode_length_discriminated_field(input)?,
        })
    }
}

struct Verdict {
    report_hash: Hash32,                                 // r
    epoch_index: u32,                                    // a
    votes: [Vote; FLOOR_TWO_THIRDS_VALIDATOR_COUNT + 1], // v
}

impl Encode for Verdict {
    fn size_hint(&self) -> usize {
        self.report_hash.size_hint() + self.epoch_index.size_hint() + self.votes.size_hint()
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        self.report_hash.encode_to(dest);
        self.epoch_index.encode_to(dest);
        self.votes.encode_to(dest);
    }
}

impl Decode for Verdict {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let report_hash = Hash32::decode(input)?;
        let epoch_index = u32::decode(input)?;
        let mut votes = [Vote::default(); FLOOR_TWO_THIRDS_VALIDATOR_COUNT + 1];
        for vote in &mut votes {
            *vote = Vote::decode(input)?;
        }
        Ok(Self {
            report_hash,
            epoch_index,
            votes,
        })
    }
}

#[derive(Copy, Clone)]
struct Vote {
    is_report_valid: bool,
    voter_index: u16, // N_V
    voter_signature: Ed25519SignatureWithKeyAndMessage,
}

impl Encode for Vote {
    fn size_hint(&self) -> usize {
        self.is_report_valid.size_hint()
            + self.voter_index.size_hint()
            + self.voter_signature.size_hint()
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        self.is_report_valid.encode_to(dest);
        self.voter_index.encode_to(dest);
        self.voter_signature.encode_to(dest);
    }
}

impl Decode for Vote {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
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

#[derive(Encode, Decode)]
struct Culprit {
    report_hash: Hash32,
    validator_key: Ed25519PubKey,
    signature: Ed25519SignatureWithKeyAndMessage,
}

#[derive(Encode, Decode)]
struct Fault {
    report_hash: Hash32,
    validator_key: Ed25519PubKey,
    signature: Ed25519SignatureWithKeyAndMessage,
}
