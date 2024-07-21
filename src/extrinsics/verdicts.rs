use crate::{
    codec::{encode_length_discriminated_field, size_hint_length_discriminated_field},
    common::{
        Ed25519PubKey, Ed25519SignatureWithKeyAndMessage, Hash32, FLOOR_TWO_THIRDS_VALIDATOR_COUNT,
    },
};
use parity_scale_codec::{Encode, Output};

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

#[derive(Encode)]
struct Culprit {
    report_hash: Hash32,
    validator_key: Ed25519PubKey,
    signature: Ed25519SignatureWithKeyAndMessage,
}

#[derive(Encode)]
struct Fault {
    report_hash: Hash32,
    validator_key: Ed25519PubKey,
    signature: Ed25519SignatureWithKeyAndMessage,
}
