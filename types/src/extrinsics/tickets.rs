use ark_ec_vrfs::prelude::ark_serialize::CanonicalDeserialize;
use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::BandersnatchRingVrfSignature;
use rjam_crypto::RingVrfSignature;
use std::{cmp::Ordering, fmt::Display, ops::Deref};

/// Represents a sequence of validators' ticket proofs for block authoring privileges.
#[derive(Debug, JamEncode, JamDecode)]
pub struct TicketsExtrinsic {
    pub items: Vec<TicketsExtrinsicEntry>,
}

impl Deref for TicketsExtrinsic {
    type Target = Vec<TicketsExtrinsicEntry>;

    fn deref(&self) -> &Self::Target {
        &self.items
    }
}

impl Display for TicketsExtrinsic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TicketsExtrinsic [")?;
        for item in self.items.iter() {
            write!(f, "{}, ", item)?;
        }
        write!(f, "]")
    }
}

// TODO: check - test vector encodes "attempt" first, but GP encodes "signature" first.
#[derive(Debug, Clone, PartialEq, Eq, JamEncode, JamDecode)]
pub struct TicketsExtrinsicEntry {
    pub entry_index: u8,                            // r; N_N
    pub ticket_proof: BandersnatchRingVrfSignature, // p; the ticket identifier (note: different from `Ticket` which contains hash of the proof as a ticket id)
}

impl Display for TicketsExtrinsicEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TicketsExtrinsicEntry {{ entry_index: {}, ticket_proof_hash: {} }}",
            self.entry_index,
            RingVrfSignature::deserialize_compressed(&self.ticket_proof[..])
                .unwrap()
                .output_hash()
        )
    }
}

impl PartialOrd for TicketsExtrinsicEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TicketsExtrinsicEntry {
    // Compare the ticket extrinsics by the hash of the ticket proofs, which is not explicitly
    // represented by the `TicketsExtrinsicEntry`.
    fn cmp(&self, other: &Self) -> Ordering {
        let self_hash = RingVrfSignature::deserialize_compressed(&self.ticket_proof[..])
            .unwrap()
            .output_hash();
        let other_hash = RingVrfSignature::deserialize_compressed(&other.ticket_proof[..])
            .unwrap()
            .output_hash();
        self_hash.cmp(&other_hash)
    }
}
