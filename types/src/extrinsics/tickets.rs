use ark_ec_vrfs::prelude::ark_serialize::CanonicalDeserialize;
use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::BandersnatchRingVrfSignature;
use rjam_crypto::vrf::RingVrfSignature;
use std::cmp::Ordering;

/// # Ordering and Validation Rules for Extrinsic Components
/// - The length of `items` is at most `K = 16` if the current slot phase `m'` is less than
///   `Y = 500`. Otherwise, the `items` must be empty.
#[derive(Debug, JamEncode, JamDecode)]
pub struct TicketsExtrinsic {
    items: Vec<TicketsExtrinsicEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, JamEncode, JamDecode)]
pub struct TicketsExtrinsicEntry {
    pub ticket_proof: BandersnatchRingVrfSignature, // p; the ticket identifier (note: different from `Ticket` which contains hash of the proof as a ticket id)
    pub entry_index: u8,                            // r; N_N
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
