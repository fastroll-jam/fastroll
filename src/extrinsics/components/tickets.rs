use crate::{
    codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput},
    common::BandersnatchRingVrfProof,
    crypto::vrf::RingVrfSignature,
};
use ark_ec_vrfs::prelude::ark_serialize::CanonicalDeserialize;
use std::cmp::Ordering;

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct TicketExtrinsicEntry {
    pub entry_index: u8,                        // r; N_N
    pub ticket_proof: BandersnatchRingVrfProof, // p; the ticket identifier (note: different from `Ticket` which contains hash of the proof as a ticket id)
}

impl PartialOrd for TicketExtrinsicEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TicketExtrinsicEntry {
    // Compare the ticket extrinsics by the hash of the ticket proofs, which is not explicitly
    // represented by the `TicketExtrinsicEntry`.
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

impl JamEncode for TicketExtrinsicEntry {
    fn size_hint(&self) -> usize {
        self.entry_index.size_hint() + self.ticket_proof.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.entry_index.encode_to(dest)?;
        self.ticket_proof.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for TicketExtrinsicEntry {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            entry_index: u8::decode(input)?,
            ticket_proof: BandersnatchRingVrfProof::decode(input)?,
        })
    }
}
