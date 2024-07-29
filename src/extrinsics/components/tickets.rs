use crate::{
    codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput},
    common::BandersnatchRingVrfProof,
};

#[derive(Copy, Clone, Ord, PartialOrd, PartialEq, Eq)]
pub(crate) struct TicketExtrinsicEntry {
    pub(crate) entry_index: u8,                        // r; N_N
    pub(crate) ticket_proof: BandersnatchRingVrfProof, // p; the ticket identifier
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
