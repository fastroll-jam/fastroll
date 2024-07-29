use crate::{
    codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput},
    common::BandersnatchRingVrfProof,
};

pub(crate) struct TicketExtrinsicEntry {
    entry_index: u32,                       // r; N_N
    ticket_proof: BandersnatchRingVrfProof, // p
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
            entry_index: u32::decode(input)?,
            ticket_proof: BandersnatchRingVrfProof::decode(input)?,
        })
    }
}
