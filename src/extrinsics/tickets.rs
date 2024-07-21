use crate::common::BandersnatchRingVrfProof;
use parity_scale_codec::Encode;

#[derive(Encode)]
pub(crate) struct TicketExtrinsicEntry {
    entry_index: u32,                       // r; N_N
    ticket_proof: BandersnatchRingVrfProof, // p
}
