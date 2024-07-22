use crate::common::BandersnatchRingVrfProof;
use parity_scale_codec::{Decode, Encode};

#[derive(Encode, Decode)]
pub(crate) struct TicketExtrinsicEntry {
    entry_index: u32,                       // r; N_N
    ticket_proof: BandersnatchRingVrfProof, // p
}
