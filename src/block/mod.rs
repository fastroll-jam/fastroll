use crate::common::{BandersnatchPubKey, BandersnatchSignature, Hash32, Ticket, EPOCH_LENGTH};

type EpochMarker = Option<(Hash32, [BandersnatchPubKey; 1023])>;
type WinningTicketsMarker = Option<[Ticket; EPOCH_LENGTH]>;
type JudgementsMarker = Option<Hash32>;

#[derive(Debug)]
pub struct BlockHeader {
    parent_hash: Hash32,
    prior_state_root: Hash32,
    extrinsic_hash: Hash32,
    timeslot_index: u32,
    epoch_marker: EpochMarker,
    winning_tickets_marker: WinningTicketsMarker,
    judgements_marker: JudgementsMarker,
    block_author_index: u16, // range [0, 1023)
    vrf_signature: BandersnatchSignature,
    block_seal: BandersnatchSignature,
}
