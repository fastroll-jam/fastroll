use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::{
    BandersnatchPubKey, BandersnatchSignature, Hash32, Ticket, EPOCH_LENGTH, VALIDATOR_COUNT,
};

type EpochMarker = Option<(Hash32, [BandersnatchPubKey; VALIDATOR_COUNT])>;
type WinningTicketsMarker = Option<[Ticket; EPOCH_LENGTH]>;
type JudgementsMarker = Vec<Hash32>;

#[derive(Debug, JamEncode, JamDecode)]
pub struct BlockHeader {
    parent_hash: Hash32,
    prior_state_root: Hash32,
    extrinsic_hash: Hash32,
    timeslot_index: u32,
    epoch_marker: EpochMarker,
    winning_tickets_marker: WinningTicketsMarker,
    judgements_marker: JudgementsMarker,
    block_author_index: u16, //  N_V
    vrf_signature: BandersnatchSignature,
    block_seal: BandersnatchSignature,
}

impl BlockHeader {
    pub fn get_vrf_signature(&self) -> &BandersnatchSignature {
        &self.vrf_signature
    }

    pub fn get_timeslot_index(&self) -> u32 {
        self.timeslot_index
    }
}
