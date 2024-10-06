use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::{
    BandersnatchPubKey, BandersnatchSignature, Ed25519PubKey, Hash32, Ticket, EPOCH_LENGTH,
    VALIDATOR_COUNT,
};

pub type EpochMarker = Option<(Hash32, [BandersnatchPubKey; VALIDATOR_COUNT])>;
pub type WinningTicketsMarker = Option<[Ticket; EPOCH_LENGTH]>;
pub type OffendersMarker = Vec<Ed25519PubKey>;

#[derive(Debug, JamEncode, JamDecode)]
pub struct BlockHeader {
    parent_hash: Hash32,
    prior_state_root: Hash32,
    extrinsic_hash: Hash32,
    timeslot_index: u32,
    epoch_marker: EpochMarker,
    winning_tickets_marker: WinningTicketsMarker,
    offenders_marker: OffendersMarker,
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
