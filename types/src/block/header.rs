use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::{
    BandersnatchPubKey, BandersnatchSignature, Ed25519PubKey, Hash32, Ticket, ValidatorIndex,
    EPOCH_LENGTH, VALIDATOR_COUNT,
};

pub type WinningTicketsMarker = [Ticket; EPOCH_LENGTH];
pub type OffendersMarker = Vec<Ed25519PubKey>;

#[derive(Debug, JamEncode, JamDecode)]
pub struct EpochMarker {
    pub entropy: Hash32,
    pub validators: Box<[BandersnatchPubKey; VALIDATOR_COUNT]>,
}

#[derive(Debug, JamEncode, JamDecode)]
pub struct BlockHeader {
    parent_hash: Hash32,                                  // p
    prior_state_root: Hash32,                             // r
    extrinsic_hash: Hash32,                               // x
    timeslot_index: u32,                                  // t
    epoch_marker: Option<EpochMarker>,                    // e
    winning_tickets_marker: Option<WinningTicketsMarker>, // w
    offenders_marker: OffendersMarker,                    // o
    block_author_index: ValidatorIndex,                   // i
    vrf_signature: BandersnatchSignature,                 // v
    block_seal: BandersnatchSignature,                    // s
}

impl BlockHeader {
    pub fn get_vrf_signature(&self) -> &BandersnatchSignature {
        &self.vrf_signature
    }

    pub fn get_timeslot_index(&self) -> u32 {
        self.timeslot_index
    }
}
