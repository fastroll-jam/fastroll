use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::{
    BandersnatchPubKey, BandersnatchSignature, Ed25519PubKey, Hash32, Ticket, ValidatorIndex,
    BANDERSNATCH_SIGNATURE_EMPTY, EPOCH_LENGTH, HASH32_EMPTY, VALIDATOR_COUNT,
};
use std::fmt::Display;

pub type WinningTicketsMarker = [Ticket; EPOCH_LENGTH];
pub type OffendersMarker = Vec<Ed25519PubKey>;

#[derive(Clone, Debug, JamEncode, JamDecode)]
pub struct EpochMarker {
    pub entropy: Hash32,
    pub validators: Box<[BandersnatchPubKey; VALIDATOR_COUNT]>,
}

#[derive(Clone, Debug, JamEncode, JamDecode)]
pub struct BlockHeader {
    pub parent_hash: Hash32,                                  // p
    pub prior_state_root: Hash32,                             // r
    pub extrinsic_hash: Hash32,                               // x
    pub timeslot_index: u32,                                  // t
    pub epoch_marker: Option<EpochMarker>,                    // e
    pub winning_tickets_marker: Option<WinningTicketsMarker>, // w
    pub offenders_marker: OffendersMarker,                    // o
    pub block_author_index: ValidatorIndex,                   // i
    pub vrf_signature: BandersnatchSignature,                 // v
    pub block_seal: BandersnatchSignature,                    // s
}

impl Display for BlockHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let offenders_encoded = self
            .offenders_marker
            .iter()
            .map(hex::encode)
            .collect::<Vec<_>>();

        write!(
            f,
            "BlockHeader {{\n\
             \tparent_hash: {:?},\n\
             \tprior_state_root: {:?},\n\
             \textrinsic_hash: {:?},\n\
             \ttimeslot_index: {},\n\
             \tepoch_marker: {:?},\n\
             \twinning_tickets_marker: {:?},\n\
             \toffenders_marker: {:?},\n\
             \tblock_author_index: {:?},\n\
             \tvrf_signature: {:?},\n\
             \tblock_seal: {:?}\n\
             }}",
            hex::encode(self.parent_hash),
            hex::encode(self.prior_state_root),
            hex::encode(self.extrinsic_hash),
            self.timeslot_index,
            self.epoch_marker,
            self.winning_tickets_marker,
            offenders_encoded,
            self.block_author_index,
            hex::encode(self.vrf_signature),
            hex::encode(self.block_seal)
        )
    }
}

impl Default for BlockHeader {
    fn default() -> Self {
        Self {
            parent_hash: HASH32_EMPTY,
            prior_state_root: HASH32_EMPTY,
            extrinsic_hash: HASH32_EMPTY,
            timeslot_index: 0,
            epoch_marker: None,
            winning_tickets_marker: None,
            offenders_marker: vec![],
            block_author_index: 0,
            vrf_signature: BANDERSNATCH_SIGNATURE_EMPTY,
            block_seal: BANDERSNATCH_SIGNATURE_EMPTY,
        }
    }
}

impl BlockHeader {
    pub fn new(parent_hash: Hash32) -> Self {
        Self {
            parent_hash,
            ..Default::default()
        }
    }
}
