use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::{
    BandersnatchPubKey, BandersnatchSignature, Ed25519PubKey, Hash32, Ticket, ValidatorIndex,
    BANDERSNATCH_SIGNATURE_EMPTY, EPOCH_LENGTH, HASH32_EMPTY, VALIDATOR_COUNT,
};
use rjam_crypto::{hash, Blake2b256, CryptoError};
use std::fmt::Display;
use thiserror::Error;

pub type WinningTicketsMarker = [Ticket; EPOCH_LENGTH];

#[derive(Debug, Error)]
pub enum BlockHeaderError {
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("JamCodec error: {0}")]
    JamCodecError(#[from] JamCodecError),
}

#[derive(Clone, Debug, JamEncode, JamDecode)]
pub struct EpochMarker {
    pub entropy: Hash32,
    pub validators: Box<[BandersnatchPubKey; VALIDATOR_COUNT]>,
}

#[derive(Clone, Debug, JamEncode, JamDecode)]
pub struct BlockHeader {
    pub parent_hash: Hash32,                                  // p
    pub parent_state_root: Hash32,                            // r
    pub extrinsic_hash: Hash32,                               // x
    pub timeslot_index: u32,                                  // t
    pub epoch_marker: Option<EpochMarker>,                    // e
    pub winning_tickets_marker: Option<WinningTicketsMarker>, // w
    pub offenders_marker: Vec<Ed25519PubKey>,                 // o
    pub block_author_index: ValidatorIndex,                   // i
    pub vrf_signature: BandersnatchSignature,                 // v
    pub block_seal: BandersnatchSignature,                    // s
}

impl Display for BlockHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let offenders_encoded = self
            .offenders_marker
            .iter()
            .map(|key| key.encode_hex())
            .collect::<Vec<_>>();

        write!(
            f,
            "BlockHeader {{\n\
             \tparent_hash: {:?},\n\
             \tparent_state_root: {:?},\n\
             \textrinsic_hash: {:?},\n\
             \ttimeslot_index: {},\n\
             \tepoch_marker: {:?},\n\
             \twinning_tickets_marker: {:?},\n\
             \toffenders_marker: {:?},\n\
             \tblock_author_index: {:?},\n\
             \tvrf_signature: {:?},\n\
             \tblock_seal: {:?}\n\
             }}",
            self.parent_hash.encode_hex(),
            self.parent_state_root.encode_hex(),
            self.extrinsic_hash.encode_hex(),
            self.timeslot_index,
            self.epoch_marker,
            self.winning_tickets_marker,
            offenders_encoded,
            self.block_author_index,
            self.vrf_signature.encode_hex(),
            self.block_seal.encode_hex(),
        )
    }
}

impl Default for BlockHeader {
    fn default() -> Self {
        Self {
            parent_hash: HASH32_EMPTY,
            parent_state_root: HASH32_EMPTY,
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

    pub fn hash(&self) -> Result<Hash32, BlockHeaderError> {
        let mut buf = vec![];
        self.encode_to(&mut buf)?;
        Ok(hash::<Blake2b256>(&buf[..])?)
    }
}
