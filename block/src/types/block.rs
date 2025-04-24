use crate::types::extrinsics::Extrinsics;
use rjam_codec::{
    JamCodecError, JamDecode, JamDecodeFixed, JamEncode, JamEncodeFixed, JamInput, JamOutput,
};
use rjam_common::{
    ticket::Ticket, BandersnatchPubKey, BandersnatchSignature, Ed25519PubKey, Hash32,
    ValidatorIndex, EPOCH_LENGTH, VALIDATOR_COUNT,
};
use rjam_crypto::{hash, Blake2b256, CryptoError};
use std::fmt::Display;
use thiserror::Error;

#[derive(Debug, PartialEq, Eq, JamEncode, JamDecode)]
pub struct Block {
    pub header: BlockHeader,
    pub extrinsics: Extrinsics,
}

pub type WinningTicketsMarker = [Ticket; EPOCH_LENGTH];

#[derive(Debug, Error)]
pub enum BlockHeaderError {
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("JamCodec error: {0}")]
    JamCodecError(#[from] JamCodecError),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct EpochMarkerValidatorKey {
    pub bandersnatch_key: BandersnatchPubKey,
    pub ed25519_key: Ed25519PubKey,
}

#[derive(Clone, Debug, PartialEq, Eq, JamEncode, JamDecode)]
pub struct EpochMarker {
    pub entropy: Hash32,
    pub tickets_entropy: Hash32,
    pub validators: Box<[EpochMarkerValidatorKey; VALIDATOR_COUNT]>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockHeaderData {
    /// `p`: The parent block hash.
    pub parent_hash: Hash32,
    /// `r`: The parent block posterior state root.
    pub parent_state_root: Hash32,
    /// `x`: Hash of the extrinsics introduced in the block.
    pub extrinsic_hash: Hash32,
    /// `t`: The timeslot index of the block.
    pub timeslot_index: u32,
    /// `e`: The epoch marker.
    pub epoch_marker: Option<EpochMarker>,
    /// `w`: The winning tickets marker.
    pub winning_tickets_marker: Option<WinningTicketsMarker>,
    /// `o`: The offenders marker.
    pub offenders_marker: Vec<Ed25519PubKey>,
    /// `i`: The block author index.
    pub author_index: ValidatorIndex,
    /// `v`: The block VRF signature, which is used as the epoch-entropy source.
    pub vrf_signature: BandersnatchSignature,
}

impl JamEncode for BlockHeaderData {
    fn size_hint(&self) -> usize {
        self.parent_hash.size_hint()
            + self.parent_state_root.size_hint()
            + self.extrinsic_hash.size_hint()
            + 4
            + self.epoch_marker.size_hint()
            + self.winning_tickets_marker.size_hint()
            + self.offenders_marker.size_hint()
            + 2
            + self.vrf_signature.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.parent_hash.encode_to(dest)?;
        self.parent_state_root.encode_to(dest)?;
        self.extrinsic_hash.encode_to(dest)?;
        self.timeslot_index.encode_to_fixed(dest, 4)?;
        self.epoch_marker.encode_to(dest)?;
        self.winning_tickets_marker.encode_to(dest)?;
        self.offenders_marker.encode_to(dest)?;
        self.author_index.encode_to_fixed(dest, 2)?;
        self.vrf_signature.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for BlockHeaderData {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            parent_hash: Hash32::decode(input)?,
            parent_state_root: Hash32::decode(input)?,
            extrinsic_hash: Hash32::decode(input)?,
            timeslot_index: u32::decode_fixed(input, 4)?,
            epoch_marker: Option::<EpochMarker>::decode(input)?,
            winning_tickets_marker: Option::<WinningTicketsMarker>::decode(input)?,
            offenders_marker: Vec::<Ed25519PubKey>::decode(input)?,
            author_index: ValidatorIndex::decode_fixed(input, 2)?,
            vrf_signature: BandersnatchSignature::decode(input)?,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockHeader {
    /// The block header data fields.
    pub header_data: BlockHeaderData,
    /// `s`: The block seal signed by the author.
    pub block_seal: BandersnatchSignature,
}

impl JamEncode for BlockHeader {
    fn size_hint(&self) -> usize {
        self.header_data.size_hint() + self.block_seal.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.header_data.encode_to(dest)?;
        self.block_seal.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for BlockHeader {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            header_data: BlockHeaderData::decode(input)?,
            block_seal: BandersnatchSignature::decode(input)?,
        })
    }
}

impl Display for BlockHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let offenders_encoded = self
            .header_data
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
             \tauthor_index: {:?},\n\
             \tvrf_signature: {:?},\n\
             \tblock_seal: {:?}\n\
             }}",
            self.parent_hash().encode_hex(),
            self.parent_state_root().encode_hex(),
            self.extrinsic_hash().encode_hex(),
            self.timeslot_index(),
            self.epoch_marker(),
            self.winning_tickets_marker(),
            offenders_encoded,
            self.author_index(),
            self.vrf_signature().encode_hex(),
            self.block_seal.encode_hex(),
        )
    }
}

impl BlockHeader {
    pub fn new(parent_hash: Hash32) -> Self {
        Self {
            header_data: BlockHeaderData {
                parent_hash,
                ..Default::default()
            },
            block_seal: BandersnatchSignature::default(),
        }
    }

    pub fn hash(&self) -> Result<Hash32, BlockHeaderError> {
        Ok(hash::<Blake2b256>(&self.encode()?)?)
    }

    pub fn parent_hash(&self) -> Hash32 {
        self.header_data.parent_hash
    }

    pub fn parent_state_root(&self) -> Hash32 {
        self.header_data.parent_state_root
    }

    pub fn extrinsic_hash(&self) -> Hash32 {
        self.header_data.extrinsic_hash
    }

    pub fn timeslot_index(&self) -> u32 {
        self.header_data.timeslot_index
    }

    pub fn epoch_marker(&self) -> Option<&EpochMarker> {
        self.header_data.epoch_marker.as_ref()
    }

    pub fn winning_tickets_marker(&self) -> Option<&WinningTicketsMarker> {
        self.header_data.winning_tickets_marker.as_ref()
    }

    pub fn offenders_marker(&self) -> &[Ed25519PubKey] {
        &self.header_data.offenders_marker
    }

    pub fn author_index(&self) -> ValidatorIndex {
        self.header_data.author_index
    }

    pub fn vrf_signature(&self) -> BandersnatchSignature {
        self.header_data.vrf_signature
    }
}
