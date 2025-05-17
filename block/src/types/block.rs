use crate::types::extrinsics::{disputes::OffendersHeaderMarker, Extrinsics};
use fr_codec::prelude::*;
use fr_common::{
    ticket::Ticket, ByteEncodable, Hash32, ValidatorIndex, EPOCH_LENGTH, VALIDATOR_COUNT,
};
use fr_crypto::{
    error::CryptoError,
    hash::{hash, Blake2b256},
    types::*,
};
use std::fmt::{Display, Formatter};
use thiserror::Error;

pub type BlockSeal = BandersnatchSig;
pub type VrfSig = BandersnatchSig;
pub type WinningTicketsMarker = [Ticket; EPOCH_LENGTH];

#[derive(Debug, Error)]
pub enum BlockHeaderError {
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("JamCodec error: {0}")]
    JamCodecError(#[from] JamCodecError),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct Block {
    pub header: BlockHeader,
    pub extrinsics: Extrinsics,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, JamEncode, JamDecode)]
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
    pub prior_state_root: Hash32,
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
    pub vrf_signature: VrfSig,
}

impl JamEncode for BlockHeaderData {
    fn size_hint(&self) -> usize {
        self.parent_hash.size_hint()
            + self.prior_state_root.size_hint()
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
        self.prior_state_root.encode_to(dest)?;
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
            prior_state_root: Hash32::decode(input)?,
            extrinsic_hash: Hash32::decode(input)?,
            timeslot_index: u32::decode_fixed(input, 4)?,
            epoch_marker: Option::<EpochMarker>::decode(input)?,
            winning_tickets_marker: Option::<WinningTicketsMarker>::decode(input)?,
            offenders_marker: Vec::<Ed25519PubKey>::decode(input)?,
            author_index: ValidatorIndex::decode_fixed(input, 2)?,
            vrf_signature: VrfSig::decode(input)?,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockHeader {
    /// The block header data fields.
    pub data: BlockHeaderData,
    /// `s`: The block seal signed by the author.
    pub block_seal: BlockSeal,
}

impl JamEncode for BlockHeader {
    fn size_hint(&self) -> usize {
        self.data.size_hint() + self.block_seal.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.data.encode_to(dest)?;
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
            data: BlockHeaderData::decode(input)?,
            block_seal: BlockSeal::decode(input)?,
        })
    }
}

impl Display for BlockHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let offenders_encoded = self
            .data
            .offenders_marker
            .iter()
            .map(|key| key.to_hex())
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
            self.vrf_signature().to_hex(),
            self.block_seal.to_hex(),
        )
    }
}

impl BlockHeader {
    pub fn from_parent_hash(parent_hash: Hash32) -> Self {
        Self {
            data: BlockHeaderData {
                parent_hash,
                ..Default::default()
            },
            block_seal: BlockSeal::default(),
        }
    }

    pub fn hash(&self) -> Result<Hash32, BlockHeaderError> {
        Ok(hash::<Blake2b256>(&self.encode()?)?)
    }

    pub fn block_announcement_blob(&self) -> Result<Vec<u8>, BlockHeaderError> {
        // Announcement = Header ++ Header Hash ++ Slot
        let mut buf = vec![];
        self.encode_to(&mut buf)?;
        self.hash()?.encode_to(&mut buf)?;
        self.timeslot_index().encode_to(&mut buf)?;
        Ok(buf)
    }

    // --- Getters

    pub fn parent_hash(&self) -> &Hash32 {
        &self.data.parent_hash
    }

    pub fn parent_state_root(&self) -> &Hash32 {
        &self.data.prior_state_root
    }

    pub fn extrinsic_hash(&self) -> &Hash32 {
        &self.data.extrinsic_hash
    }

    pub fn timeslot_index(&self) -> u32 {
        self.data.timeslot_index
    }

    pub fn epoch_marker(&self) -> Option<&EpochMarker> {
        self.data.epoch_marker.as_ref()
    }

    pub fn winning_tickets_marker(&self) -> Option<&WinningTicketsMarker> {
        self.data.winning_tickets_marker.as_ref()
    }

    pub fn offenders_marker(&self) -> &[Ed25519PubKey] {
        &self.data.offenders_marker
    }

    pub fn author_index(&self) -> ValidatorIndex {
        self.data.author_index
    }

    pub fn vrf_signature(&self) -> VrfSig {
        self.data.vrf_signature.clone()
    }

    // --- Setters

    pub fn set_parent_hash(&mut self, hash: Hash32) {
        self.data.parent_hash = hash;
    }

    pub fn set_prior_state_root(&mut self, root: Hash32) {
        self.data.prior_state_root = root;
    }

    pub fn set_timeslot(&mut self, timeslot_index: u32) {
        self.data.timeslot_index = timeslot_index;
    }

    pub fn set_extrinsic_hash(&mut self, xt_hash: Hash32) {
        self.data.extrinsic_hash = xt_hash;
    }

    pub fn set_author_index(&mut self, author_index: ValidatorIndex) {
        self.data.author_index = author_index;
    }

    pub fn set_epoch_marker(&mut self, epoch_marker: EpochMarker) {
        self.data.epoch_marker = Some(epoch_marker);
    }

    pub fn set_winning_tickets_marker(&mut self, winning_tickets_marker: WinningTicketsMarker) {
        self.data.winning_tickets_marker = Some(winning_tickets_marker);
    }

    pub fn set_offenders_marker(&mut self, offenders_header_marker: OffendersHeaderMarker) {
        self.data.offenders_marker = offenders_header_marker.items
    }

    pub fn set_vrf_signature(&mut self, signature: VrfSig) {
        self.data.vrf_signature = signature;
    }

    pub fn set_block_seal(&mut self, block_seal: BlockSeal) {
        self.block_seal = block_seal;
    }
}

#[derive(Clone, Debug, JamDecode)]
pub struct BlockAnnouncement {
    pub header: BlockHeader,
    pub header_hash: Hash32,
    pub timeslot: u32,
}

impl Display for BlockAnnouncement {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Header: {}", self.header)?;
        writeln!(f, "Header hash: {}", self.header_hash)?;
        writeln!(f, "timeslot: {}", self.timeslot)?;
        Ok(())
    }
}
