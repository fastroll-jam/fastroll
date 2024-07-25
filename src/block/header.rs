use crate::{
    codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput},
    common::{BandersnatchPubKey, BandersnatchSignature, Hash32, Ticket, EPOCH_LENGTH},
};

type EpochMarker = Option<(Hash32, [BandersnatchPubKey; 1023])>;
type WinningTicketsMarker = Option<[Ticket; EPOCH_LENGTH]>;
type JudgementsMarker = Vec<Hash32>;

#[derive(Debug)]
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

impl JamEncode for BlockHeader {
    fn size_hint(&self) -> usize {
        self.parent_hash.size_hint()
            + self.prior_state_root.size_hint()
            + self.extrinsic_hash.size_hint()
            + self.timeslot_index.size_hint()
            + self.epoch_marker.size_hint()
            + self.winning_tickets_marker.size_hint()
            + self.judgements_marker.size_hint()
            + self.block_author_index.size_hint()
            + self.vrf_signature.size_hint()
            + self.block_seal.size_hint()
    }

    fn encode_to<W: JamOutput>(&self, dest: &mut W) -> Result<(), JamCodecError> {
        self.parent_hash.encode_to(dest)?;
        self.prior_state_root.encode_to(dest)?;
        self.extrinsic_hash.encode_to(dest)?;
        self.timeslot_index.encode_to(dest)?;
        self.epoch_marker.encode_to(dest)?;
        self.winning_tickets_marker.encode_to(dest)?;
        self.judgements_marker.encode_to(dest)?;
        self.block_author_index.encode_to(dest)?;
        self.vrf_signature.encode_to(dest)?;
        self.block_seal.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for BlockHeader {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        Ok(Self {
            parent_hash: Hash32::decode(input)?,
            prior_state_root: Hash32::decode(input)?,
            extrinsic_hash: Hash32::decode(input)?,
            timeslot_index: u32::decode(input)?,
            epoch_marker: EpochMarker::decode(input)?,
            winning_tickets_marker: WinningTicketsMarker::decode(input)?,
            judgements_marker: JudgementsMarker::decode(input)?,
            block_author_index: u16::decode(input)?,
            vrf_signature: BandersnatchSignature::decode(input)?,
            block_seal: BandersnatchSignature::decode(input)?,
        })
    }
}
