use crate::{
    codec::utils::{
        decode_length_discriminated_field, decode_optional_field,
        encode_length_discriminated_field, encode_optional_field,
        size_hint_length_discriminated_field, size_hint_optional_field,
    },
    common::{BandersnatchPubKey, BandersnatchSignature, Hash32, Ticket, EPOCH_LENGTH},
};
use parity_scale_codec::{Decode, Encode, Error, Input, Output};

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

impl Encode for BlockHeader {
    fn size_hint(&self) -> usize {
        self.parent_hash.size_hint()
            + self.prior_state_root.size_hint()
            + self.extrinsic_hash.size_hint()
            + self.timeslot_index.size_hint()
            + size_hint_optional_field(&self.epoch_marker)
            + size_hint_optional_field(&self.winning_tickets_marker)
            + size_hint_length_discriminated_field(&self.judgements_marker)
            + self.block_author_index.size_hint()
            + self.vrf_signature.size_hint()
            + self.block_seal.size_hint()
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        self.parent_hash.encode_to(dest);
        self.prior_state_root.encode_to(dest);
        self.extrinsic_hash.encode_to(dest);
        self.timeslot_index.encode_to(dest);
        encode_optional_field(&self.epoch_marker, dest);
        encode_optional_field(&self.winning_tickets_marker, dest);
        encode_length_discriminated_field(&self.judgements_marker, dest);
        self.block_author_index.encode_to(dest);
        self.vrf_signature.encode_to(dest);
        self.block_seal.encode_to(dest);
    }
}

impl Decode for BlockHeader {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        Ok(Self {
            parent_hash: Hash32::decode(input)?,
            prior_state_root: Hash32::decode(input)?,
            extrinsic_hash: Hash32::decode(input)?,
            timeslot_index: u32::decode(input)?,
            epoch_marker: decode_optional_field(input)?,
            winning_tickets_marker: decode_optional_field(input)?,
            judgements_marker: decode_length_discriminated_field(input)?,
            block_author_index: u16::decode(input)?,
            vrf_signature: BandersnatchSignature::decode(input)?,
            block_seal: BandersnatchSignature::decode(input)?,
        })
    }
}
