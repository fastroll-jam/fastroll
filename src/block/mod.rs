use crate::common::{BandersnatchPubKey, BandersnatchSignature, Hash32, Ticket, EPOCH_LENGTH};
use parity_scale_codec::{Encode, Output};

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
    block_author_index: u16, // range [0, 1023)
    vrf_signature: BandersnatchSignature,
    block_seal: BandersnatchSignature,
}

impl Encode for BlockHeader {
    fn size_hint(&self) -> usize {
        self.parent_hash.size_hint()
            + self.prior_state_root.size_hint()
            + self.extrinsic_hash.size_hint()
            + 4 // timeslot_index
            + size_hint_optional_field(&self.epoch_marker)
            + size_hint_optional_field(&self.winning_tickets_marker)
            + size_hint_length_discriminated_field(&self.judgements_marker)
            + 2 // block_author_index
            + self.vrf_signature.size_hint()
            + self.block_seal.size_hint()
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        self.parent_hash.encode_to(dest);
        self.prior_state_root.encode_to(dest);
        self.extrinsic_hash.encode_to(dest);
        let encoded_timeslot = self.timeslot_index.encode();
        dest.write(&encoded_timeslot[..4]);
        encode_optional_field(&self.epoch_marker, dest);
        encode_optional_field(&self.winning_tickets_marker, dest);
        encode_length_discriminated_field(&self.judgements_marker, dest);
        let encoded_author_index = self.block_author_index.encode();
        // let first_2_bytes = &encoded_author_index[..2];
        // first_2_bytes.encode_to(dest);
        dest.write(&encoded_author_index[..2]);
        self.vrf_signature.encode_to(dest);
        self.block_seal.encode_to(dest);
    }
}

// Encoding and size hint functions for optional values
fn encode_optional_field<T: Encode, W: Output + ?Sized>(field: &Option<T>, dest: &mut W) {
    match field {
        Some(value) => {
            1u8.encode_to(dest); // Encode the presence marker (1)
            value.encode_to(dest); // Encode the value
        }
        None => {
            0u8.encode_to(dest); // Encode the absence marker (0)
        }
    }
}

fn size_hint_optional_field<T: Encode>(field: &Option<T>) -> usize {
    match field {
        Some(value) => 1 + value.size_hint(), // 1 byte for the presence marker + size of the value
        None => 1,                            // 1 byte for the absence marker
    }
}

// Encoding and size hint functions for length-discriminated values
fn encode_length_discriminated_field<W: Output + ?Sized>(field: &[Hash32], dest: &mut W) {
    let length = field.len();
    if length > 255 {
        panic!("Length exceeds maximum value for u8"); // TODO: better handling
    }
    (length as u8).encode_to(dest); // Encode the length discriminator
    field.encode_to(dest); // Encode the value
}

fn size_hint_length_discriminated_field(field: &[Hash32]) -> usize {
    let length = field.len();
    if length > 255 {
        panic!("Length exceeds maximum value for u8"); // TODO: better handling
    }
    (field.len() as u8).size_hint() + field.size_hint() // Length of the length discriminator + size of the value
}
