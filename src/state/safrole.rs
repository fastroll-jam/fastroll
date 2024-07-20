use crate::{
    codec::encode_length_discriminated_field,
    common::{
        BandersnatchPubKey, BandersnatchRingRoot, Ticket, ValidatorKey, EPOCH_LENGTH,
        VALIDATOR_COUNT,
    },
};
use parity_scale_codec::{Encode, Output};

pub(crate) struct SafroleState {
    pending_validator_set: [ValidatorKey; VALIDATOR_COUNT], // gamma_k
    ring_root: BandersnatchRingRoot,                        // gamma_z
    slot_sealers: SlotSealerType,                           // gamma_s
    ticket_accumulator: Vec<Ticket>,                        // gamma_a; max length EPOCH_LENGTH
}

impl Encode for SafroleState {
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        self.pending_validator_set.encode_to(dest);
        self.ring_root.encode_to(dest);
        self.slot_sealers.encode_to(dest);
        encode_length_discriminated_field(&self.ticket_accumulator, dest);
    }
}

enum SlotSealerType {
    Tickets(Box<[Ticket; EPOCH_LENGTH]>),
    BandersnatchPubKeys(Box<[BandersnatchPubKey; EPOCH_LENGTH]>),
}

impl Encode for SlotSealerType {
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        match self {
            SlotSealerType::Tickets(tickets) => {
                0u8.encode_to(dest);
                tickets.encode_to(dest);
            }
            SlotSealerType::BandersnatchPubKeys(keys) => {
                1u8.encode_to(dest);
                keys.encode_to(dest);
            }
        }
    }
}
