use crate::{
    codec::{encode_length_discriminated_field, size_hint_length_discriminated_field},
    common::{
        BandersnatchPubKey, BandersnatchRingRoot, Ticket, ValidatorKey,
        BANDERSNATCH_RING_ROOT_DEFAULT, EPOCH_LENGTH, VALIDATOR_COUNT, VALIDATOR_KEY_DEFAULT,
    },
};
use parity_scale_codec::{Decode, Encode, Error, Input, Output};

pub(crate) struct SafroleState {
    pending_validator_set: [ValidatorKey; VALIDATOR_COUNT], // gamma_k
    ring_root: BandersnatchRingRoot,                        // gamma_z
    slot_sealers: SlotSealerType,                           // gamma_s
    ticket_accumulator: Vec<Ticket>,                        // gamma_a; max length EPOCH_LENGTH
}

impl Encode for SafroleState {
    fn size_hint(&self) -> usize {
        self.pending_validator_set.size_hint()
            + self.ring_root.size_hint()
            + self.slot_sealers.size_hint()
            + size_hint_length_discriminated_field(&self.ticket_accumulator)
    }

    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        self.pending_validator_set.encode_to(dest);
        self.ring_root.encode_to(dest);
        self.slot_sealers.encode_to(dest);
        encode_length_discriminated_field(&self.ticket_accumulator, dest);
    }
}

impl Decode for SafroleState {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let mut pending_validator_set = [VALIDATOR_KEY_DEFAULT; VALIDATOR_COUNT];
        for validator in pending_validator_set.iter_mut() {
            *validator = ValidatorKey::decode(input)?;
        }

        let mut ring_root = BANDERSNATCH_RING_ROOT_DEFAULT;
        input.read(&mut ring_root)?;

        let slot_sealers = SlotSealerType::decode(input)?;
        let ticket_accumulator = Vec::<Ticket>::decode(input)?;

        Ok(Self {
            pending_validator_set,
            ring_root,
            slot_sealers,
            ticket_accumulator,
        })
    }
}

enum SlotSealerType {
    Tickets(Box<[Ticket; EPOCH_LENGTH]>),
    BandersnatchPubKeys(Box<[BandersnatchPubKey; EPOCH_LENGTH]>),
}

impl Encode for SlotSealerType {
    fn size_hint(&self) -> usize {
        match self {
            SlotSealerType::Tickets(tickets) => 1 + tickets.size_hint(),
            SlotSealerType::BandersnatchPubKeys(keys) => 1 + keys.size_hint(),
        }
    }

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

impl Decode for SlotSealerType {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        match u8::decode(input)? {
            0 => {
                let mut tickets = Vec::with_capacity(EPOCH_LENGTH);
                for _ in 0..EPOCH_LENGTH {
                    tickets.push(Ticket::decode(input)?);
                }
                let boxed_tickets: Box<[Ticket; EPOCH_LENGTH]> = tickets
                    .into_boxed_slice()
                    .try_into()
                    .map_err(|_| Error::from("Failed to convert to Box<[Ticket; EPOCH_LENGTH]>"))?;
                Ok(SlotSealerType::Tickets(boxed_tickets))
            }
            1 => {
                let mut keys = Vec::with_capacity(EPOCH_LENGTH);
                for _ in 0..EPOCH_LENGTH {
                    keys.push(BandersnatchPubKey::decode(input)?);
                }
                let boxed_keys: Box<[BandersnatchPubKey; EPOCH_LENGTH]> =
                    keys.into_boxed_slice().try_into().map_err(|_| {
                        Error::from("Failed to convert to Box<[BandersnatchPubKey; EPOCH_LENGTH]>")
                    })?;
                Ok(SlotSealerType::BandersnatchPubKeys(boxed_keys))
            }
            // TODO: add custom error types
            _ => Err(Error::from("Invalid SlotSealerType discriminator")),
        }
    }
}
