use crate::{
    codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput},
    common::{
        BandersnatchPubKey, BandersnatchRingRoot, Ticket, BANDERSNATCH_RING_ROOT_DEFAULT,
        EPOCH_LENGTH, VALIDATOR_COUNT,
    },
    crypto::vrf::RingVrfSignature,
    extrinsics::components::tickets::TicketExtrinsicEntry,
    state::components::validators::{ValidatorKey, ValidatorSet},
};
use ark_ec_vrfs::prelude::ark_serialize::CanonicalDeserialize;

pub(crate) struct SafroleState {
    pub(crate) pending_validator_set: ValidatorSet, // gamma_k
    pub(crate) ring_root: BandersnatchRingRoot,     // gamma_z
    pub(crate) slot_sealers: SlotSealerType,        // gamma_s
    pub(crate) ticket_accumulator: Vec<Ticket>,     // gamma_a; max length EPOCH_LENGTH
}

impl JamEncode for SafroleState {
    fn size_hint(&self) -> usize {
        self.pending_validator_set.size_hint()
            + self.ring_root.size_hint()
            + self.slot_sealers.size_hint()
            + self.ticket_accumulator.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.pending_validator_set.encode_to(dest)?;
        self.ring_root.encode_to(dest)?;
        self.slot_sealers.encode_to(dest)?;
        self.ticket_accumulator.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for SafroleState {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        let mut pending_validator_set = [ValidatorKey::default(); VALIDATOR_COUNT];
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

impl JamEncode for SlotSealerType {
    fn size_hint(&self) -> usize {
        match self {
            SlotSealerType::Tickets(tickets) => 1 + tickets.size_hint(),
            SlotSealerType::BandersnatchPubKeys(keys) => 1 + keys.size_hint(),
        }
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        match self {
            SlotSealerType::Tickets(tickets) => {
                0u8.encode_to(dest)?;
                tickets.encode_to(dest)?;
                Ok(())
            }
            SlotSealerType::BandersnatchPubKeys(keys) => {
                1u8.encode_to(dest)?;
                keys.encode_to(dest)?;
                Ok(())
            }
        }
    }
}

impl JamDecode for SlotSealerType {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        match u8::decode(input)? {
            0 => {
                let mut tickets = Vec::with_capacity(EPOCH_LENGTH);
                for _ in 0..EPOCH_LENGTH {
                    tickets.push(Ticket::decode(input)?);
                }
                let boxed_tickets: Box<[Ticket; EPOCH_LENGTH]> =
                    tickets.into_boxed_slice().try_into().map_err(|_| {
                        JamCodecError::ConversionError(
                            "Failed to convert to Box<[Ticket; EPOCH_LENGTH]>".into(),
                        )
                    })?;
                Ok(SlotSealerType::Tickets(boxed_tickets))
            }
            1 => {
                let mut keys = Vec::with_capacity(EPOCH_LENGTH);
                for _ in 0..EPOCH_LENGTH {
                    keys.push(BandersnatchPubKey::decode(input)?);
                }
                let boxed_keys: Box<[BandersnatchPubKey; EPOCH_LENGTH]> =
                    keys.into_boxed_slice().try_into().map_err(|_| {
                        JamCodecError::ConversionError(
                            "Failed to convert to Box<[BandersnatchPubKey; EPOCH_LENGTH]>".into(),
                        )
                    })?;
                Ok(SlotSealerType::BandersnatchPubKeys(boxed_keys))
            }
            _ => Err(JamCodecError::ConversionError(
                "Invalid SlotSealerType discriminator".into(),
            )),
        }
    }
}

fn ticket_extrinsics_to_new_tickets(ticket_extrinsics: Vec<TicketExtrinsicEntry>) -> Vec<Ticket> {
    ticket_extrinsics
        .iter()
        .map(|ticket| {
            let vrf_output_hash =
                RingVrfSignature::deserialize_compressed(&ticket.ticket_proof[..])
                    .unwrap()
                    .output_hash();
            (vrf_output_hash, ticket.entry_index)
        })
        .collect()
}
