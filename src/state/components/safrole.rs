use crate::{
    codec::{
        JamCodecError, JamDecode, JamDecodeFixed, JamEncode, JamEncodeFixed, JamInput, JamOutput,
    },
    common::{
        sorted_limited_tickets::SortedLimitedTickets, BandersnatchPubKey, BandersnatchRingRoot,
        Hash32, Ticket, BANDERSNATCH_RING_ROOT_DEFAULT, EPOCH_LENGTH,
        TICKET_SUBMISSION_DEADLINE_SLOT, VALIDATOR_COUNT,
    },
    crypto::{
        generate_ring_root,
        utils::{blake2b_256_first_4bytes, CryptoError},
        vrf::RingVrfSignature,
    },
    extrinsics::components::tickets::TicketExtrinsicEntry,
    state::components::{
        entropy::EntropyAccumulator,
        timeslot::Timeslot,
        validators::{ActiveValidatorSet, StagingValidatorSet, ValidatorKey, ValidatorSet},
    },
    transition::{Transition, TransitionError},
};
use ark_ec_vrfs::prelude::ark_serialize::CanonicalDeserialize;
use std::fmt::{Display, Formatter};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FallbackKeyError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Codec error: {0}")]
    Codec(#[from] JamCodecError),
    #[error("Array conversion error")]
    ArrayConversion,
}

#[derive(Clone, Debug)]
pub struct SafroleState {
    pub pending_validator_set: ValidatorSet,      // gamma_k
    pub ring_root: BandersnatchRingRoot,          // gamma_z
    pub slot_sealers: SlotSealerType,             // gamma_s
    pub ticket_accumulator: SortedLimitedTickets, // gamma_a; max length EPOCH_LENGTH
}

impl Display for SafroleState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "SafroleState {{")?;

        writeln!(f, "  Pending Validator Set: [")?;
        for (i, validator) in self.pending_validator_set.iter().enumerate() {
            writeln!(f, "    Validator {}: {}", i, validator)?;
        }
        writeln!(f, "  ]")?;

        writeln!(f, "  Ring Root: {}", hex::encode(self.ring_root))?;

        writeln!(f, "  Slot Sealers:")?;
        match &self.slot_sealers {
            SlotSealerType::Tickets(tickets) => {
                for (i, ticket) in tickets.iter().enumerate() {
                    writeln!(f, "    Slot {}: {}", i, ticket)?;
                }
            }
            SlotSealerType::BandersnatchPubKeys(keys) => {
                for (i, key) in keys.iter().enumerate() {
                    writeln!(f, "    Slot {}: {}", i, hex::encode(key))?;
                }
            }
        }

        writeln!(f, "  Ticket Accumulator: {}", self.ticket_accumulator)?;

        write!(f, "}}")
    }
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
        let ticket_accumulator = SortedLimitedTickets::decode(input)?;

        Ok(Self {
            pending_validator_set,
            ring_root,
            slot_sealers,
            ticket_accumulator,
        })
    }
}

#[derive(Clone, Debug)]
pub enum SlotSealerType {
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

fn ticket_extrinsics_to_new_tickets(ticket_extrinsics: &[TicketExtrinsicEntry]) -> Vec<Ticket> {
    ticket_extrinsics
        .iter()
        .map(|ticket| {
            let vrf_output_hash =
                RingVrfSignature::deserialize_compressed(&ticket.ticket_proof[..])
                    .unwrap()
                    .output_hash();
            Ticket {
                id: vrf_output_hash,
                attempt: ticket.entry_index, // Assuming entry_index is compatible with u8
            }
        })
        .collect()
}

fn outside_in_array<T, const N: usize>(mut arr: [T; N]) -> [T; N] {
    let mid = N / 2;
    for i in 0..mid {
        arr.swap(i + 1, N - (i + 1));
    }
    arr
}

fn outside_in_vec<T>(mut vec: Vec<T>) -> Vec<T> {
    let len = vec.len();
    let mid = len / 2;
    for i in 0..mid {
        vec.swap(i + 1, len - (i + 1));
    }
    vec
}

fn generate_fallback_keys(
    validator_set: &ValidatorSet,
    entropy: Hash32,
) -> Result<[BandersnatchPubKey; EPOCH_LENGTH], FallbackKeyError> {
    let mut bandersnatch_keys: [BandersnatchPubKey; EPOCH_LENGTH] = [[0u8; 32]; EPOCH_LENGTH];
    let entropy_vec = entropy.to_vec();

    for (i, key) in bandersnatch_keys.iter_mut().enumerate() {
        let i_encoded = (i as u32)
            .encode_fixed(4)
            .map_err(FallbackKeyError::Codec)?;

        let mut entropy_with_index = entropy_vec.clone();
        entropy_with_index.extend_from_slice(&i_encoded);

        let mut hash: &[u8] = &blake2b_256_first_4bytes(&entropy_with_index)?;
        let key_index: u32 = u32::decode_fixed(&mut hash, 4)? % (VALIDATOR_COUNT as u32);

        *key = validator_set[key_index as usize].bandersnatch_key;
    }

    Ok(bandersnatch_keys)
}

pub struct SafroleStateContext {
    pub timeslot: Timeslot,
    pub is_new_epoch: bool,
    pub tickets: Vec<TicketExtrinsicEntry>,
    pub current_staging_set: StagingValidatorSet,
    pub post_active_set: ActiveValidatorSet,
    pub post_entropy: EntropyAccumulator,
}

impl Transition for SafroleState {
    type Context = SafroleStateContext;

    fn to_next(&mut self, ctx: &Self::Context) -> Result<(), TransitionError>
    where
        Self: Sized,
    {
        let entropy = ctx.post_entropy.second_history(); // eta_2

        //
        // Per-epoch operations
        //

        if ctx.is_new_epoch {
            // The fallback mode triggers when the slot phase hasn't reached the ticket submission
            // deadline or the ticket accumulator is not yet full.
            // TODO: check how the "slot_phase" is derived (calculated from timeslot or from a separate index)
            // FIXME: should refer to "previous" slot phase
            let is_fallback = ((ctx.timeslot.slot_phase() as usize)
                < TICKET_SUBMISSION_DEADLINE_SLOT)
                || !self.ticket_accumulator.is_full();

            // Update Safrole pending set into Global state staging set
            self.pending_validator_set = ctx.current_staging_set.0;

            // Update the ring root with the updated pending set ring
            self.ring_root = generate_ring_root(&self.pending_validator_set)?;

            // Update slot sealer sequence
            if is_fallback {
                let active_validator_set = ctx.post_active_set.0; // kappa

                self.slot_sealers = SlotSealerType::BandersnatchPubKeys(Box::new(
                    generate_fallback_keys(&active_validator_set, entropy)?,
                ))
            } else {
                let ticket_accumulator_outside_in: [Ticket; EPOCH_LENGTH] =
                    outside_in_vec(self.ticket_accumulator.clone().into_vec())
                        .try_into()
                        .unwrap();

                self.slot_sealers =
                    SlotSealerType::Tickets(Box::new(ticket_accumulator_outside_in));
            }

            // Reset the ticket accumulator
            self.ticket_accumulator = SortedLimitedTickets::new();
        }

        //
        // Per-slot operations
        //

        // let ticket_extrinsics: Vec<TicketExtrinsicEntry> = get_ticket_extrinsics(ctx.timeslot);
        let ticket_extrinsics = &ctx.tickets;

        // Check if the ticket extrinsics are ordered by ticket id
        for window in ticket_extrinsics.windows(2) {
            if let [prev, curr] = window {
                if prev > curr {
                    return Err(TransitionError::TicketsNotOrdered);
                }
            }
        }

        // TODO: Verify the ring VRF proof of each ticket extrinsic

        // Construct "new tickets" from Tickets Extrinsics
        let new_tickets = ticket_extrinsics_to_new_tickets(ticket_extrinsics);

        // Check if the ticket accumulator contains the new ticket entry
        // If not, accumulate the new ticket entry into the accumulator
        for ticket in new_tickets {
            if self.ticket_accumulator.contains(&ticket) {
                return Err(TransitionError::DuplicateTicket);
            }
            self.ticket_accumulator.add(ticket);
        }

        Ok(())
    }
}
