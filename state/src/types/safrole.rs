use crate::{
    impl_simple_state_component,
    state_utils::{SimpleStateComponent, StateComponent, StateEntryType, StateKeyConstant},
    types::Timeslot,
};
use fr_block::types::block::{EpochMarker, WinningTicketsMarker};
use fr_codec::prelude::*;
use fr_common::{
    ticket::Ticket, ByteEncodable, EntropyHash, ValidatorIndex, EPOCH_LENGTH, VALIDATOR_COUNT,
};
use fr_crypto::{error::CryptoError, hash_prefix_4, types::*, Blake2b256};
use fr_limited_vec::FixedVec;
use std::{
    collections::BinaryHeap,
    fmt::{Display, Formatter},
};
use thiserror::Error;

pub type EpochTickets = FixedVec<Ticket, EPOCH_LENGTH>;
pub type EpochFallbackKeys = FixedVec<BandersnatchPubKey, EPOCH_LENGTH>;

#[derive(Error, Debug)]
pub enum SlotSealerError {
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("Codec error: {0}")]
    CodecError(#[from] JamCodecError),
}

#[derive(Clone, Default)]
pub struct SafroleHeaderMarkers {
    pub epoch_marker: Option<EpochMarker>,
    pub winning_tickets_marker: Option<WinningTicketsMarker>,
}

/// State components associated with the Safrole protocol.
///
/// Represents `γ` of the GP.
#[derive(Debug, Clone, Default, PartialEq, Eq, JamEncode)]
pub struct SafroleState {
    /// `γ_P`: Pending validator key set, which will be active in the next epoch.
    /// This set is used to determine the Bandersnatch ring root for the next epoch.
    pub pending_set: ValidatorKeySet,
    /// `γ_Z`: Bandersnatch ring root of the current epoch.
    pub ring_root: BandersnatchRingRoot,
    /// `γ_S`: Slot-sealers of the current epoch.
    /// Composed of `E` tickets (or `E` Bandersnatch keys in the fallback mode).
    pub slot_sealers: SlotSealers,
    /// `γ_A`: Ticket accumulator.
    pub ticket_accumulator: TicketAccumulator,
}
impl_simple_state_component!(SafroleState, SafroleState);

impl Display for SafroleState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{{")?;
        writeln!(f, "  \"PendingSet\": [")?;
        for (i, validator) in self.pending_set.iter().enumerate() {
            writeln!(f, "    {{")?;
            writeln!(f, "      \"{i}\": {validator}")?;
            writeln!(f, "    }},")?;
        }
        writeln!(f, "  ],")?;
        writeln!(f, "  \"Ring Root\": \"{}\",", self.ring_root.encode_hex())?;

        writeln!(f, "  \"Slot Sealers\": {{")?;
        match &self.slot_sealers {
            SlotSealers::Tickets(tickets) => {
                for (i, ticket) in tickets.iter().enumerate() {
                    writeln!(f, "    \"{i}\": \"{ticket}\",")?;
                }
            }
            SlotSealers::BandersnatchPubKeys(keys) => {
                for (i, key) in keys.iter().enumerate() {
                    writeln!(f, "    \"{i}\": \"{}\",", key.to_hex())?;
                }
            }
        }
        writeln!(f, "  }},")?;

        writeln!(f, "  \"Ticket Accumulator\": {}", self.ticket_accumulator)?;
        write!(f, "}},")
    }
}

impl JamDecode for SafroleState {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        let mut pending_set = ValidatorKeySet::default();
        for validator in pending_set.iter_mut() {
            *validator = ValidatorKey::decode(input)?;
        }

        let mut ring_root = BandersnatchRingRoot::default();
        input.read(&mut *ring_root)?;

        let slot_sealers = SlotSealers::decode(input)?;
        let ticket_accumulator = TicketAccumulator::decode(input)?;

        Ok(Self {
            pending_set,
            ring_root,
            slot_sealers,
            ticket_accumulator,
        })
    }
}

pub enum SlotSealer {
    Ticket(Ticket),
    BandersnatchPubKeys(BandersnatchPubKey),
}

impl Default for SlotSealer {
    fn default() -> Self {
        Self::Ticket(Ticket::default())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotSealers {
    Tickets(EpochTickets),
    BandersnatchPubKeys(EpochFallbackKeys),
}

impl Default for SlotSealers {
    fn default() -> Self {
        Self::BandersnatchPubKeys(EpochFallbackKeys::default())
    }
}

impl Display for SlotSealers {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tickets(tickets) => {
                for ticket in tickets.iter() {
                    writeln!(f, "{},", ticket)?;
                }
            }
            Self::BandersnatchPubKeys(keys) => {
                for key in keys.iter() {
                    writeln!(f, "0x{},", key.to_hex())?;
                }
            }
        }
        Ok(())
    }
}

impl JamEncode for SlotSealers {
    fn size_hint(&self) -> usize {
        1 + EPOCH_LENGTH
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        match self {
            SlotSealers::Tickets(tickets) => {
                0u8.encode_to(dest)?;
                tickets.encode_to(dest)?;
                Ok(())
            }
            SlotSealers::BandersnatchPubKeys(keys) => {
                1u8.encode_to(dest)?;
                keys.encode_to(dest)?;
                Ok(())
            }
        }
    }
}

impl JamDecode for SlotSealers {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        match u8::decode(input)? {
            0 => {
                let mut tickets = Vec::with_capacity(EPOCH_LENGTH);
                for _ in 0..EPOCH_LENGTH {
                    tickets.push(Ticket::decode(input)?);
                }
                let epoch_tickets = FixedVec::try_from(tickets).map_err(|_| {
                    JamCodecError::ConversionError(
                        "EpochTickets has more than EPOCH_LENGTH entries".to_string(),
                    )
                })?;
                Ok(SlotSealers::Tickets(epoch_tickets))
            }
            1 => {
                let mut keys = Vec::with_capacity(EPOCH_LENGTH);
                for _ in 0..EPOCH_LENGTH {
                    keys.push(BandersnatchPubKey::decode(input)?);
                }
                let epoch_keys = FixedVec::try_from(keys).map_err(|_| {
                    JamCodecError::ConversionError(
                        "EpochFallbackKeys has more than EPOCH_LENGTH entries".to_string(),
                    )
                })?;
                Ok(SlotSealers::BandersnatchPubKeys(epoch_keys))
            }
            _ => Err(JamCodecError::ConversionError(
                "Invalid SlotSealers type discriminator".into(),
            )),
        }
    }
}

pub fn outside_in_vec<T: Clone>(vec: Vec<T>) -> Vec<T> {
    let len = vec.len();
    let mut result = Vec::with_capacity(len);
    let mut left = 0;
    let mut right = len - 1;

    while left <= right {
        if let Some(left_elem) = vec.get(left) {
            result.push(left_elem.clone());
        }
        if left != right {
            if let Some(right_elem) = vec.get(right) {
                result.push(right_elem.clone());
            }
        }
        left += 1;
        right = right.saturating_sub(1);
    }
    result
}

impl SlotSealers {
    pub fn is_fallback(&self) -> bool {
        match self {
            Self::Tickets(_) => false,
            Self::BandersnatchPubKeys(_) => true,
        }
    }

    pub fn get_slot_sealer(&self, timeslot: &Timeslot) -> SlotSealer {
        let slot_phase = timeslot.slot_phase() as usize;
        match self {
            Self::Tickets(tickets) => SlotSealer::Ticket(tickets[slot_phase].clone()),
            Self::BandersnatchPubKeys(keys) => {
                SlotSealer::BandersnatchPubKeys(keys[slot_phase].clone())
            }
        }
    }
}

pub fn generate_fallback_keys(
    validator_set: &ValidatorKeySet,
    entropy: &EntropyHash,
) -> Result<FixedVec<BandersnatchPubKey, EPOCH_LENGTH>, SlotSealerError> {
    let mut fallback_keys = EpochFallbackKeys::default();
    let entropy_vec = entropy.to_vec();

    for (i, key) in fallback_keys.iter_mut().enumerate() {
        let i_encoded = (i as u32)
            .encode_fixed(4)
            .map_err(SlotSealerError::CodecError)?;

        let mut entropy_with_index = entropy_vec.clone();
        entropy_with_index.extend_from_slice(&i_encoded);

        let mut hash: &[u8] = &hash_prefix_4::<Blake2b256>(&entropy_with_index)?;
        let key_index: u32 = u32::decode_fixed(&mut hash, 4)? % (VALIDATOR_COUNT as u32);

        *key = validator_set
            .get_validator_bandersnatch_key(key_index as ValidatorIndex)
            .cloned()
            .expect("Should exist; index is modulo");
    }

    Ok(fallback_keys)
}

/// The ticket accumulator which holds submitted tickets sorted by their id with a length limit of `EPOCH_LENGTH`.
///
/// This struct maintains a max-heap of tickets, ensuring that the tickets are kept in ascending
/// order by their id. When the number of tickets reaches `EPOCH_LENGTH`, any new tickets added
/// will only replace existing tickets if they have a lower id.
#[derive(Clone, Debug)]
pub struct TicketAccumulator {
    heap: BinaryHeap<Ticket>,
}

impl Display for TicketAccumulator {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{{")?;
        writeln!(f, "  \"Tickets\": [")?;
        for (i, ticket) in self.heap.iter().enumerate() {
            writeln!(f, "    \"{i}\": {ticket}")?;
        }
        writeln!(f, "  ]")?;
        write!(f, "}}")
    }
}

impl Default for TicketAccumulator {
    fn default() -> Self {
        Self {
            heap: BinaryHeap::with_capacity(EPOCH_LENGTH),
        }
    }
}

impl PartialEq for TicketAccumulator {
    fn eq(&self, other: &Self) -> bool {
        let self_sorted = self.heap.clone().into_sorted_vec();
        let other_sorted = other.heap.clone().into_sorted_vec();
        self_sorted == other_sorted
    }
}

impl Eq for TicketAccumulator {}

impl TicketAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.heap.len()
    }

    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.heap.len() == EPOCH_LENGTH
    }

    /// Adds a single ticket to the accumulator.
    ///
    /// If the accumulator is not full, the ticket is always added. If it's full, the ticket is
    /// only added if its id is lower than the highest id currently in the accumulator.
    ///
    /// In this case, the ticket with the highest id is removed to make space.
    pub fn add(&mut self, ticket: Ticket) {
        if self.heap.len() < EPOCH_LENGTH {
            self.heap.push(ticket);
        } else if let Some(max_ticket) = self.heap.peek() {
            // Peek gives the largest element (max-heap)
            if &ticket < max_ticket {
                self.heap.pop(); // Remove the peek
                self.heap.push(ticket); // Insert the new smaller ticket
            }
        }
    }
    pub fn add_multiple(&mut self, tickets: Vec<Ticket>) {
        for ticket in tickets {
            self.add(ticket);
        }
    }

    pub fn contains(&self, ticket: &Ticket) -> bool {
        self.heap.iter().any(|t| *t == *ticket)
    }

    pub fn into_vec(self) -> Vec<Ticket> {
        let mut tickets: Vec<_> = self.heap.into_iter().collect();
        tickets.sort_unstable(); // Return in a sorted form
        tickets
    }

    pub fn as_vec(&self) -> Vec<Ticket> {
        let mut tickets: Vec<_> = self.heap.iter().cloned().collect();
        tickets.sort_unstable(); // Return in a sorted form
        tickets
    }

    pub fn from_vec(tickets: Vec<Ticket>) -> Self {
        let mut sorted_limited = Self::new();
        sorted_limited.add_multiple(tickets);
        sorted_limited
    }
}

impl JamEncode for TicketAccumulator {
    fn size_hint(&self) -> usize {
        let tickets_vec: Vec<Ticket> = self.as_vec();
        tickets_vec.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        let tickets_vec: Vec<Ticket> = self.as_vec();
        tickets_vec.encode_to(dest)
    }
}

impl JamDecode for TicketAccumulator {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        // Decode as `Vec<Ticket>` type first
        let tickets_vec = Vec::<Ticket>::decode(input)?;

        // Create a new `TicketAccumulator`
        let mut sorted_tickets = Self::new();
        sorted_tickets.add_multiple(tickets_vec);

        Ok(sorted_tickets)
    }
}

#[cfg(test)]
mod ticket_accumulator_tests {
    use super::*;
    use fr_common::TicketId;

    fn create_ticket(i: u16) -> Ticket {
        let mut hash = TicketId::default();
        hash[0] = (i >> 8) as u8;
        hash[1] = i as u8;
        Ticket {
            id: hash,
            attempt: (i % 2) as u8,
        }
    }

    #[test]
    fn test_add() {
        let mut tickets = TicketAccumulator::new();
        let epoch_length_u16 = EPOCH_LENGTH as u16;
        for i in 0..epoch_length_u16 {
            tickets.add(create_ticket(i));
        }
        assert_eq!(tickets.len(), epoch_length_u16.into());
        assert_eq!(
            tickets.as_vec(),
            (0..epoch_length_u16).map(create_ticket).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_add_over_capacity() {
        let mut tickets = TicketAccumulator::new();
        for i in 0..EPOCH_LENGTH as u16 + 1 {
            let mut hash = TicketId::default();
            // Constructing tickets with unique hash values, with first two bytes
            hash[0] = (i >> 8) as u8;
            hash[1] = (i & 0xFF) as u8;
            tickets.add(Ticket {
                id: hash,
                attempt: (i % 2) as u8,
            });
        }

        assert_eq!(tickets.len(), EPOCH_LENGTH); // The MaxHeap contains exactly EPOCH_LENGTH tickets only

        let expected: Vec<Ticket> = (0..EPOCH_LENGTH as u16)
            .map(|i| {
                let mut hash = TicketId::default();
                hash[0] = (i >> 8) as u8;
                hash[1] = (i & 0xFF) as u8;
                Ticket {
                    id: hash,
                    attempt: (i % 2) as u8,
                }
            })
            .collect();

        assert_eq!(tickets.as_vec(), expected);

        // Large ticket should not be included in the MaxHeap
        let large_ticket = {
            let mut hash = TicketId::default();
            hash[0] = (EPOCH_LENGTH as u16 >> 8) as u8;
            hash[1] = (EPOCH_LENGTH as u16 & 0xFF) as u8;
            Ticket {
                id: hash,
                attempt: (EPOCH_LENGTH as u16 % 2) as u8,
            }
        };
        assert!(!tickets.as_vec().contains(&large_ticket));
    }

    #[test]
    fn test_add_multiple() {
        let mut tickets = TicketAccumulator::new();
        let new_tickets: Vec<Ticket> = (0..1000).map(create_ticket).collect();
        tickets.add_multiple(new_tickets);
        assert_eq!(tickets.len(), EPOCH_LENGTH);
        assert_eq!(
            tickets.as_vec(),
            (0..EPOCH_LENGTH as u16)
                .map(create_ticket)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_add_mixed_order() {
        let mut tickets = TicketAccumulator::new();
        tickets.add(create_ticket(500));
        tickets.add(create_ticket(100));
        tickets.add(create_ticket(300));
        tickets.add(create_ticket(700));
        tickets.add(create_ticket(200));
        tickets.add(create_ticket(900));
        assert_eq!(
            tickets.as_vec(),
            vec![
                create_ticket(100),
                create_ticket(200),
                create_ticket(300),
                create_ticket(500),
                create_ticket(700),
                create_ticket(900)
            ]
        )
    }
}
