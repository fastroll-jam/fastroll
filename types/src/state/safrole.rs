use crate::{
    impl_simple_state_component,
    state_utils::{SimpleStateComponent, StateComponent, StateEntryType, StateKeyConstant},
};
use rjam_codec::{
    JamCodecError, JamDecode, JamDecodeFixed, JamEncode, JamEncodeFixed, JamInput, JamOutput,
};
use rjam_common::{
    BandersnatchPubKey, BandersnatchRingRoot, Hash32, Ticket, ValidatorKey, ValidatorKeySet,
    EPOCH_LENGTH, VALIDATOR_COUNT,
};
use rjam_crypto::{hash_prefix_4, Blake2b256, CryptoError};
use std::{
    array::from_fn,
    collections::BinaryHeap,
    fmt::{Display, Formatter},
};
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

#[derive(Debug, Clone, PartialEq, Eq, JamEncode)]
pub struct SafroleState {
    pub pending_set: ValidatorKeySet,          // gamma_k
    pub ring_root: BandersnatchRingRoot,       // gamma_z
    pub slot_sealers: SlotSealerType,          // gamma_s
    pub ticket_accumulator: TicketAccumulator, // gamma_a
}
impl_simple_state_component!(SafroleState, SafroleState);

impl Default for SafroleState {
    fn default() -> Self {
        Self {
            pending_set: Box::new(from_fn(|_| ValidatorKey::default())),
            ring_root: BandersnatchRingRoot::default(),
            slot_sealers: SlotSealerType::default(),
            ticket_accumulator: TicketAccumulator::default(),
        }
    }
}

impl Display for SafroleState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{{")?;
        writeln!(f, "  \"PendingSet\": [")?;
        for (i, validator) in self.pending_set.iter().enumerate() {
            writeln!(f, "    {{")?;
            writeln!(f, "      \"{}\": {}", i, validator)?;
            writeln!(f, "    }},")?;
        }
        writeln!(f, "  ],")?;
        writeln!(f, "  \"Ring Root\": \"{}\",", self.ring_root.encode_hex())?;

        writeln!(f, "  \"Slot Sealers\": {{")?;
        match &self.slot_sealers {
            SlotSealerType::Tickets(tickets) => {
                for (i, ticket) in tickets.iter().enumerate() {
                    writeln!(f, "    \"{}\": \"{}\",", i, ticket)?;
                }
            }
            SlotSealerType::BandersnatchPubKeys(keys) => {
                for (i, key) in keys.iter().enumerate() {
                    writeln!(f, "    \"{}\": \"{}\",", i, key.encode_hex())?;
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
        let mut pending_set = Box::new([ValidatorKey::default(); VALIDATOR_COUNT]);
        for validator in pending_set.iter_mut() {
            *validator = ValidatorKey::decode(input)?;
        }

        let mut ring_root = BandersnatchRingRoot::default();
        input.read(&mut *ring_root)?;

        let slot_sealers = SlotSealerType::decode(input)?;
        let ticket_accumulator = TicketAccumulator::decode(input)?;

        Ok(Self {
            pending_set,
            ring_root,
            slot_sealers,
            ticket_accumulator,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotSealerType {
    Tickets(Box<[Ticket; EPOCH_LENGTH]>),
    BandersnatchPubKeys(Box<[BandersnatchPubKey; EPOCH_LENGTH]>),
}

impl Default for SlotSealerType {
    fn default() -> Self {
        Self::Tickets(Box::new([Ticket::default(); EPOCH_LENGTH]))
    }
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

pub fn generate_fallback_keys(
    validator_set: &ValidatorKeySet,
    entropy: Hash32,
) -> Result<[BandersnatchPubKey; EPOCH_LENGTH], FallbackKeyError> {
    let mut bandersnatch_keys: [BandersnatchPubKey; EPOCH_LENGTH] =
        [BandersnatchPubKey::default(); EPOCH_LENGTH];
    let entropy_vec = entropy.to_vec();

    for (i, key) in bandersnatch_keys.iter_mut().enumerate() {
        let i_encoded = (i as u32)
            .encode_fixed(4)
            .map_err(FallbackKeyError::Codec)?;

        let mut entropy_with_index = entropy_vec.clone();
        entropy_with_index.extend_from_slice(&i_encoded);

        let mut hash: &[u8] = &hash_prefix_4::<Blake2b256>(&entropy_with_index)?;
        let key_index: u32 = u32::decode_fixed(&mut hash, 4)? % (VALIDATOR_COUNT as u32);

        *key = validator_set[key_index as usize].bandersnatch_key;
    }

    Ok(bandersnatch_keys)
}

/// A data structure used for ticket accumulator which holds submitted tickets sorted by their id
/// with a length limit defined by `EPOCH_LENGTH`.
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
            writeln!(f, "    \"{}\": {}", i, ticket)?;
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

    fn create_ticket(i: u16) -> Ticket {
        let mut hash = Hash32::default();
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
            let mut hash = Hash32::default();
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
                let mut hash = Hash32::default();
                hash[0] = (i >> 8) as u8;
                hash[1] = (i & 0xFF) as u8;
                Ticket {
                    id: hash, // hash is already [u8; 32], which is Hash32
                    attempt: (i % 2) as u8,
                }
            })
            .collect();

        assert_eq!(tickets.as_vec(), expected);

        // Large ticket should not be included in the MaxHeap
        let large_ticket = {
            let mut hash = Hash32::default();
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
