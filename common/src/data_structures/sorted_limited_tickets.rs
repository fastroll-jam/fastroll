use crate::{Ticket, EPOCH_LENGTH};
use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use std::{
    collections::BinaryHeap,
    fmt::{Display, Formatter},
};

/// A data structure used for ticket accumulator which holds submitted tickets sorted by their id
/// with a length limit defined by `EPOCH_LENGTH`.
///
/// This struct maintains a max-heap of tickets, ensuring that the tickets are kept in ascending
/// order by their id. When the number of tickets reaches `EPOCH_LENGTH`, any new tickets added
/// will only replace existing tickets if they have a lower id.
#[derive(Clone, Debug)]
pub struct SortedLimitedTickets {
    heap: BinaryHeap<Ticket>,
}

impl Display for SortedLimitedTickets {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "SortedLimitedTickets {{")?;
        for (i, ticket) in self.heap.iter().enumerate() {
            writeln!(f, "  {}: {}", i, ticket)?;
        }
        write!(f, "}}")
    }
}

impl Default for SortedLimitedTickets {
    fn default() -> Self {
        Self::new()
    }
}

impl SortedLimitedTickets {
    pub fn new() -> Self {
        Self {
            heap: BinaryHeap::with_capacity(EPOCH_LENGTH),
        }
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

impl JamEncode for SortedLimitedTickets {
    fn size_hint(&self) -> usize {
        let tickets_vec: Vec<Ticket> = self.as_vec();
        tickets_vec.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        let tickets_vec: Vec<Ticket> = self.as_vec();
        tickets_vec.encode_to(dest)
    }
}

impl JamDecode for SortedLimitedTickets {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        // Decode as `Vec<Ticket>` type first
        let tickets_vec = Vec::<Ticket>::decode(input)?;

        // Create a new `SortedLimitedTickets`
        let mut sorted_tickets = Self::new();
        sorted_tickets.add_multiple(tickets_vec);

        Ok(sorted_tickets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Ticket, HASH32_EMPTY};

    fn create_ticket(i: u16) -> Ticket {
        let mut hash = HASH32_EMPTY;
        hash[0] = (i >> 8) as u8;
        hash[1] = i as u8;
        Ticket {
            id: hash,
            attempt: (i % 2) as u8,
        }
    }

    #[test]
    fn test_add() {
        let mut tickets = SortedLimitedTickets::new();
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
        let mut tickets = SortedLimitedTickets::new();
        for i in 0..EPOCH_LENGTH as u16 + 1 {
            let mut hash = HASH32_EMPTY;
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
                let mut hash = [0u8; 32];
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
            let mut hash = [0u8; 32];
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
        let mut tickets = SortedLimitedTickets::new();
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
        let mut tickets = SortedLimitedTickets::new();
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
