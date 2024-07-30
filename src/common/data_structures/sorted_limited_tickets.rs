use crate::{
    codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput},
    common::{Ticket, EPOCH_LENGTH},
};
use std::{cmp::Reverse, collections::BinaryHeap};

pub struct SortedLimitedTickets {
    heap: BinaryHeap<Reverse<Ticket>>,
}

impl SortedLimitedTickets {
    pub fn new() -> Self {
        Self {
            heap: BinaryHeap::with_capacity(EPOCH_LENGTH),
        }
    }

    pub fn add(&mut self, ticket: Ticket) {
        if self.heap.len() < EPOCH_LENGTH {
            self.heap.push(Reverse(ticket));
        } else if ticket < self.heap.peek().unwrap().0 {
            // To keep EPOCH_LENGTH of tickets in ascending orders, compare with the Max heap peak
            // before pushing a new Ticket entry
            self.heap.pop();
            self.heap.push(Reverse(ticket));
        }
    }

    pub fn add_multiple(&mut self, tickets: Vec<Ticket>) {
        for ticket in tickets {
            self.add(ticket);
        }
    }

    pub fn into_vec(self) -> Vec<Ticket> {
        let mut tickets: Vec<_> = self
            .heap
            .into_iter()
            .map(|Reverse(ticket)| ticket)
            .collect();
        tickets.sort_unstable(); // Return in a sorted form
        tickets
    }

    pub fn as_vec(&self) -> Vec<Ticket> {
        let mut tickets: Vec<_> = self
            .heap
            .iter()
            .map(|Reverse(ticket)| ticket.clone())
            .collect();
        tickets.sort_unstable(); // Return in a sorted form
        tickets
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
        let mut sorted_tickets = SortedLimitedTickets::new();
        sorted_tickets.add_multiple(tickets_vec);

        Ok(sorted_tickets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{Ticket, HASH32_DEFAULT};

    fn create_ticket(i: u16) -> Ticket {
        let mut hash = HASH32_DEFAULT;
        hash[0] = (i >> 8) as u8;
        hash[1] = i as u8;
        (hash, (i % 2) as u8)
    }

    #[test]
    fn test_add() {
        let mut tickets = SortedLimitedTickets::new();
        for i in 0..200 {
            tickets.add(create_ticket(i));
        }
        assert_eq!(tickets.heap.len(), 200);
        assert_eq!(
            tickets.as_vec(),
            (0..200).map(create_ticket).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_add_over_capacity() {
        let mut tickets = SortedLimitedTickets::new();
        for i in 0..EPOCH_LENGTH as u16 + 1 {
            let mut hash = HASH32_DEFAULT;
            // Constructing tickets with unique hash values, with first two bytes
            hash[0] = (i >> 8) as u8;
            hash[1] = (i & 0xFF) as u8;
            tickets.add((hash, (i % 2) as u8));
        }

        assert_eq!(tickets.heap.len(), EPOCH_LENGTH); // The MaxHeap contains exactly EPOCH_LENGTH tickets only

        let expected: Vec<_> = (0..EPOCH_LENGTH as u16)
            .map(|i| {
                let mut hash = [0u8; 32];
                hash[0] = (i >> 8) as u8;
                hash[1] = (i & 0xFF) as u8;
                (hash, (i % 2) as u8)
            })
            .collect();

        assert_eq!(tickets.as_vec(), expected);

        // Large ticket should not be included in the MaxHeap
        let large_ticket = {
            let mut hash = [0u8; 32];
            hash[0] = (EPOCH_LENGTH as u16 >> 8) as u8;
            hash[1] = (EPOCH_LENGTH as u16 & 0xFF) as u8;
            (hash, (EPOCH_LENGTH as u16 % 2) as u8)
        };
        assert!(!tickets.as_vec().contains(&large_ticket));
    }

    #[test]
    fn test_add_multiple() {
        let mut tickets = SortedLimitedTickets::new();
        let new_tickets: Vec<Ticket> = (0..1000).map(create_ticket).collect();
        tickets.add_multiple(new_tickets);
        assert_eq!(tickets.heap.len(), EPOCH_LENGTH);
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
