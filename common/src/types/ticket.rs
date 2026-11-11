use crate::TicketId;
use fr_codec::prelude::*;
use std::{
    cmp::Ordering,
    fmt::{Display, Formatter},
};

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct Ticket {
    /// `y`: The ticket identifier, which is the `Y` output hash of the Ring VRF proof from `TicketsXtEntry`.
    pub id: TicketId,
    /// `e`: The ticket entry index, either 0 or 1.
    pub attempt: u8,
}

impl JamEncode for Ticket {
    fn size_hint(&self) -> usize {
        self.id.size_hint() + 1
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.id.encode_to(dest)?;
        self.attempt.encode_to_fixed(dest, 1)?;
        Ok(())
    }
}

impl JamDecode for Ticket {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            id: TicketId::decode(input)?,
            attempt: u8::decode_fixed(input, 1)?,
        })
    }
}

impl Display for Ticket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{ \"attempt\": \"{}\", \"id\": \"{}\" }}",
            self.attempt,
            self.id.encode_hex(),
        )
    }
}

impl PartialOrd for Ticket {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Ticket {
    fn cmp(&self, other: &Self) -> Ordering {
        self.id.cmp(&other.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_ticket_attempt_encodes_in_one_octet() -> Result<(), Box<dyn Error>> {
        // A compact encoding takes two octets for an attempt of 128 or more.
        let ticket = Ticket {
            id: TicketId::default(),
            attempt: 200,
        };
        let encoded = ticket.encode()?;
        assert_eq!(encoded.len(), 33);
        assert_eq!(encoded[32], 200);
        assert_eq!(Ticket::decode(&mut encoded.as_slice())?, ticket);
        Ok(())
    }
}
