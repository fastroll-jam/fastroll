use crate::Hash32;
use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use std::{
    cmp::Ordering,
    fmt::{Display, Formatter},
};

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, JamEncode, JamDecode)]
pub struct Ticket {
    /// **`y`**: The ticket identifier, which is the `Y` output hash of the Ring VRF proof from `TicketsXtEntry`.
    pub id: Hash32,
    /// `r`: The ticket entry index, either 0 or 1.
    pub attempt: u8,
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
