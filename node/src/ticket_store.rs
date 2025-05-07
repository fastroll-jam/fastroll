use fr_common::ticket::Ticket;
use std::collections::HashMap;

/// A collection of tickets submitted by the node, indexed by epoch number.
pub struct TicketStore {
    pub inner: HashMap<u32, Ticket>,
}
