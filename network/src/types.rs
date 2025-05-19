use fr_block::types::block::BlockHeader;
use fr_codec::prelude::*;
use fr_common::Hash32;
use std::fmt::{Display, Formatter};

pub const CHUNK_SIZE: usize = 1024;

#[derive(Clone, Debug, JamDecode)]
pub struct BlockAnnouncement {
    pub header: BlockHeader,
    pub header_hash: Hash32,
    pub timeslot: u32,
}

impl Display for BlockAnnouncement {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Header: {}", self.header)?;
        writeln!(f, "Header hash: {}", self.header_hash)?;
        writeln!(f, "timeslot: {}", self.timeslot)?;
        Ok(())
    }
}
