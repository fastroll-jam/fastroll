pub mod extrinsics;
pub mod header;
pub mod state;
pub mod trie;

use crate::extrinsics::Extrinsics;
use header::BlockHeader;
use jam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};

pub struct Block {
    header: BlockHeader,
    extrinsics: Extrinsics,
}

impl JamEncode for Block {
    fn size_hint(&self) -> usize {
        self.header.size_hint() + self.extrinsics.size_hint()
    }

    fn encode_to<W: JamOutput>(&self, dest: &mut W) -> Result<(), JamCodecError> {
        self.header.encode_to(dest)?;
        self.extrinsics.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for Block {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        // TODO: additional validation on Block structure, etc.
        Ok(Self {
            header: BlockHeader::decode(input)?,
            extrinsics: Extrinsics::decode(input)?,
        })
    }
}
