use crate::{block::header::BlockHeader, extrinsics::Extrinsics};
use parity_scale_codec::{Decode, Encode, Error, Input, Output};

mod header;

pub struct Block {
    header: BlockHeader,
    extrinsics: Extrinsics,
}

impl Encode for Block {
    fn size_hint(&self) -> usize {
        self.header.size_hint() + self.extrinsics.size_hint()
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        self.header.encode_to(dest);
        self.extrinsics.encode_to(dest);
    }
}

impl Decode for Block {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let header = BlockHeader::decode(input)?;
        let extrinsics = Extrinsics::decode(input)?;

        // TODO: additional validation on Block structure, etc.

        Ok(Self { header, extrinsics })
    }
}
