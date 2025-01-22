pub mod header;

use crate::{block::header::BlockHeader, extrinsics::Extrinsics};
use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};

#[derive(Debug, PartialEq, Eq, JamEncode, JamDecode)]
pub struct Block {
    pub header: BlockHeader,
    pub extrinsics: Extrinsics,
}
