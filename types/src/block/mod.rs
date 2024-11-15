pub mod header;

use crate::{block::header::BlockHeader, extrinsics::Extrinsics};
use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};

#[derive(Debug, JamEncode, JamDecode)]
pub struct Block {
    pub header: BlockHeader,
    pub extrinsics: Extrinsics,
}
