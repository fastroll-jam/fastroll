pub mod header;

use header::BlockHeader;
use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_extrinsics::Extrinsics;

#[derive(Debug, JamEncode, JamDecode)]
pub struct Block {
    header: BlockHeader,
    extrinsics: Extrinsics,
}
