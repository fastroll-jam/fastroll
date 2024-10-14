use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::{Ed25519Signature, WorkReport};

/// Extrinsic entry containing a work report guaranteed by specific validators called `Guarantors`.
///
/// Each block, three `Guarantors` are assigned per core to verify accuracy of the work and this
/// extrinsic entry carries guaranteeing signature from two or three of the `Guarantors`.
#[derive(Debug, Clone, PartialEq, Eq, JamEncode, JamDecode)]
pub struct GuaranteesExtrinsicEntry {
    work_report: WorkReport,                  // w
    timeslot: u32,                            // t
    credential: Vec<(u16, Ed25519Signature)>, // a; length either 2 or 3
}
