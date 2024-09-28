use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::{Ed25519Signature, WorkReport};

// TODO: check what `c` of `E_G` means (GP v0.3.0)
#[derive(Debug, Clone, Ord, PartialOrd, PartialEq, Eq, JamEncode, JamDecode)]
pub struct GuaranteeExtrinsicEntry {
    work_report: WorkReport,                  // w
    timeslot: u32,                            // t; N_T
    credential: Vec<(u16, Ed25519Signature)>, // a; (WorkReport, N_T, [(N_V, Ed25519Signature)]_{2:3}; length up to CORE_COUNT
}
