use crate::{
    codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput},
    common::{Ed25519Signature, WorkReport},
};

#[derive(Clone, Ord, PartialOrd, PartialEq, Eq)]
pub(crate) struct GuaranteeExtrinsicEntry {
    work_report: WorkReport,                  // w
    timeslot: u32,                            // t; N_T
    credential: Vec<(u16, Ed25519Signature)>, // a; (WorkReport, N_T, [(N_V, Ed25519Signature)]_{2:3}; length up to CORE_COUNT
}

impl JamEncode for GuaranteeExtrinsicEntry {
    fn size_hint(&self) -> usize {
        self.timeslot.size_hint() + self.work_report.size_hint() + self.credential.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.timeslot.encode_to(dest)?; // TODO: check what `c` of `E_G` means (GP v0.3.0)
        self.work_report.encode_to(dest)?;
        self.credential.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for GuaranteeExtrinsicEntry {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        Ok(Self {
            work_report: WorkReport::decode(input)?,
            timeslot: u32::decode(input)?,
            credential: Vec::decode(input)?,
        })
    }
}
