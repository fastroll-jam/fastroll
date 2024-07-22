use crate::{
    codec::{
        decode_length_discriminated_field, encode_length_discriminated_field,
        size_hint_length_discriminated_field,
    },
    common::{Ed25519Signature, WorkReport},
};
use parity_scale_codec::{Decode, Encode, Error, Input, Output};

pub(crate) struct GuaranteeExtrinsicEntry {
    work_report: WorkReport,                  // w
    timeslot: u32,                            // t; N_T
    credential: Vec<(u16, Ed25519Signature)>, // a; (WorkReport, N_T, [(N_V, Ed25519Signature)]_{2:3}; length up to CORE_COUNT
}

impl Encode for GuaranteeExtrinsicEntry {
    fn size_hint(&self) -> usize {
        self.timeslot.size_hint()
            + self.work_report.size_hint()
            + size_hint_length_discriminated_field(&self.credential)
    }

    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        self.timeslot.encode_to(dest); // TODO: check what `c` of `E_G` means (GP v0.3.0)
        self.work_report.encode_to(dest);
        encode_length_discriminated_field(&self.credential, dest);
    }
}

impl Decode for GuaranteeExtrinsicEntry {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let timeslot = u32::decode(input)?;
        let work_report = WorkReport::decode(input)?;
        let credential = decode_length_discriminated_field(input)?;

        Ok(Self {
            work_report,
            timeslot,
            credential,
        })
    }
}
