use crate::{
    codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput},
    common::WorkReport,
    state::global_state::Timeslot,
};

pub(crate) struct PendingReport {
    work_report: WorkReport,
    timeslot: u32,
}

impl JamEncode for PendingReport {
    fn size_hint(&self) -> usize {
        self.work_report.size_hint() + self.timeslot.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.work_report.encode_to(dest)?;
        self.timeslot.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for PendingReport {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        Ok(Self {
            work_report: WorkReport::decode(input)?,
            timeslot: Timeslot::decode(input)?,
        })
    }
}
