use crate::state::timeslot::Timeslot;
use jam_codec::{
    impl_jam_codec_for_newtype, JamCodecError, JamDecode, JamEncode, JamInput, JamOutput,
};
use jam_common::{WorkReport, CORE_COUNT};

pub struct PendingReports(pub [Option<PendingReport>; CORE_COUNT]);
impl_jam_codec_for_newtype!(PendingReports, [Option<PendingReport>; CORE_COUNT]);

#[derive(Clone)]
pub struct PendingReport {
    work_report: WorkReport,
    timeslot: Timeslot,
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
            timeslot: JamDecode::decode(input)?,
        })
    }
}
