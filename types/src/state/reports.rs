use crate::state::timeslot::Timeslot;
use rjam_codec::{
    impl_jam_codec_for_newtype, JamCodecError, JamDecode, JamEncode, JamInput, JamOutput,
};
use rjam_common::{WorkReport, CORE_COUNT};

pub struct PendingReports(pub [Option<PendingReport>; CORE_COUNT]);
impl_jam_codec_for_newtype!(PendingReports, [Option<PendingReport>; CORE_COUNT]);

#[derive(Clone, JamEncode, JamDecode)]
pub struct PendingReport {
    work_report: WorkReport,
    timeslot: Timeslot,
}
