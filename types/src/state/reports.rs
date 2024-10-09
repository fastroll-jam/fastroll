use crate::state::timeslot::Timeslot;
use rjam_codec::{
    impl_jam_codec_for_newtype, JamCodecError, JamDecode, JamEncode, JamInput, JamOutput,
};
use rjam_common::{WorkReport, CORE_COUNT};

#[derive(Clone)]
pub struct PendingReports(pub Box<[Option<PendingReport>; CORE_COUNT]>);
impl_jam_codec_for_newtype!(PendingReports, Box<[Option<PendingReport>; CORE_COUNT]>);

#[derive(Clone, JamEncode, JamDecode)]
pub struct PendingReport {
    work_report: WorkReport,
    timeslot: Timeslot,
}
