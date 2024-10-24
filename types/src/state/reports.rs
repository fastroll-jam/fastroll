use crate::{common::workloads::WorkReport, state::timeslot::Timeslot};
use rjam_codec::{
    impl_jam_codec_for_newtype, JamCodecError, JamDecode, JamEncode, JamInput, JamOutput,
};
use rjam_common::{Hash32, CORE_COUNT};
use rjam_crypto::utils::{hash, Blake2b256};

#[derive(Clone)]
pub struct PendingReports(pub Box<[Option<PendingReport>; CORE_COUNT]>);
impl_jam_codec_for_newtype!(PendingReports, Box<[Option<PendingReport>; CORE_COUNT]>);

impl PendingReports {
    /// Checks if any entry holds `Some(PendingReport)` with the given hash.
    /// If found, the entry is replaced with `None`.
    /// TODO: Move the hashing process to outside of this function (e.g. impl as WorkReport method)
    pub fn remove_by_hash(&mut self, target_hash: &Hash32) -> bool {
        for report_entry in self.0.iter_mut() {
            if let Some(report) = report_entry {
                let mut buf = vec![];
                report.encode_to(&mut buf).unwrap();
                let report_hash = hash::<Blake2b256>(&buf[..]).unwrap();

                if &report_hash == target_hash {
                    *report_entry = None;
                    return true; // Hash found and entry turned into None
                }
            }
        }
        false // Hash not found
    }
}

#[derive(Clone, JamEncode, JamDecode)]
pub struct PendingReport {
    work_report: WorkReport,
    timeslot: Timeslot,
}
