use crate::{
    common::workloads::{WorkReport, WorkReportError},
    state::timeslot::Timeslot,
};
use rjam_codec::{
    impl_jam_codec_for_newtype, JamCodecError, JamDecode, JamEncode, JamInput, JamOutput,
};
use rjam_common::{CoreIndex, Hash32, CORE_COUNT};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PendingReportsError {
    #[error("WorkReport error: {0}")]
    WorkReportError(#[from] WorkReportError),
    #[error("Invalid Core Index: {core_index}")]
    InvalidCoreIndex { core_index: CoreIndex },
}

#[derive(Clone)]
pub struct PendingReports(pub Box<[Option<PendingReport>; CORE_COUNT]>);
impl_jam_codec_for_newtype!(PendingReports, Box<[Option<PendingReport>; CORE_COUNT]>);

impl PendingReports {
    pub fn get_by_core_index(&self, core_index: CoreIndex) -> &Option<PendingReport> {
        &self.0[core_index as usize]
    }

    /// Checks if any entry holds `Some(PendingReport)` with the given hash.
    /// If found, the entry is replaced with `None`.
    pub fn remove_by_hash(&mut self, target_hash: &Hash32) -> Result<bool, PendingReportsError> {
        for report_entry in self.0.iter_mut() {
            if let Some(report) = report_entry {
                if &report.work_report.hash()? == target_hash {
                    *report_entry = None;
                    return Ok(true); // Hash found and entry turned into None
                }
            }
        }
        Ok(false) // Hash not found
    }

    pub fn remove_by_core_index(
        &mut self,
        core_index: CoreIndex,
    ) -> Result<(), PendingReportsError> {
        if (core_index as usize) < CORE_COUNT {
            self.0[core_index as usize] = None;
            Ok(())
        } else {
            Err(PendingReportsError::InvalidCoreIndex { core_index })
        }
    }
}

#[derive(Clone, JamEncode, JamDecode)]
pub struct PendingReport {
    pub work_report: WorkReport,
    pub timeslot: Timeslot,
}
