use crate::{
    common::workloads::{WorkReport, WorkReportError},
    impl_simple_state_component,
    state::timeslot::Timeslot,
    state_utils::{SimpleStateComponent, StateComponent, StateEntryType, StateKeyConstant},
};
use rjam_codec::{
    impl_jam_codec_for_newtype, JamCodecError, JamDecode, JamEncode, JamInput, JamOutput,
};
use rjam_common::{CoreIndex, Hash32, CORE_COUNT, PENDING_REPORT_TIMEOUT};
use std::{
    array::from_fn,
    fmt::{Display, Formatter},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PendingReportsError {
    #[error("WorkReport error: {0}")]
    WorkReportError(#[from] WorkReportError),
    #[error("Invalid Core Index: {0}")]
    InvalidCoreIndex(CoreIndex),
}

#[derive(Clone, Debug, PartialEq)]
pub struct PendingReports(pub Box<[Option<PendingReport>; CORE_COUNT]>);
impl_jam_codec_for_newtype!(PendingReports, Box<[Option<PendingReport>; CORE_COUNT]>);
impl_simple_state_component!(PendingReports, PendingReports);

impl Default for PendingReports {
    fn default() -> Self {
        let arr = from_fn(|_| None);
        Self(Box::new(arr))
    }
}

impl Display for PendingReports {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "PendingReports: {{")?;
        for (core_idx, reports) in self.0.iter().enumerate() {
            writeln!(f, "  core #{}:", core_idx)?;
            match reports {
                Some(report) => {
                    writeln!(f, "    {}", report)?;
                }
                None => {
                    writeln!(f, "    None")?;
                }
            }
        }
        write!(f, "}}")
    }
}

impl PendingReports {
    pub fn get_by_core_index(
        &self,
        core_index: CoreIndex,
    ) -> Result<&Option<PendingReport>, PendingReportsError> {
        if core_index as usize >= CORE_COUNT {
            return Err(PendingReportsError::InvalidCoreIndex(core_index));
        }
        Ok(&self.0[core_index as usize])
    }

    pub fn get_timed_out_core_indices(
        &self,
        current_timeslot: &Timeslot,
    ) -> Result<Vec<CoreIndex>, PendingReportsError> {
        let mut timed_out_core_indices = vec![];

        for (i, maybe_report) in self.0.iter().enumerate() {
            if let Some(report) = maybe_report {
                if current_timeslot.slot() as usize
                    >= report.reported_timeslot.slot() as usize + PENDING_REPORT_TIMEOUT
                {
                    timed_out_core_indices.push(i as CoreIndex);
                }
            }
        }

        Ok(timed_out_core_indices)
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
            Err(PendingReportsError::InvalidCoreIndex(core_index))
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, JamEncode, JamDecode)]
pub struct PendingReport {
    pub work_report: WorkReport,
    pub reported_timeslot: Timeslot,
}

impl Display for PendingReport {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PendingReport: {{ wr: {}, slot: {:?} }}",
            self.work_report, self.reported_timeslot
        )
    }
}
