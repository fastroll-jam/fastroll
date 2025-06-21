use crate::{
    impl_simple_state_component,
    state_utils::{SimpleStateComponent, StateComponent, StateEntryType, StateKeyConstant},
    types::{work_report::WorkReport, Timeslot},
};
use fr_codec::prelude::*;
use fr_common::{CoreIndex, Hash32, CORE_COUNT, PENDING_REPORT_TIMEOUT};
use fr_crypto::{error::CryptoError, hash, Blake2b256};
use fr_limited_vec::FixedVec;
use std::fmt::{Display, Formatter};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PendingReportsError {
    #[error("Invalid Core Index: {0}")]
    InvalidCoreIndex(CoreIndex),
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("CryptoError: {0}")]
    CryptoError(#[from] CryptoError),
}

pub type CorePendingReportsEntries = FixedVec<Option<PendingReport>, CORE_COUNT>;

/// Work reports pending availability by assurers.
///
/// Represents `ρ` of the GP.
#[derive(Clone, Debug, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct PendingReports(pub CorePendingReportsEntries);
impl_simple_state_component!(PendingReports, PendingReports);

impl Display for PendingReports {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "PendingReports: {{")?;
        for (core_idx, reports) in self.0.iter().enumerate() {
            writeln!(f, "  core #{core_idx}:")?;
            match reports {
                Some(report) => {
                    writeln!(f, "    {report}")?;
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
                if hash::<Blake2b256>(&report.work_report.encode()?)? == *target_hash {
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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PendingReport {
    /// `w`: Work Report
    pub work_report: WorkReport,
    /// `t`: Timeslot when the work report was introduced on-chain (reported).
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

impl JamEncode for PendingReport {
    fn size_hint(&self) -> usize {
        self.work_report.size_hint() + 4
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.work_report.encode_to(dest)?;
        self.reported_timeslot.encode_to_fixed(dest, 4)?;
        Ok(())
    }
}

impl JamDecode for PendingReport {
    fn decode<T: JamInput>(input: &mut T) -> Result<Self, JamCodecError> {
        Ok(Self {
            work_report: WorkReport::decode(input)?,
            reported_timeslot: Timeslot::decode_fixed(input, 4)?,
        })
    }
}
