use crate::{
    impl_simple_state_component,
    state_utils::{SimpleStateComponent, StateComponent, StateEntryType, StateKeyConstant},
    types::{work_report::WorkReport, Timeslot},
};
use fr_block::types::extrinsics::guarantees::GuaranteesXtEntry;
use fr_codec::prelude::*;
use fr_common::{CoreIndex, WorkReportHash, CORE_COUNT, PENDING_REPORT_TIMEOUT};
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

/// Availability assignments, one optional work report guarantee per core, pending availability by assurers.
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
                    >= report.registered_timeslot.slot() as usize + PENDING_REPORT_TIMEOUT
                {
                    timed_out_core_indices.push(i as CoreIndex);
                }
            }
        }
        Ok(timed_out_core_indices)
    }

    /// Checks if any entry holds `Some(PendingReport)` with the given hash.
    /// If found, the entry is replaced with `None`.
    pub fn remove_by_hash(
        &mut self,
        target_hash: &WorkReportHash,
    ) -> Result<bool, PendingReportsError> {
        for report_entry in self.0.iter_mut() {
            if let Some(report) = report_entry {
                if &hash::<Blake2b256>(&report.work_report().encode()?)? == target_hash {
                    *report_entry = None;
                    return Ok(true); // Hash found and entry turned into None
                }
            }
        }
        Ok(false) // Hash not found
    }

    /// Removes every pending report, e.g. when the active validator set size changes.
    pub fn clear(&mut self) {
        for entry in self.0.iter_mut() {
            *entry = None;
        }
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

/// Availability assignment of a core, holding the work report guarantee until the report is available.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PendingReport {
    /// `g`: Guarantee of the work report, with the guarantee timeslot and the guarantor credentials.
    pub guarantee: GuaranteesXtEntry,
    /// `t`: Timeslot when the guarantee was introduced on-chain, which the availability timeout counts from.
    pub registered_timeslot: Timeslot,
}

impl PendingReport {
    pub fn work_report(&self) -> &WorkReport {
        &self.guarantee.work_report
    }
}

impl Display for PendingReport {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PendingReport: {{ wr: {}, guarantee_slot: {}, slot: {:?} }}",
            self.guarantee.work_report, self.guarantee.timeslot_index, self.registered_timeslot
        )
    }
}

impl JamEncode for PendingReport {
    fn size_hint(&self) -> usize {
        self.guarantee.size_hint() + 4
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.guarantee.encode_to(dest)?;
        self.registered_timeslot.encode_to_fixed(dest, 4)?;
        Ok(())
    }
}

impl JamDecode for PendingReport {
    fn decode<T: JamInput>(input: &mut T) -> Result<Self, JamCodecError> {
        Ok(Self {
            guarantee: GuaranteesXtEntry::decode(input)?,
            registered_timeslot: Timeslot::decode_fixed(input, 4)?,
        })
    }
}
