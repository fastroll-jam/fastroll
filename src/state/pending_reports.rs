use crate::{
    codec::{encode_optional_field, size_hint_optional_field},
    common::{WorkReport, CORE_COUNT},
};
use parity_scale_codec::{Encode, Output};

pub(crate) struct PendingReports {
    entries: [Option<PendingReport>; CORE_COUNT],
}

impl Encode for PendingReports {
    fn size_hint(&self) -> usize {
        self.entries.iter().map(size_hint_optional_field).sum()
    }

    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        for entry in &self.entries {
            encode_optional_field(entry, dest);
        }
    }
}

pub(crate) struct PendingReport {
    work_report: WorkReport,
    timeslot: u32,
}

impl Encode for PendingReport {
    fn size_hint(&self) -> usize {
        self.work_report.size_hint() + self.timeslot.size_hint()
    }

    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        self.work_report.encode_to(dest);
        self.timeslot.encode_to(dest);
    }
}
