use crate::types::common::ExportDataSegment;
use rjam_types::common::workloads::WorkPackage;

// TODO: Find a better location
/// Refine entry-point function arguments
#[derive(Clone, Default)]
pub struct RefineInvokeArgs {
    /// `i`: Index of the work item to be refined
    pub item_idx: usize,
    /// `p`: Work package that contains the work item to be refined
    pub package: WorkPackage,
    /// **`o`**: Authorization output blob
    pub auth_output: Vec<u8>,
    /// **`ī`**: Fixed-length data segments imported from the import DA
    pub import_segments: Vec<ExportDataSegment>,
    /// `ς`: Initial offset index of the export segments array
    pub export_segments_offset: usize,
}
