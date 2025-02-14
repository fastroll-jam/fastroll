use crate::types::{accumulation::AccumulateOperand, common::ExportDataSegment};
use rjam_common::{Address, UnsignedGas};
use rjam_types::common::workloads::{ExtrinsicInfo, WorkPackage};
use std::collections::HashMap;

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
    pub import_segments: Vec<Vec<ExportDataSegment>>,
    /// `ς`: Initial offset index of the export segments array
    pub export_segments_offset: usize,
    /// A mapping form `ExtrinsicInfo` to its corresponding extrinsic data blob.
    /// This is expected to be known by guarantors.
    pub extrinsic_data_map: HashMap<ExtrinsicInfo, Vec<u8>>,
}

/// Accumulate entry-point function arguments
///
/// Note: The partial state (**`u`**) is implicitly loaded when accessing the global state
/// within host function execution contexts. The timeslot index (`t`) is directly fetched
/// from the state manager.
pub struct AccumulateInvokeArgs {
    /// `s`: The address of the service account to run the accumulation process
    pub accumulate_host: Address,
    /// `g`: The maximum amount of gas allowed for the accumulation process
    pub gas_limit: UnsignedGas,
    /// **`o`**: A vector of `AccumulateOperand`s, which are the outputs from the refinement process to be accumulated
    pub operands: Vec<AccumulateOperand>,
}
