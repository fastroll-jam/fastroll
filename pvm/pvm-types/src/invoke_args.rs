use crate::common::ExportDataSegment;
use rjam_codec::{JamCodecError, JamEncode, JamOutput};
use rjam_common::{
    workloads::{ExtrinsicInfo, WorkExecutionOutput, WorkPackage},
    Balance, Hash32, ServiceId, UnsignedGas, TRANSFER_MEMO_SIZE,
};
use std::collections::HashMap;

/// Accumulate entry-point function arguments
///
/// Note: The partial state (**`u`**) is implicitly loaded when accessing the global state
/// within host function execution contexts. The timeslot index (`t`) is directly fetched
/// from the state manager.
pub struct AccumulateInvokeArgs {
    /// `s`: The id of the service account to run the accumulation process
    pub accumulate_host: ServiceId,
    /// `g`: The maximum amount of gas allowed for the accumulation process
    pub gas_limit: UnsignedGas,
    /// **`o`**: A vector of `AccumulateOperand`s, which are the outputs from the refinement process to be accumulated
    pub operands: Vec<AccumulateOperand>,
}

/// Accumulate entry-point function arguments
///
/// Note: The timeslot index (`t`) is directly fetched from the state manager.
pub struct OnTransferInvokeArgs {
    /// `s`: Destination (recipient) service account index of the transfer
    pub destination: ServiceId,
    /// **`t`**: A vector of `DeferredTransfer`s
    pub transfers: Vec<DeferredTransfer>,
}

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

#[derive(Clone, JamEncode)]
pub struct AccumulateOperand {
    /// `h`: Work package hash (`work_package_hash` of `AvailSpecs`)
    pub work_package_hash: Hash32,
    /// `e`: Work report segment root (`segment_root` of `AvailSpecs`)
    pub segment_root: Hash32,
    /// `a`: Work report authorizer hash (`authorizer_hash` of `WorkReport`)
    pub authorizer_hash: Hash32,
    /// **`o`**: Authorization output (`authorization_output` of `WorReport`)
    pub authorization_output: Vec<u8>,
    /// `y`: Work item payload hash (`payload_hash` of `WorkItemResult`)
    pub work_item_payload_hash: Hash32,
    /// **`d`**: Work output (`refine_output` of `WorkItemResult`)
    pub work_output: WorkExecutionOutput,
}

#[derive(Clone, JamEncode)]
pub struct DeferredTransfer {
    /// `s`: Sender service id
    pub from: ServiceId,
    /// `d`: Receiver service id
    pub to: ServiceId,
    /// `a`: Token transfer amount
    pub amount: Balance,
    /// `m`: A simple memo transferred alongside the balance
    pub memo: [u8; TRANSFER_MEMO_SIZE],
    /// `g`: Gas limit for the transfer
    pub gas_limit: UnsignedGas,
}
