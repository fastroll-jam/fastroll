use crate::common::ExportDataSegment;
use fr_codec::prelude::*;
use fr_common::{
    workloads::{ExtrinsicInfo, WorkExecutionResult, WorkPackage},
    AuthHash, Balance, ByteArray, CoreIndex, Hash32, SegmentRoot, ServiceId, TimeslotIndex,
    UnsignedGas, WorkPackageHash, TRANSFER_MEMO_SIZE,
};
use std::collections::HashMap;

#[derive(Clone, JamEncode)]
pub struct AccumulateOperand {
    /// `p`: Work package hash (`work_package_hash` of `AvailSpecs`)
    pub work_package_hash: WorkPackageHash,
    /// `e`: Work report segment root (`segment_root` of `AvailSpecs`)
    pub segment_root: SegmentRoot,
    /// `a`: Work report authorizer hash (`authorizer_hash` of `WorkReport`)
    pub authorizer_hash: AuthHash,
    /// `y`: Work item payload hash (`payload_hash` of `WorkDigest`)
    pub work_item_payload_hash: Hash32,
    /// `g`: Gas limit for accumulate (`accumulate_gas_limit` of `WorkDigest`)
    pub accumulate_gas_limit: UnsignedGas,
    /// **`l`**: Work item refine result (`refine_result` of `WorkDigest`)
    pub refine_result: WorkExecutionResult,
    /// **`t`**: Authorization trace (`auth_trace` of `WorkReport`)
    pub auth_trace: Vec<u8>,
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
    pub memo: ByteArray<TRANSFER_MEMO_SIZE>,
    /// `g`: Gas limit for the transfer
    pub gas_limit: UnsignedGas,
}

/// Accumulation input item, which is either accumulate operand or deferred transfer.
#[derive(Clone)]
pub enum AccumulateInput {
    Operand(AccumulateOperand),
    Transfer(DeferredTransfer),
}

impl JamEncode for AccumulateInput {
    fn size_hint(&self) -> usize {
        let data_size = match self {
            Self::Operand(operand) => operand.size_hint(),
            Self::Transfer(transfer) => transfer.size_hint(),
        };
        1 + data_size
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        match self {
            Self::Operand(operand) => {
                0u8.encode_to(dest)?;
                operand.encode_to(dest)
            }
            Self::Transfer(transfer) => {
                1u8.encode_to(dest)?;
                transfer.encode_to(dest)
            }
        }
    }
}

/// Accumulate input type, which includes a heterogeneous sequence of wrangled work-digests
/// associated with a certain service and deferred transfers targeted to that service.
/// Also, total deferred transfers amount is retained for efficiency.
#[derive(Clone, Default)]
pub struct AccumulateInputs {
    inputs: Vec<AccumulateInput>,
    deferred_transfers_amount: Balance,
}

impl AccumulateInputs {
    pub fn new(
        deferred_transfers: Vec<DeferredTransfer>,
        operands: Vec<AccumulateOperand>,
    ) -> Self {
        let deferred_transfers_amount = deferred_transfers.iter().map(|t| t.amount).sum();
        Self {
            inputs: deferred_transfers
                .into_iter()
                .map(AccumulateInput::Transfer)
                .chain(operands.into_iter().map(AccumulateInput::Operand))
                .collect::<Vec<_>>(),
            deferred_transfers_amount,
        }
    }

    pub fn inputs(&self) -> &Vec<AccumulateInput> {
        &self.inputs
    }

    pub fn deferred_transfers_amount(&self) -> Balance {
        self.deferred_transfers_amount
    }
}

/// Accumulate entry-point function arguments
///
/// Note: The partial state (**`u`**) is implicitly loaded when accessing the global state
/// within host function execution contexts. The timeslot index (`t`) is directly fetched
/// from the state manager.
#[derive(Clone, Default)]
pub struct AccumulateInvokeArgs {
    /// `t`: Current timeslot index.
    pub curr_timeslot_index: TimeslotIndex,
    /// `s`: The id of the service account to run the accumulation process.
    pub accumulate_host: ServiceId,
    /// `g`: The maximum amount of gas allowed for the accumulation process.
    pub gas_limit: UnsignedGas,
    /// **`i`**: Accumulation inputs sequence, comprised of operands or deferred transfers.
    pub inputs: AccumulateInputs,
}

/// Is-authorized entry-point function arguments
#[derive(Clone)]
pub struct IsAuthorizedInvokeArgs {
    /// **`p`**: Work package
    pub package: WorkPackage,
    /// `c`: Core index to process the work package
    pub core_index: CoreIndex,
}

/// Refine entry-point function arguments
#[derive(Clone, Default)]
pub struct RefineInvokeArgs {
    /// `i`: Index of the work item to be refined
    pub item_idx: usize,
    /// `p`: Work package that contains the work item to be refined
    pub package: WorkPackage,
    /// **`r`**: Authorization trace blob
    pub auth_trace: Vec<u8>,
    /// **`ī`**: Fixed-length data segments imported from the import DA
    pub import_segments: Vec<Vec<ExportDataSegment>>,
    /// `ς`: Initial offset index of the export segments array
    pub export_segments_offset: usize,
    /// A mapping form `ExtrinsicInfo` to its corresponding extrinsic data blob.
    /// This is expected to be known by guarantors.
    pub extrinsic_data_map: HashMap<ExtrinsicInfo, Vec<u8>>,
}
