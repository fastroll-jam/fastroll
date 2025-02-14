use rjam_codec::{JamCodecError, JamEncode, JamOutput};
use rjam_common::Hash32;
use rjam_types::common::workloads::WorkExecutionOutput;

#[derive(Clone, JamEncode)]
pub struct AccumulateOperand {
    /// **`o`**: Work output (`refine_output` of `WorkItemResult`)
    pub work_output: WorkExecutionOutput,
    /// `l`: Work output payload hash (`payload_hash` of `WorkItemResult`)
    pub work_output_payload_hash: Hash32,
    /// `k`: Work package hash (`work_package_hash` or `AvailSpecs`)
    pub work_package_hash: Hash32,
    /// **`a`**: Authorization output (`authorization_output` of `WorReport`)
    pub authorization_output: Vec<u8>,
}
