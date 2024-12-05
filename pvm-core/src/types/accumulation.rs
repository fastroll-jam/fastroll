use rjam_codec::{JamCodecError, JamEncode, JamOutput};
use rjam_common::Hash32;
use rjam_types::common::workloads::WorkExecutionOutput;

#[derive(JamEncode)]
pub struct AccumulateOperand {
    pub work_output: WorkExecutionOutput, // o
    pub work_output_payload_hash: Hash32, // l
    pub work_package_hash: Hash32,        // k
    pub authorization_output: Vec<u8>,    // a
}
