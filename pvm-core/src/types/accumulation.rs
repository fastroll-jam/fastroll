use rjam_codec::{JamCodecError, JamEncode, JamOutput};
use rjam_common::{Hash32, Octets, WorkExecutionOutput};

#[derive(JamEncode)]
pub struct AccumulateOperand {
    pub work_output: WorkExecutionOutput,
    pub work_output_payload_hash: Hash32,
    pub work_package_hash: Hash32,
    pub authorization_output: Octets,
}
