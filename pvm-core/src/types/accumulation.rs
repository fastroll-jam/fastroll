use rjam_codec::{JamCodecError, JamEncode, JamOutput};
use rjam_common::{Hash32, Octets, WorkExecutionOutput};

#[derive(JamEncode)]
pub struct AccumulateOperand {
    work_output: WorkExecutionOutput,
    work_output_payload_hash: Hash32,
    work_package_hash: Hash32,
    authorization_output: Octets,
}
