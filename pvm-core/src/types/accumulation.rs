use rjam_codec::{JamCodecError, JamEncode, JamOutput};
use rjam_common::{Hash32, Octets, WorkExecutionOutput};

pub struct AccumulateOperand {
    work_output: WorkExecutionOutput,
    work_output_payload_hash: Hash32,
    work_package_hash: Hash32,
    authorization_output: Octets,
}

impl JamEncode for AccumulateOperand {
    fn size_hint(&self) -> usize {
        self.work_output.size_hint()
            + self.work_output_payload_hash.size_hint()
            + self.work_package_hash.size_hint()
            + self.authorization_output.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.work_output.encode_to(dest)?;
        self.work_output_payload_hash.encode_to(dest)?;
        self.work_package_hash.encode_to(dest)?;
        self.authorization_output.encode_to(dest)?;
        Ok(())
    }
}
