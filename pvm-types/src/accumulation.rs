use jam_codec::{JamCodecError, JamEncode, JamOutput};
use jam_common::{AccountAddress, Hash32, Octets, RefinementOutput, TokenBalance, UnsignedGas};

const TRANSFER_MEMO_SIZE: usize = 128;

pub struct AccumulationOperand {
    work_output: RefinementOutput,
    work_output_payload_hash: Hash32,
    work_package_hash: Hash32,
    authorization_output: Octets,
}

impl JamEncode for AccumulationOperand {
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

#[derive(Clone, Copy)]
pub struct DeferredTransfer {
    from: AccountAddress,           // s
    to: AccountAddress,             // d
    amount: TokenBalance,           // a
    memo: [u8; TRANSFER_MEMO_SIZE], // m
    gas_limit: UnsignedGas,         // g
}
