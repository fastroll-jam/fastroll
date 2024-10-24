use rjam_codec::{JamCodecError, JamEncode, JamOutput};
use rjam_common::{Address, Balance, UnsignedGas, TRANSFER_MEMO_SIZE};

#[derive(Clone, Copy, JamEncode)]
pub struct DeferredTransfer {
    pub from: Address,                  // s
    pub to: Address,                    // d
    pub amount: Balance,                // a
    pub memo: [u8; TRANSFER_MEMO_SIZE], // m
    pub gas_limit: UnsignedGas,         // g
}
