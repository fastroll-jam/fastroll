use rjam_codec::{JamCodecError, JamEncode, JamOutput};
use rjam_common::{Balance, ServiceId, UnsignedGas, TRANSFER_MEMO_SIZE};

#[derive(Clone, Copy, JamEncode)]
pub struct DeferredTransfer {
    pub from: ServiceId,                // s
    pub to: ServiceId,                  // d
    pub amount: Balance,                // a
    pub memo: [u8; TRANSFER_MEMO_SIZE], // m
    pub gas_limit: UnsignedGas,         // g
}
