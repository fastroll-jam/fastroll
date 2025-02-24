use rjam_codec::{JamCodecError, JamEncode, JamOutput};
use rjam_common::{Balance, ServiceId, UnsignedGas, TRANSFER_MEMO_SIZE};

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
