use crate::{
    impl_simple_state_component,
    state_utils::{SimpleStateComponent, StateComponent, StateEntryType, StateKeyConstant},
};
use rjam_clock::Clock;
use rjam_codec::{
    JamCodecError, JamDecode, JamDecodeFixed, JamEncode, JamEncodeFixed, JamInput, JamOutput,
    SizeUnit,
};
use rjam_common::{COMMON_ERA_TIMESTAMP, EPOCH_LENGTH, SLOT_DURATION};

/// Time timeslot index.
///
/// Represents `τ` of the GP.
#[derive(Clone, Copy, Debug, Default, Ord, PartialOrd, PartialEq, Eq, JamEncode, JamDecode)]
pub struct Timeslot(pub u32);
impl_simple_state_component!(Timeslot, Timeslot);

impl JamEncodeFixed for Timeslot {
    const SIZE_UNIT: SizeUnit = SizeUnit::Bytes;

    fn encode_to_fixed<T: JamOutput>(
        &self,
        dest: &mut T,
        size: usize,
    ) -> Result<(), JamCodecError> {
        self.0.encode_to_fixed(dest, size)
    }
}

impl JamDecodeFixed for Timeslot {
    const SIZE_UNIT: SizeUnit = SizeUnit::Bytes;

    fn decode_fixed<I: JamInput>(input: &mut I, size: usize) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self(u32::decode_fixed(input, size)?))
    }
}

impl Timeslot {
    pub fn new(slot: u32) -> Self {
        Self(slot)
    }

    pub fn slot(&self) -> u32 {
        self.0
    }

    pub fn epoch(&self) -> u32 {
        self.0 / EPOCH_LENGTH as u32
    }

    pub fn is_epoch_start(&self) -> bool {
        self.slot_phase() == 0
    }

    pub fn slot_phase(&self) -> u32 {
        self.0 % EPOCH_LENGTH as u32
    }

    pub fn to_unix_timestamp(&self) -> u64 {
        let slot_duration_secs = self.0 as u64 * SLOT_DURATION;
        COMMON_ERA_TIMESTAMP + slot_duration_secs
    }

    /// Checks if the timeslot value is in the future compared to the current UTC time
    pub fn is_in_future(&self) -> bool {
        let current_utc_time = Clock::now_unix_timestamp();
        self.to_unix_timestamp() > current_utc_time
    }
}
