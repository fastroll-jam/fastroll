use rjam_codec::{
    impl_jam_codec_for_newtype, JamCodecError, JamDecode, JamEncode, JamInput, JamOutput,
};
use rjam_common::{COMMON_ERA_TIMESTAMP, EPOCH_LENGTH, SLOT_DURATION};
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, Ord, PartialOrd, PartialEq, Eq)]
pub struct Timeslot(pub u32);
impl_jam_codec_for_newtype!(Timeslot, u32);

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

    pub fn from_unix_timestamp(timestamp: u64) -> Option<Self> {
        if timestamp < COMMON_ERA_TIMESTAMP {
            return None;
        }
        let slot = (timestamp - COMMON_ERA_TIMESTAMP) / SLOT_DURATION;
        Some(Self(slot as u32))
    }

    /// Checks if the timeslot value is in the future compared to the current UTC time
    pub fn is_in_future(&self) -> bool {
        let current_utc_time = OffsetDateTime::now_utc().unix_timestamp() as u64;
        let slot_unix_time = self.to_unix_timestamp();

        slot_unix_time > current_utc_time
    }
}
