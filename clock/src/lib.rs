use fr_common::{COMMON_ERA_TIMESTAMP, SLOT_DURATION};
use time::OffsetDateTime;

pub struct Clock;
impl Clock {
    pub fn now_unix_timestamp() -> u64 {
        OffsetDateTime::now_utc().unix_timestamp() as u64
    }

    pub fn now_jam_timeslot() -> Option<u32> {
        let timestamp = Self::now_unix_timestamp();
        if timestamp < COMMON_ERA_TIMESTAMP {
            return None;
        }
        let slot = (timestamp - COMMON_ERA_TIMESTAMP) / SLOT_DURATION;
        Some(slot as u32)
    }
}
