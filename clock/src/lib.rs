use fr_common::{COMMON_ERA_TIMESTAMP, COMMON_ERA_TIMESTAMP_MILLIS, SLOT_DURATION};
use std::marker::PhantomData;
use time::OffsetDateTime;

pub type JamClock = Clock<TimeProvider>;

pub trait UnixTimeProvider {
    fn now_unix_timestamp() -> u64;

    fn now_unix_timestamp_millis() -> u64;
}

pub struct TimeProvider;
impl UnixTimeProvider for TimeProvider {
    fn now_unix_timestamp() -> u64 {
        OffsetDateTime::now_utc().unix_timestamp() as u64
    }

    fn now_unix_timestamp_millis() -> u64 {
        (OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as u64
    }
}

pub struct Clock<T: UnixTimeProvider> {
    _phantom: PhantomData<T>,
}

impl<T: UnixTimeProvider> Clock<T> {
    pub fn seconds_since_common_era() -> Option<u64> {
        let now_timestamp_seconds = T::now_unix_timestamp();
        if now_timestamp_seconds < COMMON_ERA_TIMESTAMP {
            return None;
        }
        now_timestamp_seconds.checked_sub(COMMON_ERA_TIMESTAMP)
    }

    pub fn millis_since_common_era() -> Option<u64> {
        let now_timestamp_millis = T::now_unix_timestamp_millis();
        if now_timestamp_millis < COMMON_ERA_TIMESTAMP_MILLIS {
            return None;
        }
        now_timestamp_millis.checked_sub(COMMON_ERA_TIMESTAMP_MILLIS)
    }

    pub fn now_jam_timeslot() -> Option<u32> {
        Some((Self::seconds_since_common_era()? / SLOT_DURATION) as u32)
    }

    pub fn millis_until_next_timeslot_boundary() -> Option<u64> {
        let millis_since_common_era = Self::millis_since_common_era()?;
        let offset_millis = millis_since_common_era
            .checked_sub(((Self::now_jam_timeslot()? as u64) * SLOT_DURATION) * 1_000)?;
        (SLOT_DURATION * 1_000).checked_sub(offset_millis)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_UNIX_TIMESTAMP: u64 = COMMON_ERA_TIMESTAMP + 6 + 1; // 7 seconds after the common era
    const TEST_MILLIS_OFFSET: u64 = 123;

    struct TestTimeProvider;
    type TestClock = Clock<TestTimeProvider>;

    impl UnixTimeProvider for TestTimeProvider {
        fn now_unix_timestamp() -> u64 {
            TEST_UNIX_TIMESTAMP
        }

        fn now_unix_timestamp_millis() -> u64 {
            TEST_UNIX_TIMESTAMP * 1_000 + TEST_MILLIS_OFFSET
        }
    }

    #[test]
    fn test_millis_since_common_era() {
        assert_eq!(TestClock::millis_since_common_era(), Some(7_123));
    }

    #[test]
    fn test_seconds_since_common_era() {
        assert_eq!(TestClock::seconds_since_common_era(), Some(7));
    }

    #[test]
    fn test_now_jam_timeslot() {
        assert_eq!(TestClock::now_jam_timeslot(), Some(1));
    }

    #[test]
    fn test_millis_until_next_timeslot_boundary() {
        assert_eq!(
            TestClock::millis_until_next_timeslot_boundary(),
            Some(5_000 - 123)
        );
    }
}
