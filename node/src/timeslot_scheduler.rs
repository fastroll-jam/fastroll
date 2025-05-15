use fr_clock::Clock;
use fr_common::SLOT_DURATION;
use fr_state::types::Timeslot;
use tokio::time::{interval, Duration};

pub struct TimeslotScheduler;
impl TimeslotScheduler {
    pub async fn spawn_scheduled_tasks() {
        let mut interval = interval(Duration::from_secs(SLOT_DURATION));
        loop {
            interval.tick().await;
            let timeslot = Timeslot::new(
                Clock::now_jam_timeslot().expect("System time should be in JAM common era"),
            );
            if timeslot.is_epoch_start() {
                tracing::info!("🏁 New epoch: {:?}, {timeslot:?}", timeslot.epoch())
            } else {
                tracing::info!("⏱️ {timeslot:?}");
            }
            tokio::spawn(async move {
                tracing::info!("Block task spawned");
            });
        }
    }
}
