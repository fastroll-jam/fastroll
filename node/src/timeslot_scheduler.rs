use crate::{jam_node::JamNode, roles::scheduled_tasks::extend_chain};
use fr_clock::JamClock;
use fr_common::SLOT_DURATION;
use fr_state::types::Timeslot;
use std::sync::Arc;
use tokio::time::{interval_at, Duration, Instant};

pub struct TimeslotScheduler;
impl TimeslotScheduler {
    pub async fn spawn_scheduled_tasks(jam_node: Arc<JamNode>) {
        let millis = match JamClock::millis_until_next_timeslot_boundary() {
            Some(millis) => millis,
            None => {
                tracing::warn!("Failed to calculate the next timeslot boundary");
                return;
            }
        };
        let next_boundary = Instant::now() + Duration::from_millis(millis);
        let mut interval = interval_at(next_boundary, Duration::from_secs(SLOT_DURATION));
        tracing::info!("Waiting until timeslot boundary...");

        loop {
            interval.tick().await;
            let timeslot = match JamClock::now_jam_timeslot() {
                Some(slot) => Timeslot::new(slot),
                None => {
                    tracing::error!("Failed to get current JAM timeslot");
                    continue;
                }
            };
            if timeslot.is_epoch_start() {
                tracing::info!("🏁 New epoch: {:?}, {timeslot:?}", timeslot.epoch())
            } else {
                tracing::info!("⏱️ {timeslot:?}");
            }
            let jam_node_cloned = jam_node.clone();
            tokio::spawn(async move {
                if let Err(e) = extend_chain(jam_node_cloned, &timeslot).await {
                    tracing::error!("Chain extension error: {e}");
                }
            });
        }
    }
}
