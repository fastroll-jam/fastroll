use crate::{jam_node::JamNode, roles::scheduled_tasks::extend_chain};
use fr_clock::JamClock;
use fr_common::SLOT_DURATION;
use fr_state::types::Timeslot;
use std::sync::Arc;
use tokio::time::{interval, Duration};

pub struct TimeslotScheduler;
impl TimeslotScheduler {
    pub async fn spawn_scheduled_tasks(jam_node: Arc<JamNode>) {
        let mut interval = interval(Duration::from_secs(SLOT_DURATION));
        loop {
            interval.tick().await;
            let timeslot = Timeslot::new(
                JamClock::now_jam_timeslot().expect("System time should be in JAM common era"),
            );
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
