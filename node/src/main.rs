use fr_node::{init::init_node, timeslot_scheduler::TimeslotScheduler};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let node = init_node().await?;

    // Bind to a socket address and start accepting connections
    let network_manager = node.network_manager.clone();
    let server_jh = tokio::spawn(async move { network_manager.run_as_server().await });
    let network_manager = node.network_manager.clone();
    let client_jh = tokio::spawn(async move {
        network_manager.connect_to_peers().await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await; // timeout
        network_manager.connect_to_all_peers().await.unwrap();
    });

    // Spawn per-slot tasks
    let slots_jh = tokio::spawn(async move { TimeslotScheduler::spawn_scheduled_tasks().await });

    server_jh.await??;
    client_jh.await?;
    slots_jh.await?;
    // TODO: Timeslot scheduling, tickets submission
    Ok(())
}
