use fr_node::{init::init_node, timeslot_scheduler::TimeslotScheduler};
use std::{error::Error, sync::Arc};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let node = Arc::new(init_node().await?);

    // Bind to a socket address and start accepting connections
    let node_cloned = node.clone();
    let server_jh = tokio::spawn(async move { node_cloned.run_as_server().await });

    let network_manager = node.network_manager();
    let client_jh = tokio::spawn(async move {
        if let Err(e) = network_manager.connect_to_peers().await {
            tracing::warn!("Failed to connect to peers: {}", e);
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await; // timeout
        if let Err(e) = network_manager.connect_to_all_peers().await {
            tracing::error!("Failed to connect to all peers: {}", e);
        }
    });

    // Connect to all peers
    client_jh.await?;

    // Spawn per-slot tasks
    let slots_jh =
        tokio::spawn(async move { TimeslotScheduler::spawn_scheduled_tasks(node).await });

    slots_jh.await?;
    server_jh.await??;
    // TODO: Timeslot scheduling, tickets submission
    Ok(())
}
