use fr_block::types::block::Block;
use fr_node::{
    init::init_node, roles::importer::BlockImporter, timeslot_scheduler::TimeslotScheduler,
};
use std::{error::Error, sync::Arc};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let node = Arc::new(init_node().await?);

    // Open a mpsc channel to be used for communication between UP stream handler and the block importer task
    const CHANNEL_SIZE: usize = 10;
    let (block_import_mpsc_sender, block_import_mpsc_recv) = mpsc::channel::<Block>(CHANNEL_SIZE);

    // Bind to a socket address and start accepting connections
    let node_cloned = node.clone();
    let block_import_mpsc_sender_cloned = block_import_mpsc_sender.clone();
    let acceptor_jh = tokio::spawn(async move {
        node_cloned
            .run_acceptor(block_import_mpsc_sender_cloned)
            .await
    });

    let network_manager = node.network_manager();
    let block_import_mpsc_sender_cloned = block_import_mpsc_sender.clone();
    let client_jh = tokio::spawn(async move {
        if let Err(e) = network_manager
            .connect_to_peers(block_import_mpsc_sender_cloned.clone())
            .await
        {
            tracing::warn!("Failed to connect to peers: {}", e);
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await; // timeout
        if let Err(e) = network_manager
            .connect_to_all_peers(block_import_mpsc_sender_cloned)
            .await
        {
            tracing::error!("Failed to connect to all peers: {}", e);
        }
    });

    // Connect to all peers
    client_jh.await?;

    let storage = node.storage();
    let importer_jh = tokio::spawn(async move {
        BlockImporter::run_block_importer(storage, block_import_mpsc_recv).await
    });

    // Spawn per-slot tasks
    let slots_jh =
        tokio::spawn(async move { TimeslotScheduler::spawn_scheduled_tasks(node).await });

    importer_jh.await?;
    slots_jh.await?;
    acceptor_jh.await??;
    // TODO: Timeslot scheduling, tickets submission
    Ok(())
}
