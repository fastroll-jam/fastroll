use crate::{
    jam_node::JamNode, roles::importer::BlockImporter, timeslot_scheduler::TimeslotScheduler,
};
use fr_block::types::block::Block;
use std::{error::Error, sync::Arc};
use tokio::sync::mpsc;

pub async fn run_node(node: JamNode) -> Result<(), Box<dyn Error>> {
    let node = Arc::new(node);

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

    let node_cloned = node.clone();
    let block_import_mpsc_sender_cloned = block_import_mpsc_sender.clone();
    let client_jh = tokio::spawn(async move {
        node_cloned
            .run_initiator(block_import_mpsc_sender_cloned)
            .await
    });

    // Connect to all peers
    if let Err(e) = client_jh.await? {
        tracing::error!("Peer connection error: {e}");
    }

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
    // TODO: Node: Safrole Ticket submission
    Ok(())
}
