use fr_node::init::init_node;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let node = init_node().await?;

    // Bind to a socket address and start accepting connections
    let network_manager = node.network_manager.clone();
    network_manager.run_as_server().await?;

    // TODO: Connect to peers, timeslot scheduling, tickets submission

    Ok(())
}
