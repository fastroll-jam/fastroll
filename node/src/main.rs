use fr_node::init::init_node;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let _node = init_node().await?;

    // Bind to a socket address and start accepting connections
    // let mut network_manager = node.network_manager.clone();
    // tokio::spawn(async move { network_manager.run_as_server().await });

    // Connect to peers

    // TODO: Timeslot scheduling, tickets submission

    Ok(())
}
