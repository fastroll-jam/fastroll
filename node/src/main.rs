use rjam_node::init::init_node;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let _node = init_node()?;
    Ok(())
}
