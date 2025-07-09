use fr_node::{init::init_node, runner::run_node};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    run_node(init_node().await?).await
}
