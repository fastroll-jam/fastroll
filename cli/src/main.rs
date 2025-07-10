use clap::Parser;
use fastroll::cli::{Cli, CliCommand};
use fr_common::utils::tracing::setup_tracing;
use fr_fuzz_target::{
    runner::FuzzTargetRunner,
    types::{PeerInfo, Version},
};
use fr_node::jam_node::{init::init_node, runner::run_node};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Config tracing subscriber
    setup_tracing();

    // CLI args
    match Cli::parse().command {
        CliCommand::Run { dev_account } => run_node(init_node(dev_account).await?).await,
        CliCommand::Fuzz { socket } => {
            let mut target_runner = FuzzTargetRunner::new(PeerInfo::new(
                "FastRoll".to_string(),
                // TODO: keep up to date
                Version::new(0, 1, 0),
                Version::new(0, 7, 0),
            ));
            target_runner.run_as_fuzz_target(socket).await
        }
    }
}
