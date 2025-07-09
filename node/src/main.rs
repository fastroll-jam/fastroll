use clap::Parser;
use fr_common::utils::tracing::setup_tracing;
use fr_fuzz_target::runner::FuzzRunner;
use fr_node::{
    cli::{Cli, CliCommand},
    jam_node::{init::init_node, runner::run_node},
};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Config tracing subscriber
    setup_tracing();

    // CLI args
    match Cli::parse().command {
        CliCommand::Run { dev_account } => run_node(init_node(dev_account).await?).await,
        CliCommand::Fuzz { socket } => FuzzRunner::run_as_fuzz_target(socket).await,
    }
}
