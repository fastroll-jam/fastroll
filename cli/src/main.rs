use clap::Parser;
use fastroll::{
    cli::{Cli, CliCommand, NETWORK_INFO},
    CLIENT_VERSION, SPEC_VERSION,
};
use fr_common::utils::tracing::setup_tracing;
use fr_fuzz::{
    fuzz_target::FuzzTargetRunner,
    types::{PeerInfo, Version},
};
use fr_node::jam_node::{init::init_node, runner::run_node};
use std::{error::Error, str::FromStr};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Config tracing subscriber
    setup_tracing();

    let cli = Cli::parse();

    // CLI options
    if cli.network {
        println!("{}", NETWORK_INFO.as_str());
        return Ok(());
    }

    // CLI args
    match cli.command {
        Some(CliCommand::Run {
            dev_account,
            db_path,
        }) => run_node(init_node(dev_account, db_path.as_str()).await?).await,
        Some(CliCommand::Fuzz { socket }) => {
            let mut target_runner = FuzzTargetRunner::new(PeerInfo::new(
                "FastRoll".to_string(),
                Version::from_str(CLIENT_VERSION)?,
                Version::from_str(SPEC_VERSION)?,
            ));
            target_runner.run_as_fuzz_target(socket).await
        }
        None => {
            println!("Provide a subcommand or a valid flag.");
            Ok(())
        }
    }
}
