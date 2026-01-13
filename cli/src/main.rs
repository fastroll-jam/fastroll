use clap::Parser;
use fastroll::{Cli, CliCommand, NETWORK_INFO};
use fr_common::{
    utils::tracing::setup_tracing,
    versions::{CLIENT_VERSION, SPEC_VERSION},
};
use fr_fuzz::{
    fuzz_target::FuzzTargetRunner,
    types::{PeerInfo, Version},
    versions::{FUZZ_FEATURES, FUZZ_PROTO_VERSION},
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
                FUZZ_PROTO_VERSION,
                FUZZ_FEATURES,
                Version::from_str(SPEC_VERSION)?,
                Version::from_str(CLIENT_VERSION)?,
                "FastRoll".to_string(),
            ))?;
            target_runner.run_as_fuzz_target(socket).await?;
            Ok(())
        }
        None => {
            println!("Provide a subcommand or a valid flag.");
            Ok(())
        }
    }
}
