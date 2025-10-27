use clap::Parser;
use fastroll::{
    cli::{Cli, CliCommand, NETWORK_INFO},
    CLIENT_VERSION, FUZZ_FEATURES, FUZZ_PROTO_VERSION, SPEC_VERSION,
};
use fr_common::utils::tracing::setup_tracing;
use fr_fuzz::{
    fuzz_target::FuzzTargetRunner,
    types::{PeerInfo, Version},
};
use fr_node::jam_node::{init::init_node, runner::run_node};
use std::{error::Error, str::FromStr};
use tempfile::tempdir;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Config tracing subscriber
    setup_tracing();

    let cli = Cli::parse();

    // Temporary DB directory for fuzzer (TempDir guard)
    let _temp_dir = tempdir().expect("Failed to create temporary directory for Fuzz Target DB");
    let fuzz_target_db_path = _temp_dir.path().join("fuzz_target_db");

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
            let mut target_runner = FuzzTargetRunner::new(
                PeerInfo::new(
                    u8::from_str(FUZZ_PROTO_VERSION)?,
                    u32::from_str(FUZZ_FEATURES)?,
                    Version::from_str(SPEC_VERSION)?,
                    Version::from_str(CLIENT_VERSION)?,
                    "FastRoll".to_string(),
                ),
                fuzz_target_db_path,
            )?;
            target_runner.run_as_fuzz_target(socket).await?;
            Ok(())
        }
        None => {
            println!("Provide a subcommand or a valid flag.");
            Ok(())
        }
    }
}
