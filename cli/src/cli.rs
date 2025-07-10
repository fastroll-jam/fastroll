use clap::{Parser, Subcommand};
use fr_node::keystore::dev_account_profile::DevNodeAccountProfile;

#[derive(Parser)]
#[command(version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: CliCommand,
}

#[derive(Subcommand)]
pub enum CliCommand {
    /// Run JAM node
    Run {
        #[arg(long)]
        dev_account: Option<DevNodeAccountProfile>,
    },
    /// Run JAM block importer as fuzz target
    Fuzz {
        #[arg(long, default_value = "/tmp/jam_target.sock")]
        socket: String,
    },
}
