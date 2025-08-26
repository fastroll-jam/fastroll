use crate::{CLIENT_VERSION, SPEC_VERSION};
use clap::{Parser, Subcommand};
use fr_common::{CHAIN_SPEC, CORE_COUNT, EPOCH_LENGTH, SLOT_DURATION, VALIDATOR_COUNT};
use fr_node::keystore::dev_account_profile::DevNodeAccountProfile;
use std::sync::LazyLock;

static VERSION: LazyLock<String> =
    LazyLock::new(|| format!("v{CLIENT_VERSION} graypaper v{SPEC_VERSION}"));

pub static NETWORK_INFO: LazyLock<String> = LazyLock::new(|| {
    format!(
        "Network Info: \n\t\
        chain-spec: {CHAIN_SPEC} \n\t\
        validator-count: {VALIDATOR_COUNT} \n\t\
        core-count: {CORE_COUNT} \n\t\
        slot-duration: {SLOT_DURATION} \n\t\
        epoch-length: {EPOCH_LENGTH}"
    )
});

#[derive(Parser)]
#[command(version=VERSION.as_str(), about)]
#[command(subcommand_required = false)]
pub struct Cli {
    /// Print network information
    #[arg(long)]
    pub network: bool,
    #[command(subcommand)]
    pub command: Option<CliCommand>,
}

#[derive(Subcommand)]
pub enum CliCommand {
    Run {
        #[arg(long)]
        dev_account: DevNodeAccountProfile,
    },
    /// Run JAM block importer as fuzz target
    Fuzz {
        #[arg(long, default_value = "/tmp/jam_target.sock")]
        socket: String,
    },
}
