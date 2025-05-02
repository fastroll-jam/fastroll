use crate::{jam_node::ValidatorInfo, keystore::load_dev_accounts_from_file};
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command()]
pub struct Cli {
    #[command(subcommand)]
    pub command: CliCommand,
}

#[derive(Subcommand)]
pub enum CliCommand {
    Run {
        #[arg(long)]
        dev_account: Option<DevAccountName>,
    },
}

#[derive(ValueEnum, Clone, Debug)]
#[clap(rename_all = "lower")]
pub enum DevAccountName {
    Alice,
    Bob,
    Carol,
    David,
    Eve,
    Ferdie,
}

impl DevAccountName {
    pub fn load_validator_key_info(&self) -> ValidatorInfo {
        let devs = load_dev_accounts_from_file();
        match self {
            DevAccountName::Alice => devs.alice.into(),
            DevAccountName::Bob => devs.bob.into(),
            DevAccountName::Carol => devs.carol.into(),
            DevAccountName::David => devs.david.into(),
            DevAccountName::Eve => devs.eve.into(),
            DevAccountName::Ferdie => devs.fergie.into(),
        }
    }
}
