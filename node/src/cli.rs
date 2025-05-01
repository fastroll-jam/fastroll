use crate::{keystore::load_dev_accounts_from_file, node::ValidatorInfo};
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
            DevAccountName::Alice => ValidatorInfo::new_localhost(9990, devs.alice.into()),
            DevAccountName::Bob => ValidatorInfo::new_localhost(9991, devs.bob.into()),
            DevAccountName::Carol => ValidatorInfo::new_localhost(9992, devs.carol.into()),
            DevAccountName::David => ValidatorInfo::new_localhost(9993, devs.david.into()),
            DevAccountName::Eve => ValidatorInfo::new_localhost(9994, devs.eve.into()),
            DevAccountName::Ferdie => ValidatorInfo::new_localhost(9995, devs.fergie.into()),
        }
    }
}
