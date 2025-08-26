use crate::keystore::load_dev_accounts;
use clap::ValueEnum;
use fr_network::manager::LocalNodeInfo;

#[derive(ValueEnum, Clone, Debug)]
#[clap(rename_all = "lower")]
pub enum DevNodeAccountProfile {
    Alice,
    Bob,
    Carol,
    David,
    Eve,
    Fergie,
}

impl DevNodeAccountProfile {
    pub fn load_validator_key_info(&self) -> LocalNodeInfo {
        let devs = load_dev_accounts();
        match self {
            DevNodeAccountProfile::Alice => devs.alice.into(),
            DevNodeAccountProfile::Bob => devs.bob.into(),
            DevNodeAccountProfile::Carol => devs.carol.into(),
            DevNodeAccountProfile::David => devs.david.into(),
            DevNodeAccountProfile::Eve => devs.eve.into(),
            DevNodeAccountProfile::Fergie => devs.fergie.into(),
        }
    }
}
