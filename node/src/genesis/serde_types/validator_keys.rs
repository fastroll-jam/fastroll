use fr_crypto::types::{ValidatorKey, ValidatorKeySet, ValidatorKeys};
use serde::{Deserialize, Serialize};

/// Genesis validator key set which could be loaded from external files via `serde`
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct GenesisValidatorKeySet(Vec<ValidatorKey>);

impl From<GenesisValidatorKeySet> for ValidatorKeySet {
    fn from(value: GenesisValidatorKeySet) -> Self {
        Self(ValidatorKeys::try_from(value.0).expect("Invalid validators key count"))
    }
}
