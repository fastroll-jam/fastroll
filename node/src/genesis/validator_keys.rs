use fr_crypto::types::{ValidatorKey, ValidatorKeySet, ValidatorKeys};
use serde::{Deserialize, Serialize};

/// Genesis validator key set which could be loaded from external files via `serde`
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GenesisValidatorKeySet(Vec<ValidatorKey>);

impl From<GenesisValidatorKeySet> for ValidatorKeySet {
    fn from(value: GenesisValidatorKeySet) -> Self {
        Self(ValidatorKeys::try_from(value.0).expect("Invalid validators key count"))
    }
}

impl From<ValidatorKeySet> for GenesisValidatorKeySet {
    fn from(value: ValidatorKeySet) -> Self {
        Self(value.0.into())
    }
}
