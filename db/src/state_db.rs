use crate::kvdb::{KeyValueDB, KeyValueDBError, RocksDBConfig};
use std::ops::Deref;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StateDBError {
    #[error("KeyValueDBError: {0}")]
    KeyValueDBError(#[from] KeyValueDBError),
}

pub struct StateDB(KeyValueDB);

impl Deref for StateDB {
    type Target = KeyValueDB;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl StateDB {
    pub fn open(config: &RocksDBConfig) -> Result<Self, StateDBError> {
        let kvdb = KeyValueDB::new(config)?;
        Ok(Self(kvdb))
    }
}
