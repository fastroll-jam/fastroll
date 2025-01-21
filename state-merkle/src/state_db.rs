use rjam_db::kvdb::{KeyValueDBError, RocksDBConfig, KVDB};
use std::ops::Deref;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StateDBError {
    #[error("KeyValueDBError: {0}")]
    KeyValueDBError(#[from] KeyValueDBError),
}

pub struct StateDB(KVDB);

impl Deref for StateDB {
    type Target = KVDB;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl StateDB {
    pub fn open(config: &RocksDBConfig) -> Result<Self, StateDBError> {
        let kvdb = KVDB::open(config)?;
        Ok(Self(kvdb))
    }
}
