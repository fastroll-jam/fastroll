use rjam_db::core::{CoreDB, CoreDBError};
use rocksdb::WriteBatch;
use std::{path::Path, sync::Arc};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StateDBError {
    #[error("CoreDBError: {0}")]
    CoreDBError(#[from] CoreDBError),
}

pub struct StateDB {
    /// RocksDB core.
    core: Arc<CoreDB>,
}

impl StateDB {
    pub fn new(core: Arc<CoreDB>) -> Self {
        Self { core }
    }

    pub fn open<P: AsRef<Path>>(path: P, create_if_missing: bool) -> Result<Self, StateDBError> {
        let core = CoreDB::open(path, create_if_missing)?;
        Ok(Self {
            core: Arc::new(core),
        })
    }

    pub fn get_entry(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateDBError> {
        Ok(self.core.get_state(key)?)
    }

    pub fn put_entry(&self, key: &[u8], val: &[u8]) -> Result<(), StateDBError> {
        Ok(self.core.put_state(key, val)?)
    }

    pub fn delete_entry(&self, key: &[u8]) -> Result<(), StateDBError> {
        Ok(self.core.delete_state(key)?)
    }

    /// Commit a write batch to the state column family.
    pub fn commit_write_batch(&self, batch: WriteBatch) -> Result<(), StateDBError> {
        Ok(self.core.commit_write_batch(batch)?)
    }
}
