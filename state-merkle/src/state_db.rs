use dashmap::DashMap;
use rjam_common::Hash32;
use rjam_db::core::{CoreDB, CoreDBError, STATE_CF_NAME};
use rocksdb::{ColumnFamily, WriteBatch};
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
    /// Cache for storing encoded state values.
    cache: DashMap<Hash32, Vec<u8>>,
}

impl StateDB {
    pub fn new(core: Arc<CoreDB>, cache_size: usize) -> Self {
        Self {
            core,
            cache: DashMap::with_capacity(cache_size),
        }
    }

    pub fn open<P: AsRef<Path>>(
        path: P,
        create_if_missing: bool,
        cache_size: usize,
    ) -> Result<Self, StateDBError> {
        Ok(Self::new(
            Arc::new(CoreDB::open(path, create_if_missing)?),
            cache_size,
        ))
    }

    pub fn cf_handle(&self) -> Result<&ColumnFamily, StateDBError> {
        self.core.cf_handle(STATE_CF_NAME).map_err(|e| e.into())
    }

    pub fn get_entry(&self, key: &Hash32) -> Result<Option<Vec<u8>>, StateDBError> {
        // lookup the cache
        if let Some(data) = self.cache.get(key) {
            return Ok(Some(data.clone()));
        }

        // fetch encoded state data octets from the db and put into the cache
        let value = self.core.get_state(key.as_slice())?;

        // insert into cache if found
        if let Some(data) = &value {
            self.cache.insert(*key, data.clone());
        }

        Ok(value)
    }

    pub fn put_entry(&self, key: &Hash32, val: &[u8]) -> Result<(), StateDBError> {
        // write to DB
        self.core.put_state(key.as_slice(), val)?;
        // insert into cache
        self.cache.insert(*key, val.to_vec());
        Ok(())
    }

    pub fn delete_entry(&self, key: &Hash32) -> Result<(), StateDBError> {
        Ok(self.core.delete_state(key.as_slice())?)
    }

    /// Commit a write batch to the state column family.
    pub fn commit_write_batch(&self, batch: WriteBatch) -> Result<(), StateDBError> {
        Ok(self.core.commit_write_batch(batch)?)
    }
}
