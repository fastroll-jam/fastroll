use crate::core::{CoreDB, CoreDBError, STATE_CF_NAME};
use dashmap::DashMap;
use rjam_common::Hash32;
use rocksdb::{BoundColumnFamily, WriteBatch};
use std::sync::Arc;
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

    pub fn cf_handle(&self) -> Result<Arc<BoundColumnFamily>, StateDBError> {
        self.core.cf_handle(STATE_CF_NAME).map_err(|e| e.into())
    }

    pub async fn get_entry(&self, key: &Hash32) -> Result<Option<Vec<u8>>, StateDBError> {
        // lookup the cache
        if let Some(data) = self.cache.get(key) {
            return Ok(Some(data.clone()));
        }

        // fetch encoded state data octets from the db and put into the cache
        let value = self.core.get_state(key.as_slice()).await?;

        // insert into cache if found
        if let Some(data) = &value {
            self.cache.insert(*key, data.clone());
        }

        Ok(value)
    }

    pub async fn put_entry(&self, key: &Hash32, val: &[u8]) -> Result<(), StateDBError> {
        // write to DB
        self.core.put_state(key.as_slice(), val).await?;
        // insert into cache
        self.cache.insert(*key, val.to_vec());
        Ok(())
    }

    pub async fn delete_entry(&self, key: &Hash32) -> Result<(), StateDBError> {
        self.core.delete_state(key.as_slice()).await?;
        self.cache.remove(key);
        Ok(())
    }

    /// Commit a write batch to the state column family.
    pub async fn commit_write_batch(&self, batch: WriteBatch) -> Result<(), StateDBError> {
        Ok(self.core.commit_write_batch(batch).await?)
    }
}
