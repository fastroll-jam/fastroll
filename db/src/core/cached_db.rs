use crate::core::core_db::{CoreDB, CoreDBError};
use dashmap::DashMap;
use rocksdb::{ColumnFamily, WriteBatch};
use std::{hash::Hash, sync::Arc};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CachedDBError {
    #[error("CoreDBError: {0}")]
    CoreDBError(#[from] CoreDBError),
}

/// A trait for types that are hold under DB cache, defining encoding rules for the cache entries.
pub trait CacheItem: Clone {
    fn into_db_value(self) -> Vec<u8>;

    fn from_db_kv(key: &[u8], val: Vec<u8>) -> Self
    where
        Self: Sized;
}

impl CacheItem for Vec<u8> {
    fn into_db_value(self) -> Vec<u8> {
        self
    }

    fn from_db_kv(_key: &[u8], val: Vec<u8>) -> Self {
        val
    }
}

/// A RocksDB column family DB type with a built-in cache.
pub struct CachedDB<K, V>
where
    K: Hash + Eq + AsRef<[u8]> + Clone,
    V: CacheItem,
{
    /// RocksDB core
    pub core: Arc<CoreDB>,
    /// RocksDB column family name
    pub cf_name: &'static str,
    /// A thread-safe in-memory cache
    pub cache: DashMap<K, V>,
}

impl<K, V> CachedDB<K, V>
where
    K: Hash + Eq + AsRef<[u8]> + Clone,
    V: CacheItem,
{
    pub fn new(core: Arc<CoreDB>, cf_name: &'static str, cache_size: usize) -> Self {
        Self {
            core,
            cf_name,
            cache: DashMap::with_capacity(cache_size),
        }
    }

    pub fn cf_handle(&self) -> Result<&ColumnFamily, CachedDBError> {
        Ok(self.core.cf_handle(self.cf_name)?)
    }

    pub async fn get_entry(&self, key: &K) -> Result<Option<V>, CachedDBError> {
        // lookup the cache
        if let Some(v) = self.cache.get(key) {
            return Ok(Some(v.clone()));
        }

        // fetch encoded state data octets from the db and put into the cache
        let value = self
            .core
            .get_entry(self.cf_name, key.as_ref())
            .await?
            .map(|v| V::from_db_kv(key.as_ref(), v));

        // insert into cache if found
        if let Some(data) = &value {
            self.cache.insert(key.clone(), data.clone());
        }

        Ok(value)
    }

    pub async fn put_entry(&self, key: &K, val: V) -> Result<(), CachedDBError> {
        // write to DB
        self.core
            .put_entry(self.cf_name, key.as_ref(), &val.clone().into_db_value())
            .await?;
        // insert into cache
        self.cache.insert(key.clone(), val);
        Ok(())
    }

    pub async fn delete_entry(&self, key: &K) -> Result<(), CachedDBError> {
        self.core.delete_entry(self.cf_name, key.as_ref()).await?;
        self.cache.remove(key);
        Ok(())
    }

    /// Commit a write batch to the state column family.
    pub async fn commit_write_batch(&self, batch: WriteBatch) -> Result<(), CachedDBError> {
        Ok(self.core.commit_write_batch(batch).await?)
    }
}
