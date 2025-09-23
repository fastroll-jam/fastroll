use rocksdb::{
    ColumnFamily, ColumnFamilyDescriptor, Direction, IteratorMode, Options, WriteBatch,
    WriteOptions, DB,
};
use std::{path::Path, sync::Arc};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreDBError {
    #[error("Column family not found: {0}")]
    ColumnFamilyNotFound(String),
    #[error("RocksDB error: {0}")]
    RocksDBError(#[from] rocksdb::Error),
    #[error("Tokio join error: {0}")]
    JoinError(#[from] tokio::task::JoinError),
}

/// A single RocksDB handle with multiple column families.
pub struct CoreDB {
    /// RocksDB instance.
    db: Arc<DB>,
}

impl CoreDB {
    /// Opens or creates a RocksDB instance at the given `path` with column families.
    pub fn open<P: AsRef<Path>>(
        path: P,
        opts: Options,
        cf_descriptors: impl IntoIterator<Item = ColumnFamilyDescriptor>,
    ) -> Result<Self, CoreDBError> {
        // Open DB with the CF descriptors
        Ok(Self {
            db: Arc::new(DB::open_cf_descriptors(&opts, path, cf_descriptors)?),
        })
    }

    pub(crate) fn cf_handle(&self, cf_name: &str) -> Result<&ColumnFamily, CoreDBError> {
        self.db
            .cf_handle(cf_name)
            .ok_or(CoreDBError::ColumnFamilyNotFound(cf_name.to_string()))
    }

    pub(crate) async fn get_entry(
        &self,
        cf_name: &'static str,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, CoreDBError> {
        let db = self.db.clone();
        let key_vec = key.to_vec();
        Ok(tokio::task::spawn_blocking(move || {
            let cf = db
                .cf_handle(cf_name)
                .ok_or(CoreDBError::ColumnFamilyNotFound(cf_name.to_string()))
                .ok()?;
            db.get_cf(&cf, &key_vec).ok()?
        })
        .await?)
    }

    pub(crate) async fn put_entry(
        &self,
        cf_name: &'static str,
        key: &[u8],
        val: &[u8],
    ) -> Result<(), CoreDBError> {
        let db = self.db.clone();
        let key_vec = key.to_vec();
        let val_vec = val.to_vec();
        tokio::task::spawn_blocking(move || -> Result<(), CoreDBError> {
            let cf = db
                .cf_handle(cf_name)
                .ok_or(CoreDBError::ColumnFamilyNotFound(cf_name.to_string()))?;
            db.put_cf(&cf, &key_vec, val_vec)?;
            Ok(())
        })
        .await?
    }

    pub(crate) async fn delete_entry(
        &self,
        cf_name: &'static str,
        key: &[u8],
    ) -> Result<(), CoreDBError> {
        let db = self.db.clone();
        let key_vec = key.to_vec();
        tokio::task::spawn_blocking(move || -> Result<(), CoreDBError> {
            let cf = db
                .cf_handle(cf_name)
                .ok_or(CoreDBError::ColumnFamilyNotFound(cf_name.to_string()))?;
            db.delete_cf(&cf, key_vec)?;
            Ok(())
        })
        .await?
    }

    #[allow(dead_code)]
    pub(crate) fn push_to_write_batch(
        &self,
        batch: &mut WriteBatch,
        cf_name: &'static str,
        key: &[u8],
        val: &[u8],
    ) -> Result<(), CoreDBError> {
        batch.put_cf(&self.cf_handle(cf_name)?, key, val);
        Ok(())
    }

    /// Commits write items in the `WriteBatch` into the DB.
    pub(crate) async fn commit_write_batch(&self, batch: WriteBatch) -> Result<(), CoreDBError> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || -> Result<(), CoreDBError> {
            let write_opts = WriteOptions::default();
            db.write_opt(batch, &write_opts)?;
            Ok(())
        })
        .await?
    }

    pub async fn find_neighboring_keys(
        &self,
        cf_name: &'static str,
        key: &[u8],
    ) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>), CoreDBError> {
        let db = self.db.clone();
        let key_vec = key.to_vec();

        tokio::task::spawn_blocking(move || -> Result<_, CoreDBError> {
            let cf = db
                .cf_handle(cf_name)
                .ok_or(CoreDBError::ColumnFamilyNotFound(cf_name.to_string()))?;
            // TODO: further advance iterators
            let mut iter = db.iterator_cf(cf, IteratorMode::From(&key_vec, Direction::Forward));
            let next_key = iter.next().transpose()?.map(|(k, _)| k.to_vec());

            let mut iter_rev = db.iterator_cf(cf, IteratorMode::From(&key_vec, Direction::Reverse));
            let prev_key = iter_rev.next().transpose()?.map(|(k, _)| k.to_vec());

            Ok((next_key, prev_key))
        })
        .await?
    }
}
