use crate::config::RocksDBOpts;
use rocksdb::{BoundColumnFamily, WriteBatch, WriteOptions, DB};
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
    pub fn open<P: AsRef<Path>>(path: P, db_opts: RocksDBOpts) -> Result<Self, CoreDBError> {
        // Open DB with the CF descriptors
        Ok(Self {
            db: Arc::new(DB::open_cf_descriptors(
                &db_opts.opts,
                path,
                db_opts.column_families,
            )?),
        })
    }

    pub fn cf_handle(&self, cf_name: &str) -> Result<Arc<BoundColumnFamily>, CoreDBError> {
        self.db
            .cf_handle(cf_name)
            .ok_or_else(|| CoreDBError::ColumnFamilyNotFound(cf_name.to_string()))
    }

    pub async fn get_entry(
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

    pub async fn put_entry(
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
                .ok_or_else(|| CoreDBError::ColumnFamilyNotFound(cf_name.to_string()))?;
            db.put_cf(&cf, &key_vec, val_vec)?;
            Ok(())
        })
        .await?
    }

    pub async fn delete_entry(&self, cf_name: &'static str, key: &[u8]) -> Result<(), CoreDBError> {
        let db = self.db.clone();
        let key_vec = key.to_vec();
        tokio::task::spawn_blocking(move || -> Result<(), CoreDBError> {
            let cf = db
                .cf_handle(cf_name)
                .ok_or_else(|| CoreDBError::ColumnFamilyNotFound(cf_name.to_string()))?;
            db.delete_cf(&cf, key_vec)?;
            Ok(())
        })
        .await?
    }

    pub fn push_to_write_batch(
        &self,
        batch: &mut WriteBatch,
        cf_name: &'static str,
        key: &[u8],
        val: &[u8],
    ) -> Result<(), CoreDBError> {
        batch.put_cf(&self.cf_handle(cf_name)?, key, val);
        Ok(())
    }

    // --- Batch operation
    pub async fn commit_write_batch(&self, batch: WriteBatch) -> Result<(), CoreDBError> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || -> Result<(), CoreDBError> {
            let write_opts = WriteOptions::default();
            db.write_opt(batch, &write_opts)?;
            Ok(())
        })
        .await?
    }
}
