use rocksdb::{BoundColumnFamily, ColumnFamilyDescriptor, Options, WriteBatch, WriteOptions, DB};
use std::{path::Path, sync::Arc};
use thiserror::Error;

pub const STATE_CF_NAME: &str = "state_cf";
pub const MERKLE_CF_NAME: &str = "merkle_cf";
pub const HEADER_CF_NAME: &str = "header_cf";

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
    pub fn open<P: AsRef<Path>>(path: P, create_if_missing: bool) -> Result<Self, CoreDBError> {
        let mut opts = Options::default();
        opts.create_if_missing(create_if_missing);
        opts.create_missing_column_families(true);

        let cfs = vec![
            ColumnFamilyDescriptor::new(STATE_CF_NAME, Options::default()),
            ColumnFamilyDescriptor::new(MERKLE_CF_NAME, Options::default()),
            ColumnFamilyDescriptor::new(HEADER_CF_NAME, Options::default()),
        ];

        // Open DB with the CF descriptors
        Ok(Self {
            db: Arc::new(DB::open_cf_descriptors(&opts, path, cfs)?),
        })
    }

    pub fn cf_handle(&self, cf_name: &str) -> Result<Arc<BoundColumnFamily>, CoreDBError> {
        self.db
            .cf_handle(cf_name)
            .ok_or_else(|| CoreDBError::ColumnFamilyNotFound(cf_name.to_string()))
    }

    async fn get_entry(
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

    async fn put_entry(
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

    async fn delete_entry(&self, cf_name: &'static str, key: &[u8]) -> Result<(), CoreDBError> {
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

    fn push_to_write_batch(
        &self,
        batch: &mut WriteBatch,
        cf_name: &'static str,
        key: &[u8],
        val: &[u8],
    ) -> Result<(), CoreDBError> {
        batch.put_cf(&self.cf_handle(cf_name)?, key, val);
        Ok(())
    }

    // --- State CF operations

    pub async fn get_state(&self, key: &[u8]) -> Result<Option<Vec<u8>>, CoreDBError> {
        self.get_entry(STATE_CF_NAME, key).await
    }

    pub async fn put_state(&self, key: &[u8], val: &[u8]) -> Result<(), CoreDBError> {
        self.put_entry(STATE_CF_NAME, key, val).await
    }

    pub async fn delete_state(&self, key: &[u8]) -> Result<(), CoreDBError> {
        self.delete_entry(STATE_CF_NAME, key).await
    }

    pub fn push_to_state_write_batch(
        &self,
        batch: &mut WriteBatch,
        key: &[u8],
        val: &[u8],
    ) -> Result<(), CoreDBError> {
        self.push_to_write_batch(batch, STATE_CF_NAME, key, val)
    }

    // --- Merkle CF operations

    pub async fn get_merkle(&self, key: &[u8]) -> Result<Option<Vec<u8>>, CoreDBError> {
        self.get_entry(MERKLE_CF_NAME, key).await
    }

    pub async fn put_merkle(&self, key: &[u8], val: &[u8]) -> Result<(), CoreDBError> {
        self.put_entry(MERKLE_CF_NAME, key, val).await
    }

    pub async fn delete_merkle(&self, key: &[u8]) -> Result<(), CoreDBError> {
        self.delete_entry(MERKLE_CF_NAME, key).await
    }

    pub fn push_to_merkle_write_batch(
        &self,
        batch: &mut WriteBatch,
        key: &[u8],
        val: &[u8],
    ) -> Result<(), CoreDBError> {
        self.push_to_write_batch(batch, MERKLE_CF_NAME, key, val)
    }

    // --- Header CF operations

    pub async fn get_header(&self, key: &[u8]) -> Result<Option<Vec<u8>>, CoreDBError> {
        self.get_entry(HEADER_CF_NAME, key).await
    }

    pub async fn put_header(&self, key: &[u8], val: &[u8]) -> Result<(), CoreDBError> {
        self.put_entry(HEADER_CF_NAME, key, val).await
    }

    pub async fn delete_header(&self, key: &[u8]) -> Result<(), CoreDBError> {
        self.delete_entry(HEADER_CF_NAME, key).await
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
