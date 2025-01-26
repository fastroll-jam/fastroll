use rocksdb::{BoundColumnFamily, ColumnFamilyDescriptor, Options, WriteBatch, WriteOptions, DB};
use std::{path::Path, sync::Arc};
use thiserror::Error;

pub const STATE_CF_NAME: &str = "state_cf";
pub const MERKLE_CF_NAME: &str = "merkle_cf";
pub const HEADER_CF_NAME: &str = "header_cf";

#[derive(Debug, Error)]
pub enum CoreDBError {
    #[error("RocksDB error: {0}")]
    RocksDBError(#[from] rocksdb::Error),
    #[error("Column family not found: {0}")]
    ColumnFamilyNotFound(String),
}

/// A single RocksDB handle with multiple column families.
pub struct CoreDB {
    /// RocksDB instance.
    db: DB,
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
            db: DB::open_cf_descriptors(&opts, path, cfs)?,
        })
    }

    pub fn cf_handle(&self, cf_name: &str) -> Result<Arc<BoundColumnFamily>, CoreDBError> {
        self.db
            .cf_handle(cf_name)
            .ok_or_else(|| CoreDBError::ColumnFamilyNotFound(cf_name.to_string()))
    }

    // --- State CF operations
    pub fn get_state(&self, key: &[u8]) -> Result<Option<Vec<u8>>, CoreDBError> {
        let cf = self.cf_handle(STATE_CF_NAME)?;
        Ok(self.db.get_cf(&cf, key)?)
    }

    pub fn put_state(&self, key: &[u8], val: &[u8]) -> Result<(), CoreDBError> {
        let cf = self.cf_handle(STATE_CF_NAME)?;
        Ok(self.db.put_cf(&cf, key, val)?)
    }

    pub fn delete_state(&self, key: &[u8]) -> Result<(), CoreDBError> {
        let cf = self.cf_handle(STATE_CF_NAME)?;
        Ok(self.db.delete_cf(&cf, key)?)
    }

    pub fn push_to_state_write_batch(
        &self,
        batch: &mut WriteBatch,
        key: &[u8],
        val: &[u8],
    ) -> Result<(), CoreDBError> {
        batch.put_cf(&self.cf_handle(STATE_CF_NAME)?, key, val);
        Ok(())
    }

    // --- Merkle CF operations
    pub fn get_merkle(&self, key: &[u8]) -> Result<Option<Vec<u8>>, CoreDBError> {
        let cf = self.cf_handle(MERKLE_CF_NAME)?;
        Ok(self.db.get_cf(&cf, key)?)
    }

    pub fn put_merkle(&self, key: &[u8], val: &[u8]) -> Result<(), CoreDBError> {
        let cf = self.cf_handle(MERKLE_CF_NAME)?;
        Ok(self.db.put_cf(&cf, key, val)?)
    }

    pub fn delete_merkle(&self, key: &[u8]) -> Result<(), CoreDBError> {
        let cf = self.cf_handle(MERKLE_CF_NAME)?;
        Ok(self.db.delete_cf(&cf, key)?)
    }

    pub fn push_to_merkle_write_batch(
        &self,
        batch: &mut WriteBatch,
        key: &[u8],
        val: &[u8],
    ) -> Result<(), CoreDBError> {
        batch.put_cf(&self.cf_handle(MERKLE_CF_NAME)?, key, val);
        Ok(())
    }

    // --- Header CF operations
    pub fn get_header(&self, key: &[u8]) -> Result<Option<Vec<u8>>, CoreDBError> {
        let cf = self.cf_handle(HEADER_CF_NAME)?;
        Ok(self.db.get_cf(&cf, key)?)
    }

    pub fn put_header(&self, key: &[u8], val: &[u8]) -> Result<(), CoreDBError> {
        let cf = self.cf_handle(HEADER_CF_NAME)?;
        Ok(self.db.put_cf(&cf, key, val)?)
    }

    pub fn delete_header(&self, key: &[u8]) -> Result<(), CoreDBError> {
        let cf = self.cf_handle(HEADER_CF_NAME)?;
        Ok(self.db.delete_cf(&cf, key)?)
    }

    // --- Batch operation
    pub fn commit_write_batch(&self, batch: WriteBatch) -> Result<(), CoreDBError> {
        let write_opts = WriteOptions::default();
        Ok(self.db.write_opt(batch, &write_opts)?)
    }
}
