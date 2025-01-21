use rocksdb::{ColumnFamily, ColumnFamilyDescriptor, Options, WriteBatch, WriteOptions, DB};
use std::{path::Path, sync::Arc};
use thiserror::Error;

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
    db: Arc<DB>,
}

impl CoreDB {
    pub const STATE_CF_NAME: &'static str = "state_cf";
    pub const MERKLE_CF_NAME: &'static str = "merkle_cf";
    pub const HEADER_CF_NAME: &'static str = "header_cf";

    /// Opens or creates a RocksDB instance at the given `path` with column families.
    pub fn open<P: AsRef<Path>>(path: P, create_if_missing: bool) -> Result<Self, CoreDBError> {
        let mut opts = Options::default();
        opts.create_if_missing(create_if_missing);

        let cfs = vec![
            ColumnFamilyDescriptor::new(Self::STATE_CF_NAME, Options::default()),
            ColumnFamilyDescriptor::new(Self::MERKLE_CF_NAME, Options::default()),
            ColumnFamilyDescriptor::new(Self::HEADER_CF_NAME, Options::default()),
        ];

        // Open DB with the CF descriptors
        let db = DB::open_cf_descriptors(&opts, path, cfs)?;
        Ok(Self { db: Arc::new(db) })
    }

    fn cf_handle(&self, cf_name: &str) -> Result<&ColumnFamily, CoreDBError> {
        self.db
            .cf_handle(cf_name)
            .ok_or_else(|| CoreDBError::ColumnFamilyNotFound(cf_name.to_string()))
    }

    // --- State CF operations
    pub fn get_state(&self, key: &[u8]) -> Result<Option<Vec<u8>>, CoreDBError> {
        let cf = self.cf_handle(Self::STATE_CF_NAME)?;
        Ok(self.db.get_cf(cf, key)?)
    }

    pub fn put_state(&self, key: &[u8], val: &[u8]) -> Result<(), CoreDBError> {
        let cf = self.cf_handle(Self::STATE_CF_NAME)?;
        Ok(self.db.put_cf(cf, key, val)?)
    }

    pub fn delete_state(&self, key: &[u8]) -> Result<(), CoreDBError> {
        let cf = self.cf_handle(Self::STATE_CF_NAME)?;
        Ok(self.db.delete_cf(cf, key)?)
    }

    // --- Merkle CF operations
    pub fn get_merkle(&self, key: &[u8]) -> Result<Option<Vec<u8>>, CoreDBError> {
        let cf = self.cf_handle(Self::MERKLE_CF_NAME)?;
        Ok(self.db.get_cf(cf, key)?)
    }

    pub fn put_merkle(&self, key: &[u8], val: &[u8]) -> Result<(), CoreDBError> {
        let cf = self.cf_handle(Self::MERKLE_CF_NAME)?;
        Ok(self.db.put_cf(cf, key, val)?)
    }

    pub fn delete_merkle(&self, key: &[u8]) -> Result<(), CoreDBError> {
        let cf = self.cf_handle(Self::MERKLE_CF_NAME)?;
        Ok(self.db.delete_cf(cf, key)?)
    }

    // --- Header CF operations
    pub fn get_header(&self, key: &[u8]) -> Result<Option<Vec<u8>>, CoreDBError> {
        let cf = self.cf_handle(Self::HEADER_CF_NAME)?;
        Ok(self.db.get_cf(cf, key)?)
    }

    pub fn put_header(&self, key: &[u8], val: &[u8]) -> Result<(), CoreDBError> {
        let cf = self.cf_handle(Self::HEADER_CF_NAME)?;
        Ok(self.db.put_cf(cf, key, val)?)
    }

    pub fn delete_header(&self, key: &[u8]) -> Result<(), CoreDBError> {
        let cf = self.cf_handle(Self::HEADER_CF_NAME)?;
        Ok(self.db.delete_cf(cf, key)?)
    }

    // --- Batch operation
    pub fn commit_write_batch(&self, batch: WriteBatch) -> Result<(), CoreDBError> {
        let write_opts = WriteOptions::default();
        Ok(self.db.write_opt(batch, &write_opts)?)
    }
}
