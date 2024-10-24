use rjam_common::Octets;
use rocksdb::{Options, WriteBatch, WriteOptions, DB};
use std::{path::PathBuf, sync::Arc};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StateDBError {
    #[error("RocksDB error: {0}")]
    RocksDBError(String),
}

pub enum DBWriteOp<'a> {
    Put(&'a [u8], Octets), // key, value
    Delete(&'a [u8]),      // key
}

// DB configs
pub struct RocksDBConfig {
    pub path: PathBuf,
    pub create_if_missing: bool,
    pub max_open_files: i32,
    pub write_buffer_size: usize,
    pub max_write_buffer_number: i32,
}

impl Default for RocksDBConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("./rocksdb"),
            create_if_missing: true,
            max_open_files: 1000,
            write_buffer_size: 64 * 1024 * 1024, // 64MB
            max_write_buffer_number: 2,
        }
    }
}
pub struct StateDB {
    db: Arc<DB>,
}
// APIs required: new, open, put, get, delete, commit (batch-write)
// stateManager
impl StateDB {
    pub fn open(config: RocksDBConfig) -> Result<Self, StateDBError> {
        let mut opts = Options::default();
        opts.create_if_missing(config.create_if_missing);
        opts.set_max_open_files(config.max_open_files);
        opts.set_write_buffer_size(config.write_buffer_size);
        opts.set_max_write_buffer_number(config.max_write_buffer_number);

        let db =
            DB::open(&opts, &config.path).map_err(|e| StateDBError::RocksDBError(e.to_string()))?;
        Ok(StateDB { db: Arc::new(db) })
    }

    fn get_db(&self) -> Arc<DB> {
        Arc::clone(&self.db)
    }

    pub fn get_entry(&self, key: &[u8]) -> Result<Option<Octets>, StateDBError> {
        let db = self.get_db();
        db.get(key)
            .map_err(|e| StateDBError::RocksDBError(e.to_string()))
    }

    #[allow(dead_code)]
    fn put_entry(&self, key: &[u8], value: &[u8]) -> Result<(), StateDBError> {
        let db = self.get_db();
        db.put(key, value)
            .map_err(|e| StateDBError::RocksDBError(e.to_string()))
    }

    #[allow(dead_code)]
    fn delete_entry(&self, key: &[u8]) -> Result<(), StateDBError> {
        let db = self.get_db();
        db.delete(key)
            .map_err(|e| StateDBError::RocksDBError(e.to_string()))
    }

    pub fn commit(&self, changes: &[DBWriteOp]) -> Result<(), StateDBError> {
        let db = self.get_db();
        let mut batch = WriteBatch::default();
        let write_opts = WriteOptions::default();

        for change in changes {
            match change {
                DBWriteOp::Put(key, value) => batch.put(*key, value),
                DBWriteOp::Delete(key) => batch.delete(*key),
            }
        }

        db.write_opt(batch, &write_opts)
            .map_err(|e| StateDBError::RocksDBError(e.to_string()))
    }

    pub fn batch_operation<F>(&self, operations: F) -> Result<(), StateDBError>
    where
        F: FnOnce(&mut WriteBatch),
    {
        let mut batch = WriteBatch::default();
        operations(&mut batch);
        self.db
            .write(batch)
            .map_err(|e| StateDBError::RocksDBError(e.to_string()))
    }

    pub fn write_without_wal(&self, key: &[u8], value: &[u8]) -> Result<(), StateDBError> {
        let mut write_opts = WriteOptions::default();
        write_opts.disable_wal(true);
        self.db
            .put_opt(key, value, &write_opts)
            .map_err(|e| StateDBError::RocksDBError(e.to_string()))
    }
}
