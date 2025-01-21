use rocksdb::{Options, WriteBatch, WriteOptions, DB};
use std::{path::PathBuf, sync::Arc};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeyValueDBError {
    #[error("RocksDB error: {0}")]
    RocksDBError(#[from] rocksdb::Error),
}

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

impl RocksDBConfig {
    pub fn from_path(path: PathBuf) -> Self {
        Self {
            path,
            ..Default::default()
        }
    }
}

pub struct KVDB {
    /// RocksDB instance.
    db: Arc<DB>,
}

impl KVDB {
    pub fn open(config: &RocksDBConfig) -> Result<Self, KeyValueDBError> {
        let mut opts = Options::default();
        opts.create_if_missing(config.create_if_missing);
        opts.set_max_open_files(config.max_open_files);
        opts.set_write_buffer_size(config.write_buffer_size);
        opts.set_max_write_buffer_number(config.max_write_buffer_number);

        let db = DB::open(&opts, &config.path).map_err(KeyValueDBError::RocksDBError)?;
        Ok(KVDB { db: Arc::new(db) })
    }

    pub fn get_entry(&self, key: &[u8]) -> Result<Option<Vec<u8>>, KeyValueDBError> {
        self.db.get(key).map_err(KeyValueDBError::RocksDBError)
    }

    pub fn put_entry(&self, key: &[u8], value: &[u8]) -> Result<(), KeyValueDBError> {
        self.db
            .put(key, value)
            .map_err(KeyValueDBError::RocksDBError)
    }

    pub fn delete_entry(&self, key: &[u8]) -> Result<(), KeyValueDBError> {
        self.db.delete(key).map_err(KeyValueDBError::RocksDBError)
    }

    pub fn commit_write_batch(&self, write_batch: WriteBatch) -> Result<(), KeyValueDBError> {
        let write_options = WriteOptions::default();
        self.db.write_opt(write_batch, &write_options)?;
        Ok(())
    }

    pub fn batch_operation<F>(&self, operations: F) -> Result<(), KeyValueDBError>
    where
        F: FnOnce(&mut WriteBatch),
    {
        let mut batch = WriteBatch::default();
        operations(&mut batch);
        self.db.write(batch).map_err(KeyValueDBError::RocksDBError)
    }

    pub fn write_without_wal(&self, key: &[u8], value: &[u8]) -> Result<(), KeyValueDBError> {
        let mut write_opts = WriteOptions::default();
        write_opts.disable_wal(true);
        self.db
            .put_opt(key, value, &write_opts)
            .map_err(KeyValueDBError::RocksDBError)
    }
}
