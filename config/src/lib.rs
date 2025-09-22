#![allow(dead_code)]
use fr_db::{ColumnFamilyDescriptor, RocksDBOptions};
use std::path::PathBuf;

// --- Default values
pub const DEFAULT_ROCKSDB_PATH: &str = "./.rocksdb";
pub const DEFAULT_FUZZER_SOCKET: &str = "/tmp/jam_target.sock";

pub const STATE_CF_NAME: &str = "state_cf";
pub const MERKLE_CF_NAME: &str = "merkle_cf";
pub const MERKLE_LEAF_CF_NAME: &str = "merkle_leaf_cf";
pub const HEADER_CF_NAME: &str = "header_cf";
pub const XT_CF_NAME: &str = "xt_cf";
pub const POST_SR_CF_NAME: &str = "post_state_root_cf";

pub const STATE_DB_CACHE_SIZE: usize = 8192;
pub const MERKLE_DB_CACHE_SIZE: usize = 8192;
pub const HEADER_DB_CACHE_SIZE: usize = 1024;
pub const XT_DB_CACHE_SIZE: usize = 1024;
pub const POST_SR_DB_CACHE_SIZE: usize = 1024;

pub const STATE_CACHE_SIZE: usize = 8192;

pub struct ColumnFamilyConfig {
    pub cf_name: &'static str,
    pub cache_size: usize,
}

impl ColumnFamilyConfig {
    fn new(cf_name: &'static str, cache_size: usize) -> Self {
        Self {
            cf_name,
            cache_size,
        }
    }
}

pub struct ColumnFamilyConfigs {
    pub state_db: ColumnFamilyConfig,
    pub merkle_db: ColumnFamilyConfig,
    pub header_db: ColumnFamilyConfig,
    pub xt_db: ColumnFamilyConfig,
    pub post_state_root_db: ColumnFamilyConfig,
}

impl Default for ColumnFamilyConfigs {
    fn default() -> Self {
        Self {
            state_db: ColumnFamilyConfig::new(STATE_CF_NAME, STATE_DB_CACHE_SIZE),
            merkle_db: ColumnFamilyConfig::new(MERKLE_CF_NAME, MERKLE_DB_CACHE_SIZE),
            header_db: ColumnFamilyConfig::new(HEADER_CF_NAME, HEADER_DB_CACHE_SIZE),
            xt_db: ColumnFamilyConfig::new(XT_CF_NAME, XT_DB_CACHE_SIZE),
            post_state_root_db: ColumnFamilyConfig::new(POST_SR_CF_NAME, POST_SR_DB_CACHE_SIZE),
        }
    }
}

pub struct StorageConfig {
    /// CoreDB path
    pub path: PathBuf,
    /// Column family-level options (CachedDB)
    pub cfs: ColumnFamilyConfigs,
    /// Size of `StateCache` of `StateManager`
    pub state_cache_size: usize,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("./.rocksdb"),
            cfs: ColumnFamilyConfigs::default(),
            state_cache_size: STATE_CACHE_SIZE,
        }
    }
}

impl StorageConfig {
    pub fn from_path(path: PathBuf) -> Self {
        Self {
            path,
            ..Default::default()
        }
    }

    pub fn from_node_id(node_id: &str, db_path: &str) -> Self {
        Self {
            path: PathBuf::from(format!("{db_path}/{node_id}")),
            ..Default::default()
        }
    }

    /// Database-level options
    pub fn rocksdb_opts() -> RocksDBOptions {
        // Default Database-level options
        let mut opts = RocksDBOptions::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts
    }

    pub fn cf_descriptors() -> Vec<ColumnFamilyDescriptor> {
        vec![
            ColumnFamilyDescriptor::new(STATE_CF_NAME, RocksDBOptions::default()),
            ColumnFamilyDescriptor::new(MERKLE_CF_NAME, RocksDBOptions::default()),
            ColumnFamilyDescriptor::new(MERKLE_LEAF_CF_NAME, RocksDBOptions::default()),
            ColumnFamilyDescriptor::new(HEADER_CF_NAME, RocksDBOptions::default()),
            ColumnFamilyDescriptor::new(XT_CF_NAME, RocksDBOptions::default()),
            ColumnFamilyDescriptor::new(POST_SR_CF_NAME, RocksDBOptions::default()),
        ]
    }
}

pub struct NodeConfig {
    pub storage: StorageConfig,
}

impl NodeConfig {
    pub fn from_node_id(node_id: &str, db_path: &str) -> Self {
        Self {
            storage: StorageConfig::from_node_id(node_id, db_path),
        }
    }
}
