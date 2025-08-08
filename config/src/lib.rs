#![allow(dead_code)]
use fr_db::{ColumnFamilyDescriptor, RocksDBOptions};
use std::path::PathBuf;

// --- Default values
const STATE_CF_NAME: &str = "state_cf";
const MERKLE_CF_NAME: &str = "merkle_cf";
const HEADER_CF_NAME: &str = "header_cf";
const XT_CF_NAME: &str = "xt_cf";
const POST_SR_CF_NAME: &str = "post_state_root_cf";

const STATE_DB_CACHE_SIZE: usize = 8192;
const MERKLE_DB_CACHE_SIZE: usize = 8192;
const HEADER_DB_CACHE_SIZE: usize = 1024;
const XT_DB_CACHE_SIZE: usize = 1024;
const POST_SR_DB_CACHE_SIZE: usize = 1024;

const STATE_CACHE_SIZE: usize = 8192;

struct ColumnFamilyConfig {
    cf_name: &'static str,
    cf_opts: RocksDBOptions,
}

impl ColumnFamilyConfig {
    fn new(cf_name: &'static str) -> Self {
        Self {
            cf_name,
            cf_opts: RocksDBOptions::default(), // TODO: configure
        }
    }

    fn cf_descriptor(self) -> ColumnFamilyDescriptor {
        ColumnFamilyDescriptor::new(self.cf_name, self.cf_opts)
    }
}

struct CachedDBConfig {
    cf_config: ColumnFamilyConfig,
    cache_size: usize,
}

impl CachedDBConfig {
    fn new(cf_config: ColumnFamilyConfig, cache_size: usize) -> Self {
        Self {
            cf_config,
            cache_size,
        }
    }
}

// TODO: load from config files
struct CachedDBConfigs {
    state_db: CachedDBConfig,
    merkle_db: CachedDBConfig,
    header_db: CachedDBConfig,
    xt_db: CachedDBConfig,
    post_state_root_db: CachedDBConfig,
}

impl Default for CachedDBConfigs {
    fn default() -> Self {
        Self {
            state_db: CachedDBConfig::new(
                ColumnFamilyConfig::new(STATE_CF_NAME),
                STATE_DB_CACHE_SIZE,
            ),
            merkle_db: CachedDBConfig::new(
                ColumnFamilyConfig::new(MERKLE_CF_NAME),
                MERKLE_DB_CACHE_SIZE,
            ),
            header_db: CachedDBConfig::new(
                ColumnFamilyConfig::new(HEADER_CF_NAME),
                HEADER_DB_CACHE_SIZE,
            ),
            xt_db: CachedDBConfig::new(ColumnFamilyConfig::new(XT_CF_NAME), XT_DB_CACHE_SIZE),
            post_state_root_db: CachedDBConfig::new(
                ColumnFamilyConfig::new(POST_SR_CF_NAME),
                POST_SR_DB_CACHE_SIZE,
            ),
        }
    }
}

struct StorageConfig {
    /// CoreDB path
    path: PathBuf,
    /// Database-level options
    opts: RocksDBOptions,
    /// Column family-level options (CachedDB)
    cfs: CachedDBConfigs,
}

impl StorageConfig {
    fn from_node_id(node_id: &str) -> Self {
        // TODO: configure
        // Default Database-level options
        let mut opts = RocksDBOptions::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        Self {
            path: PathBuf::from(format!("./.rocksdb/{node_id}")),
            opts,
            cfs: CachedDBConfigs::default(),
        }
    }
}

pub struct NodeConfig {
    db: StorageConfig,
}

impl NodeConfig {
    pub fn from_node_id(node_id: &str) -> Self {
        Self {
            db: StorageConfig::from_node_id(node_id),
        }
    }
}
