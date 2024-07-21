use dotenv::dotenv;
use lazy_static::lazy_static;
use rocksdb::{Options, DB as RocksDB};
use std::{
    env,
    sync::{Arc, Mutex},
};

// Key-Value database representation

// Placeholder for the key-value database
pub(crate) trait KeyValueDB: Sync + Send {
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), String>;
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, String>;
}

struct DB {
    inner: Arc<dyn KeyValueDB>,
}

impl DB {
    fn new(inner: Arc<dyn KeyValueDB>) -> Self {
        DB { inner }
    }
}

impl KeyValueDB for DB {
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), String> {
        self.inner.put(key, value)
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        self.inner.get(key)
    }
}

// Wrapper around RocksDB to implement KeyValueDB
struct RocksDBWrapper {
    db: RocksDB,
}

impl RocksDBWrapper {
    fn new(path: &str) -> Self {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = RocksDB::open(&opts, path).expect("Failed to open RocksDB");
        RocksDBWrapper { db }
    }
}

impl KeyValueDB for RocksDBWrapper {
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), String> {
        self.db.put(key, value).map_err(|e| e.to_string())
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        self.db.get(key).map_err(|e| e.to_string())
    }
}

// Global state manager for the KVDB instance
pub struct GlobalStateManager {
    db: Arc<dyn KeyValueDB>,
}

impl GlobalStateManager {
    fn new(db: Arc<dyn KeyValueDB>) -> Self {
        GlobalStateManager { db }
    }

    pub(crate) fn get_db(&self) -> Arc<dyn KeyValueDB> {
        Arc::clone(&self.db)
    }

    // TODO: state retrieval / update functions here
}

// Lazy initialization for a Singleton access to the DB instance
lazy_static! {
    pub static ref GLOBAL_STATE_MANAGER: Mutex<GlobalStateManager> = {
        dotenv().ok();
        let db_path = env::var("ROCKSDB_PATH").expect("ROCKSDB_PATH must be set correctly");

        Mutex::new(GlobalStateManager::new(Arc::new(RocksDBWrapper::new(
            &db_path,
        ))))
    };
}
