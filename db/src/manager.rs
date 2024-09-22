use crate::wrappers::{KeyValueDB, RocksDBWrapper};
use dotenv::dotenv;
use lazy_static::lazy_static;
use rjam_common::{Hash32, Octets};
use rjam_crypto::utils::{blake2b_256, CryptoError};
use std::{
    env,
    sync::{Arc, Mutex},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KVDBError {
    #[error("CryptoError: {0}")]
    CryptoError(CryptoError),
    #[error("Node not found")]
    NodeNotFound,
    #[error("Failed to store node")]
    StoreNodeError,
    #[error("Failed to get node")]
    GetNodeError,
}

// Lazy initialization for a Singleton access to the DB instance
lazy_static! {
    pub static ref GLOBAL_KVDB_MANAGER: Mutex<KVDBManager> = {
        dotenv().ok();
        let db_path = env::var("ROCKSDB_PATH").expect("ROCKSDB_PATH must be set correctly");

        Mutex::new(KVDBManager::new(Arc::new(RocksDBWrapper::new(&db_path))))
    };
}

// Global KVDB manager
pub struct KVDBManager {
    db: Arc<dyn KeyValueDB>,
}

impl KVDBManager {
    fn new(db: Arc<dyn KeyValueDB>) -> Self {
        KVDBManager { db }
    }

    pub(crate) fn get_db(&self) -> Arc<dyn KeyValueDB> {
        Arc::clone(&self.db)
    }

    // Merkle trie representations
    // Store serialized branch & leaf nodes
    pub fn store_node(&self, hash: &Hash32, serialized_node: &[u8]) -> Result<(), KVDBError> {
        let db = self.get_db();
        db.put(hash, serialized_node)
            .map_err(|_| KVDBError::StoreNodeError)
    }

    // Store data that leaf nodes point to
    pub fn store_data(&self, data: &[u8]) -> Result<Hash32, KVDBError> {
        let db = self.get_db();
        let data_hash = blake2b_256(data).map_err(KVDBError::CryptoError)?;
        db.put(&data_hash, data)
            .map_err(|_| KVDBError::StoreNodeError)?;
        Ok(data_hash)
    }

    // Get serialized node data in Octets form
    pub fn get_node(&self, hash: &Hash32) -> Result<Octets, KVDBError> {
        let db = self.get_db();
        db.get(hash)
            .map_err(|_| KVDBError::GetNodeError)
            .and_then(|opt| opt.ok_or(KVDBError::NodeNotFound))
    }
}
