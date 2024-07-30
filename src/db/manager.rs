use crate::{
    common::{Hash32, Octets},
    crypto::utils::blake2b_256,
    db::wrappers::{KeyValueDB, RocksDBWrapper},
    trie::utils::MerklizationError,
};
use dotenv::dotenv;
use lazy_static::lazy_static;
use std::{
    env,
    sync::{Arc, Mutex},
};

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
    pub(crate) fn store_node(
        &self,
        hash: &Hash32,
        serialized_node: &[u8],
    ) -> Result<(), MerklizationError> {
        let db = self.get_db();
        db.put(hash, serialized_node)
            .map_err(|_| MerklizationError::StoreNodeError)
    }

    // Store data that leaf nodes point to
    pub(crate) fn store_data(&self, data: &[u8]) -> Result<Hash32, MerklizationError> {
        let db = self.get_db();
        let data_hash = blake2b_256(data)?;
        db.put(&data_hash, data)
            .map_err(|_| MerklizationError::StoreNodeError)?;
        Ok(data_hash)
    }

    // Get serialized node data in Octets form
    pub(crate) fn get_node(&self, hash: &Hash32) -> Result<Octets, MerklizationError> {
        let db = self.get_db();
        db.get(hash)
            .map_err(|_| MerklizationError::GetNodeError)
            .and_then(|opt| opt.ok_or(MerklizationError::NodeNotFound))
    }
}
