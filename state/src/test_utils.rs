use crate::{cache::StateCache, manager::StateManager, state_db::StateDB};
use fr_block::header_db::BlockHeaderDB;
use fr_config::{
    StorageConfig, HEADER_CF_NAME, HEADER_DB_CACHE_SIZE, MERKLE_LEAF_PATHS_CF_NAME,
    MERKLE_LEAF_PATHS_DB_CACHE_SIZE, MERKLE_NODES_CF_NAME, MERKLE_NODES_DB_CACHE_SIZE,
    STATE_CACHE_SIZE, STATE_CF_NAME, STATE_DB_CACHE_SIZE,
};
use fr_db::core::core_db::CoreDB;
use fr_state_merkle_v2::merkle_db::MerkleDB;
use std::sync::Arc;
use tempfile::tempdir;

fn init_core_db() -> CoreDB {
    let db_path = tempdir().unwrap().path().join("test_db");
    CoreDB::open(
        db_path,
        StorageConfig::rocksdb_opts(),
        StorageConfig::cf_descriptors(),
    )
    .unwrap()
}

fn init_header_db(core_db: Arc<CoreDB>) -> BlockHeaderDB {
    BlockHeaderDB::new(core_db, HEADER_CF_NAME, HEADER_DB_CACHE_SIZE)
}

fn init_state_manager(core_db: Arc<CoreDB>) -> StateManager {
    let state_db = StateDB::new(core_db.clone(), STATE_CF_NAME, STATE_DB_CACHE_SIZE);
    let state_cache = StateCache::new(STATE_CACHE_SIZE);
    let merkle_db: MerkleDB = MerkleDB::new(
        core_db,
        MERKLE_NODES_CF_NAME,
        MERKLE_LEAF_PATHS_CF_NAME,
        MERKLE_NODES_DB_CACHE_SIZE,
        MERKLE_LEAF_PATHS_DB_CACHE_SIZE,
    );
    StateManager::new(state_db, merkle_db, state_cache)
}

pub fn init_db_and_manager() -> (BlockHeaderDB, StateManager) {
    let core_db = Arc::new(init_core_db());
    (
        init_header_db(core_db.clone()),
        init_state_manager(core_db.clone()),
    )
}
