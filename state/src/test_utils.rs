use crate::{cache::StateCache, manager::StateManager, state_db::StateDB};
use fr_block::{
    header_db::BlockHeaderDB, post_state_root_db::PostStateRootDB, types::block::BlockHeader,
    xt_db::XtDB,
};
use fr_db::{
    config::{
        RocksDBOpts, HEADER_CF_NAME, MERKLE_CF_NAME, POST_STATE_ROOT_CF_NAME, STATE_CF_NAME,
        XT_CF_NAME,
    },
    core::core_db::CoreDB,
};
use fr_state_merkle::merkle_db::MerkleDB;
use std::sync::Arc;
use tempfile::tempdir;

fn init_core_db() -> CoreDB {
    let db_path = tempdir().unwrap().path().join("test_db");
    CoreDB::open(db_path, RocksDBOpts::default()).unwrap()
}

fn init_merkle_db(core_db: Arc<CoreDB>) -> MerkleDB {
    const MERKLE_DB_CACHE_SIZE: usize = 1024;
    MerkleDB::new(core_db, MERKLE_CF_NAME, MERKLE_DB_CACHE_SIZE)
}

fn init_state_db(core_db: Arc<CoreDB>) -> StateDB {
    const STATE_DB_CACHE_SIZE: usize = 1024;
    StateDB::new(core_db, STATE_CF_NAME, STATE_DB_CACHE_SIZE)
}

fn init_state_cache() -> StateCache {
    const STATE_CACHE_SIZE: usize = 4096;
    StateCache::new(STATE_CACHE_SIZE)
}

fn init_header_db(core_db: Arc<CoreDB>, best_header: Option<BlockHeader>) -> BlockHeaderDB {
    const HEADER_DB_CACHE_SIZE: usize = 1024;
    BlockHeaderDB::new(core_db, HEADER_CF_NAME, HEADER_DB_CACHE_SIZE, best_header)
}

fn init_xt_db(core_db: Arc<CoreDB>) -> XtDB {
    const XT_DB_CACHE_SIZE: usize = 1024;
    XtDB::new(core_db, XT_CF_NAME, XT_DB_CACHE_SIZE)
}

fn init_state_manager(core_db: Arc<CoreDB>) -> StateManager {
    let merkle_db = init_merkle_db(core_db.clone());
    let state_db = init_state_db(core_db);

    StateManager::new(state_db, merkle_db, init_state_cache())
}

fn init_post_state_root_db(core_db: Arc<CoreDB>) -> PostStateRootDB {
    const STATE_DB_CACHE_SIZE: usize = 1024;
    PostStateRootDB::new(core_db, POST_STATE_ROOT_CF_NAME, STATE_DB_CACHE_SIZE)
}

pub fn init_db_and_manager(
    best_header: Option<BlockHeader>,
) -> (BlockHeaderDB, XtDB, StateManager, PostStateRootDB) {
    let core_db = Arc::new(init_core_db());
    (
        init_header_db(core_db.clone(), best_header),
        init_xt_db(core_db.clone()),
        init_state_manager(core_db.clone()),
        init_post_state_root_db(core_db),
    )
}
