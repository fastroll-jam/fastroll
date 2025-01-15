use crate::StateManager;
use rjam_db::RocksDBConfig;
use rjam_state_merkle::{merkle_db::MerkleDB, state_db::StateDB};
use tempfile::tempdir;

pub fn init_merkle_db() -> MerkleDB {
    const MERKLE_DB_CACHE_SIZE: usize = 1000;
    MerkleDB::open(
        &RocksDBConfig::from_path(tempdir().unwrap().into_path().join("merkle_db")),
        MERKLE_DB_CACHE_SIZE,
    )
    .unwrap()
}

pub fn init_state_db() -> StateDB {
    StateDB::open(&RocksDBConfig::from_path(
        tempdir().unwrap().into_path().join("state_db"),
    ))
    .unwrap()
}

pub fn init_state_manager(state_db: StateDB, merkle_db: MerkleDB) -> StateManager {
    StateManager::new(state_db, merkle_db)
}
