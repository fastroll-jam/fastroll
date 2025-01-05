//! MerkleDB Integration Tests
#[cfg(test)]
mod tests {
    use crate::{StateManager, StateMut};
    use rjam_codec::JamDecode;
    use rjam_db::RocksDBConfig;
    use rjam_state_merkle::{
        codec::test_utils::simple_hash, merkle_db::MerkleDB, state_db::StateDB,
    };
    use rjam_types::{
        state::AuthPool,
        state_utils::{get_simple_state_key, StateEntryType, StateKeyConstant},
    };
    use tempfile::tempdir;

    fn init_merkle_db() -> MerkleDB {
        const MERKLE_DB_CACHE_SIZE: usize = 1000;
        MerkleDB::open(
            &RocksDBConfig::from_path(tempdir().unwrap().into_path().join("merkle_db")),
            MERKLE_DB_CACHE_SIZE,
        )
        .unwrap()
    }

    fn init_state_db() -> StateDB {
        StateDB::open(&RocksDBConfig::from_path(
            tempdir().unwrap().into_path().join("state_db"),
        ))
        .unwrap()
    }

    fn init_state_manager(state_db: StateDB, merkle_db: MerkleDB) -> StateManager {
        StateManager::new(state_db, merkle_db)
    }

    #[test]
    fn merkle_db_test() {
        let mut state_manager = init_state_manager(init_state_db(), init_merkle_db());
        println!("--- StateManager initialized.");

        // Prior state
        let mut auth_pool = AuthPool::default();
        auth_pool.0[0].push(simple_hash("00"));
        auth_pool.0[1].push(simple_hash("01"));

        // Load to the state manager as clean cache
        state_manager.load_state_for_test(
            StateKeyConstant::AuthPool,
            StateEntryType::AuthPool(auth_pool),
        );
        println!("--- Prior state loaded to the StateManager.");

        // Apply state mutation
        state_manager
            .with_mut_auth_pool(StateMut::Add, |_| {}) // Just add the entry
            .unwrap();

        println!("--- State Mutation Done.");

        // Commit to the DB
        let auth_pool_state_key = get_simple_state_key(StateKeyConstant::AuthPool);
        state_manager
            .commit_single_dirty_cache(&auth_pool_state_key)
            .unwrap();

        println!("--- DB Commit Done.");

        // Retrieve the entry from the DB (not gating the state cache)
        let state_data = state_manager
            .retrieve_state_encoded(&auth_pool_state_key)
            .unwrap()
            .unwrap();
        let auth_pool = AuthPool::decode(&mut state_data.as_slice()).unwrap();

        println!(">>> Retrieved AuthPool: {:?}", &auth_pool);
    }
}
