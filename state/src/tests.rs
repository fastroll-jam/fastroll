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
        state::{AuthPool, PendingReport, PendingReports},
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

        // --- 1. Add one state entry, initializing the Merkle Trie
        println!("1. Add the first state entry.");
        let mut auth_pool = AuthPool::default();
        auth_pool.0[0].push(simple_hash("00"));
        auth_pool.0[1].push(simple_hash("01"));

        // Load to the state manager as clean cache
        state_manager.load_state_for_test(
            StateKeyConstant::AuthPool,
            StateEntryType::AuthPool(auth_pool),
        );

        // Apply state mutation
        state_manager
            .with_mut_auth_pool(StateMut::Add, |_| {}) // Just add the entry
            .unwrap();

        // Commit to the DB
        let auth_pool_state_key = get_simple_state_key(StateKeyConstant::AuthPool);
        state_manager
            .commit_single_dirty_cache(&auth_pool_state_key)
            .unwrap();
        println!(
            "--- DB Commit Done. Merkle Root: {}",
            state_manager.merkle_root()
        );

        // Retrieve the entry from the DB (not gating the state cache)
        let auth_pool_state_data = state_manager
            .retrieve_state_encoded(&auth_pool_state_key)
            .unwrap()
            .unwrap();
        let auth_pool = AuthPool::decode(&mut auth_pool_state_data.as_slice()).unwrap();
        println!("\nState Retrieved: {}", &auth_pool);

        // --- 2. Add another state entry
        println!("\n\n\n2. Add another state entry.");
        let mut pending_reports = PendingReports::default();
        pending_reports.0[0] = Some(PendingReport::default());
        pending_reports.0[1] = Some(PendingReport::default());

        state_manager.load_state_for_test(
            StateKeyConstant::PendingReports,
            StateEntryType::PendingReports(pending_reports),
        );

        state_manager
            .with_mut_pending_reports(StateMut::Add, |_| {}) // Just add the entry
            .unwrap();

        let pending_reports_state_key = get_simple_state_key(StateKeyConstant::PendingReports);

        state_manager
            .commit_single_dirty_cache(&pending_reports_state_key)
            .unwrap();
        println!(
            "--- DB Commit Done. Merkle Root: {}",
            state_manager.merkle_root()
        );

        // Retrieve the entry from the DB (not gating the state cache)
        let auth_pool_state_data = state_manager
            .retrieve_state_encoded(&auth_pool_state_key)
            .unwrap()
            .unwrap();

        let pending_reports_state_data = state_manager
            .retrieve_state_encoded(&pending_reports_state_key)
            .unwrap()
            .unwrap();

        let auth_pool = AuthPool::decode(&mut auth_pool_state_data.as_slice()).unwrap();
        let pending_reports =
            PendingReports::decode(&mut pending_reports_state_data.as_slice()).unwrap();

        println!("\nState Retrieved: {}", &auth_pool);
        println!("\nState Retrieved: {}", &pending_reports);

        // --- 3. Update state entry
        println!("\n\n\n3. Update state entry.");
        state_manager
            .with_mut_auth_pool(StateMut::Update, |pool| {
                pool.0[1].push(simple_hash("02"));
            })
            .unwrap();
        state_manager
            .commit_single_dirty_cache(&auth_pool_state_key)
            .unwrap();
        println!(
            "--- DB Commit Done. Merkle Root: {}",
            state_manager.merkle_root()
        );

        let auth_pool_state_data = state_manager
            .retrieve_state_encoded(&auth_pool_state_key)
            .unwrap()
            .unwrap();
        let auth_pool = AuthPool::decode(&mut auth_pool_state_data.as_slice()).unwrap();
        println!("\nState Retrieved: {}", &auth_pool);

        // --- 4. Remove state entry
        println!("\n\n\n4. Remove state entry.");
        state_manager
            .with_mut_auth_pool(StateMut::Remove, |_| {})
            .unwrap();
        state_manager
            .commit_single_dirty_cache(&auth_pool_state_key)
            .unwrap();
        // FIXME: When there is the only state entry in the merkle trie, the leaf must be promoted to the root.
        println!(
            "--- DB Commit Done. Merkle Root: {}",
            state_manager.merkle_root()
        );
        let auth_pool_state_data = state_manager
            .retrieve_state_encoded(&auth_pool_state_key)
            .unwrap()
            .unwrap();
        let auth_pool = AuthPool::decode(&mut auth_pool_state_data.as_slice()).unwrap();
        println!("\nState Retrieved: {}", &auth_pool);
    }
}
