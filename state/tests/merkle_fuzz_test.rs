//! MerkleDB Fuzz Tests
#![allow(unused_imports)]
use fr_codec::prelude::*;
use fr_common::utils::tracing::setup_timed_tracing;
use fr_state::test_utils::{init_db_and_manager, random_state_key, random_state_val};
use rand::{seq::SliceRandom, thread_rng};
use std::{collections::HashMap, error::Error};

#[tokio::test]
async fn test_merkle_fuzz() -> Result<(), Box<dyn Error>> {
    // Config tracing subscriber
    setup_timed_tracing();

    let (_, _, state_manager) = init_db_and_manager(None);

    // Test with n random state entries
    const N_DEFAULT: usize = 100;
    let n: usize = std::env::var("MERKLE_FUZZ_N")
        .unwrap_or(N_DEFAULT.to_string())
        .parse()
        .unwrap_or(N_DEFAULT);
    tracing::info!("--- Running fuzz test with n = {}", n);

    const MAX_VAL_SIZE: usize = 1000;

    // Generate random state entries
    let mut state_keys = Vec::with_capacity(n);
    let mut expected_state_values = Vec::with_capacity(n); // In-memory values

    // Add to the Cache
    for i in 0..n {
        tracing::debug!("Adding entry #{i}");
        let state_key = random_state_key();
        let state_val = random_state_val(MAX_VAL_SIZE);

        state_manager
            .add_raw_state_entry(&state_key, state_val.clone())
            .await?;

        state_keys.push(state_key);
        expected_state_values.push(state_val);
    }

    // Commit Additions
    state_manager.commit_dirty_cache().await?;
    tracing::info!("--- Committed to the DB: Add");

    // Verify the Additions
    for i in 0..n {
        tracing::debug!("Verifying added entry #{i}");
        let raw_state_val_db = state_manager
            .get_raw_state_entry_from_db(&state_keys[i])
            .await?
            .expect("should not be None");
        let state_val_expected = expected_state_values[i].clone();

        assert_eq!(raw_state_val_db, state_val_expected);
    }
    tracing::info!("--- Verified Additions");

    // State Mutation: 33% Updates, 20% Removals
    let num_updates = n / 3;
    let num_removes = n / 5;

    // Shuffle the keys
    let mut indices: Vec<usize> = (0..n).collect();
    indices.shuffle(&mut thread_rng());

    // State Mutation (Update)
    let update_indices = &indices[0..num_updates];
    let mut updated_values = HashMap::new();

    for i in update_indices {
        tracing::debug!("Updating entry #{i}");
        let key = &state_keys[*i];
        let new_val = random_state_val(MAX_VAL_SIZE);
        state_manager
            .update_raw_state_entry(key, new_val.clone())
            .await?;
        updated_values.insert(key, new_val);
    }

    // State Mutation (Remove)
    let remove_indices = &indices[num_updates..(num_updates + num_removes)];
    let mut removed_keys = Vec::with_capacity(num_removes);

    for i in remove_indices {
        tracing::debug!("Removing entry #{i}");
        let key = &state_keys[*i];
        state_manager.remove_raw_state_entry(key).await?;
        removed_keys.push(key);
    }

    // Commit Updates and Removals
    state_manager.commit_dirty_cache().await?;

    tracing::info!("--- Committed to the DB: Update/Remove");

    // Verify the Updates
    for (key, val_expected) in updated_values {
        tracing::debug!("Verifying updated entry with key {key}");
        let raw_state_val_db = state_manager
            .get_raw_state_entry_from_db(key)
            .await?
            .expect("updated key must still exist");
        assert_eq!(raw_state_val_db, val_expected);
    }
    tracing::info!("--- Verified Updates");

    // Verify the Removals
    for key in removed_keys {
        tracing::debug!("Verifying removed entry with key {key}");
        let maybe_state_val = state_manager.get_raw_state_entry_from_db(key).await?;
        assert!(
            maybe_state_val.is_none(),
            "Removed key ({key}) still found in DB"
        );
    }
    tracing::info!("--- Verified Removed keys");

    // Verify the unchanged entries
    let unchanged_keys = indices[(num_updates + num_removes)..].to_vec();
    for i in unchanged_keys {
        let key = &state_keys[i];
        let raw_state_val_db = state_manager
            .get_raw_state_entry_from_db(key)
            .await?
            .expect("unchanged key should exist");
        assert_eq!(raw_state_val_db, expected_state_values[i]);
    }
    tracing::info!("--- Verified Unchanged entries");

    Ok(())
}
