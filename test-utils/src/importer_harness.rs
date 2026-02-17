use crate::state_display::display_state_entry;
use fr_block::types::block::{Block, BlockHeader};
use fr_codec::prelude::*;
#[cfg(not(feature = "flamegraph"))]
use fr_common::utils::tracing::setup_timed_tracing;
#[cfg(feature = "flamegraph")]
use fr_common::utils::tracing::setup_timed_tracing_with_flamegraph;
use fr_common::{utils::serde::FileReader, ByteSequence, StateKey, StateRoot};
use fr_config::StorageConfig;
use fr_node::roles::importer::{BlockCommitMode, BlockImporter};
use fr_state::{
    manager::StateManager,
    state_utils::{add_all_simple_state_entries, get_simple_state_key, StateKeyConstant},
    types::Timeslot,
};
use fr_storage::node_storage::NodeStorage;
use fr_transition::state::services::AccountStateChanges;
use std::{
    collections::HashMap,
    error::Error,
    path::{Path, PathBuf},
    sync::Arc,
};
use tempfile::tempdir;
use tracing::{info_span, instrument};

// --- FastRoll Types
#[derive(Clone, Debug, JamEncode, JamDecode)]
pub struct RawState {
    pub state_root: StateRoot,
    pub keyvals: Vec<KeyValue>,
}

#[derive(Clone, Debug, JamEncode, JamDecode)]
pub struct KeyValue {
    pub key: StateKey,
    pub value: ByteSequence,
}

#[derive(Clone, Debug, JamEncode, JamDecode)]
pub struct TestCase {
    pub pre_state: RawState,
    pub block: Block,
    pub post_state: RawState,
}

#[derive(Clone, Debug, JamEncode, JamDecode)]
pub struct GenesisBlockTestCase {
    pub header: BlockHeader,
    pub state: RawState,
}

// --- Test Harness

/// Prints a human-readable diff of expected vs actual raw state entries.
/// Timeslot mismatch is handled specially to avoid noisy output.
pub fn print_state_diff(expected_post_state: &RawState, actual_state: &HashMap<StateKey, Vec<u8>>) {
    let timeslot_state_key = get_simple_state_key(StateKeyConstant::Timeslot);
    let expected_timeslot = expected_post_state
        .keyvals
        .iter()
        .find(|kv| kv.key == timeslot_state_key)
        .map(|kv| kv.value.as_slice());
    let actual_timeslot = actual_state
        .get(&timeslot_state_key)
        .map(|val| val.as_slice());

    match (actual_timeslot, expected_timeslot) {
        (Some(actual_timeslot), Some(expected_timeslot)) => {
            if actual_timeslot != expected_timeslot {
                tracing::error!("Timeslot mismatch.");
                let mut actual_slice = actual_timeslot;
                let mut expected_slice = expected_timeslot;
                println!("Actual: {:?}", Timeslot::decode(&mut actual_slice).unwrap());
                println!(
                    "Expected: {:?}",
                    Timeslot::decode(&mut expected_slice).unwrap()
                );
                return;
            }
        }
        (None, Some(_)) => {
            tracing::warn!(
                "Raw state entry not found. Key: {}",
                timeslot_state_key.encode_hex()
            );
        }
        (Some(_), None) => {
            tracing::warn!(
                "Expected state entry not found. Key: {}",
                timeslot_state_key.encode_hex()
            );
        }
        (None, None) => {}
    }

    for kv in &expected_post_state.keyvals {
        if let Some(actual_val) = actual_state.get(&kv.key) {
            if actual_val.as_slice() != kv.value.as_slice() {
                tracing::error!("State mismatch. Key: {}", kv.key);
                println!("Actual:");
                display_state_entry(kv.key.as_ref(), actual_val.as_slice());
                println!("\nExpected:");
                display_state_entry(kv.key.as_ref(), kv.value.as_slice());
                println!("\n");
            }
        } else {
            tracing::warn!("Raw state entry not found. Key: {}", kv.key.encode_hex());
        }
    }
}

/// A test harness for simple, linear block sequence import with no forks.
/// For more complex test scenarios involving simple forks ("fuzzy blocks"),
/// use the fuzz protocol via unix socket.
pub struct BlockImportHarness;
impl BlockImportHarness {
    fn resolve_bin_trace_path(file_path: &Path) -> PathBuf {
        if file_path.extension().and_then(|ext| ext.to_str()) == Some("bin") {
            file_path.to_path_buf()
        } else {
            file_path.with_extension("bin")
        }
    }

    pub fn load_test_case(file_path: &Path) -> TestCase {
        let bin_path = Self::resolve_bin_trace_path(file_path);
        let bytes = FileReader::read_bytes(&bin_path).expect("Failed to read test case .bin");
        TestCase::decode(&mut bytes.as_slice()).expect("Failed to decode test case from .bin")
    }

    pub fn load_genesis_test_case(file_path: &Path) -> GenesisBlockTestCase {
        let bin_path = Self::resolve_bin_trace_path(file_path);
        let bytes = FileReader::read_bytes(&bin_path).expect("Failed to read genesis .bin");
        GenesisBlockTestCase::decode(&mut bytes.as_slice())
            .expect("Failed to decode genesis test case from .bin")
    }

    pub fn init_node_storage(db_path: PathBuf) -> NodeStorage {
        NodeStorage::new(StorageConfig::from_path(db_path))
            .expect("Failed to initialize NodeStorage with tempdir")
    }

    pub async fn commit_pre_state(
        state_manager: &StateManager,
        pre_state: RawState,
    ) -> Result<(), Box<dyn Error>> {
        for kv in pre_state.keyvals {
            state_manager
                .add_raw_state_entry(&kv.key, kv.value.into_vec())
                .await?;
        }
        state_manager.commit_dirty_cache().await?;
        tracing::debug!("Pre-state committed.");
        Ok(())
    }

    #[instrument(level = "info", skip_all, name = "import")]
    async fn import_block(
        storage: Arc<NodeStorage>,
        block: Block,
    ) -> Result<(StateRoot, AccountStateChanges), Box<dyn Error>> {
        let output =
            BlockImporter::import_block(storage, block, false, BlockCommitMode::Immediate).await?;
        Ok((output.post_state_root, output.account_state_changes))
    }

    async fn _extract_post_state() -> Result<RawState, Box<dyn Error>> {
        // TODO: Check if enumerating on all state entries would be effective
        unimplemented!()
    }

    #[instrument(level = "info", skip_all)]
    async fn assert_post_state(
        state_manager: &StateManager,
        actual_post_state_root: StateRoot,
        expected_post_state: RawState,
    ) {
        let mut actual_state = HashMap::new();
        for kv in &expected_post_state.keyvals {
            if let Some(actual_val) = state_manager.get_raw_state_entry(&kv.key).await.unwrap() {
                actual_state.insert(kv.key.clone(), actual_val);
            }
        }
        print_state_diff(&expected_post_state, &actual_state);
        assert_eq!(
            hex::encode(&actual_post_state_root),
            hex::encode(&expected_post_state.state_root)
        );
    }
}

pub async fn run_test_case(file_path: &str) -> Result<(), Box<dyn Error>> {
    // Config tracing subscriber
    #[cfg(feature = "flamegraph")]
    setup_timed_tracing_with_flamegraph(file_path);
    #[cfg(not(feature = "flamegraph"))]
    setup_timed_tracing();

    // TempDir guard
    let _temp_dir = tempdir().expect("Failed to create temporary directory for test");

    let (storage, test_case) = {
        let span = info_span!("init_test");
        let _e = span.enter();

        // load test case
        let test_case = BlockImportHarness::load_test_case(&PathBuf::from(file_path));

        // init node storage
        let temp_db_path = _temp_dir.path().join("importer_db");
        let storage = Arc::new(BlockImportHarness::init_node_storage(temp_db_path));

        // initialize state keys if genesis block
        if test_case.block.is_genesis() {
            add_all_simple_state_entries(&storage.state_manager(), None).await?;
        }

        BlockImportHarness::commit_pre_state(&storage.state_manager(), test_case.pre_state.clone())
            .await?;

        if !test_case.block.is_genesis() {
            // Workaround: Import parent block from the previous test case and then set it as best header.
            let parent_header = get_parent_block_header(file_path);
            let parent_header_hash = parent_header.hash()?;
            storage.header_db().set_best_header(parent_header);

            // Set post state root of the parent block (prior state root)
            storage
                .post_state_root_db()
                .set_post_state_root(
                    &parent_header_hash,
                    test_case.block.header.parent_state_root().clone(),
                )
                .await?;
        }
        (storage, test_case)
    };

    // import block
    let post_state_root =
        match BlockImportHarness::import_block(storage.clone(), test_case.block.clone()).await {
            Ok((post_state_root, _account_state_changes)) => post_state_root,
            Err(e) => {
                tracing::warn!("Invalid block: {e:?}");
                // If the block is invalid, return the latest committed state root.
                // Here, returning state root of `pre_state` of the test file for convenience.
                test_case.pre_state.state_root.clone()
            }
        };

    // assertions
    BlockImportHarness::assert_post_state(
        &storage.state_manager(),
        post_state_root,
        test_case.post_state,
    )
    .await;

    Ok(())
}

pub fn get_parent_block_header(file_path: &str) -> BlockHeader {
    let current_path = BlockImportHarness::resolve_bin_trace_path(&PathBuf::from(file_path));
    let stem = current_path
        .file_stem()
        .and_then(|s| s.to_str())
        .expect("Invalid trace filename");

    if stem == "00000001" {
        let genesis_block_file_path = current_path.with_file_name("genesis.bin");
        let genesis_block_test_case =
            BlockImportHarness::load_genesis_test_case(&genesis_block_file_path);
        genesis_block_test_case.header
    } else {
        let current_num: u64 = stem.parse().expect("Invalid numeric trace filename");
        let parent_num = current_num.saturating_sub(1);
        let parent_file = format!("{parent_num:0width$}.bin", width = stem.len());
        let parent_block_file_path = current_path.with_file_name(parent_file);
        let parent_block_test_case = BlockImportHarness::load_test_case(&parent_block_file_path);
        parent_block_test_case.block.header
    }
}
