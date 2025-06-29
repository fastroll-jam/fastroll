use fr_asn_types::types::common::{AsnBlock, AsnByteArray, AsnByteSequence, AsnOpaqueHash};
use fr_block::types::block::{Block, BlockHeader};
use fr_common::{utils::tracing::setup_timed_tracing, ByteSequence, StateKey, StateRoot};
use fr_node::roles::importer::BlockImporter;
use fr_state::{
    manager::StateManager,
    test_utils::{add_all_simple_state_entries, init_db_and_manager},
};
use fr_storage::node_storage::NodeStorage;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
// --- ASN Types

pub type AsnStateKey = AsnByteArray<31>;
pub type AsnStateRoot = AsnOpaqueHash;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnRawState {
    pub state_root: AsnStateRoot,
    pub keyvals: Vec<AsnKeyValue>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnKeyValue {
    pub key: AsnStateKey,
    pub value: AsnByteSequence,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AsnTestCase {
    pub pre_state: AsnRawState,
    pub block: AsnBlock,
    pub post_state: AsnRawState,
}

// --- FastRoll Types
pub struct RawState {
    pub state_root: StateRoot,
    pub keyvals: Vec<KeyValue>,
}

pub struct KeyValue {
    pub key: StateKey,
    pub value: ByteSequence,
}

pub struct TestCase {
    pub pre_state: RawState,
    pub block: Block,
    pub post_state: RawState,
}

// --- Type Conversion
impl From<KeyValue> for AsnKeyValue {
    fn from(kv: KeyValue) -> Self {
        Self {
            key: kv.key.into(),
            value: kv.value.into(),
        }
    }
}

impl From<AsnKeyValue> for KeyValue {
    fn from(kv: AsnKeyValue) -> Self {
        Self {
            key: kv.key.into(),
            value: kv.value.into(),
        }
    }
}

impl From<RawState> for AsnRawState {
    fn from(value: RawState) -> Self {
        Self {
            state_root: value.state_root.into(),
            keyvals: value.keyvals.into_iter().map(AsnKeyValue::from).collect(),
        }
    }
}

impl From<AsnRawState> for RawState {
    fn from(value: AsnRawState) -> Self {
        Self {
            state_root: value.state_root.into(),
            keyvals: value.keyvals.into_iter().map(KeyValue::from).collect(),
        }
    }
}

// --- Test Harness

struct BlockImportHarness;
impl BlockImportHarness {
    fn load_test_case(file_path: &Path) -> AsnTestCase {
        tracing::info!("file_path: {:?}", file_path);
        let json_str = fs::read_to_string(file_path).expect("Failed to read test vector file");
        serde_json::from_str(&json_str).expect("Failed to parse JSON")
    }

    fn convert_test_case(test_case: AsnTestCase) -> TestCase {
        TestCase {
            pre_state: test_case.pre_state.into(),
            block: test_case.block.into(),
            post_state: test_case.post_state.into(),
        }
    }

    fn init_node_storage() -> NodeStorage {
        let (header_db, xt_db, state_manager, post_state_root_db) = init_db_and_manager(None);
        NodeStorage::new(
            Arc::new(state_manager),
            Arc::new(header_db),
            Arc::new(xt_db),
            Arc::new(post_state_root_db),
        )
    }

    async fn commit_pre_state(
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

    async fn import_block(
        storage: Arc<NodeStorage>,
        block: Block,
    ) -> Result<StateRoot, Box<dyn Error>> {
        let post_state_root = BlockImporter::import_block(storage, block).await?;
        Ok(post_state_root)
    }

    async fn _extract_post_state() -> Result<RawState, Box<dyn Error>> {
        // TODO: Check if enumerating on all state entries would be effective
        unimplemented!()
    }

    async fn assert_post_state(
        state_manager: &StateManager,
        actual_post_state_root: StateRoot,
        expected_post_state: RawState,
    ) {
        for kv in expected_post_state.keyvals {
            if let Some(actual_val) = state_manager.get_raw_state_entry(&kv.key).await.unwrap() {
                let actual_encoded = hex::encode(&actual_val);
                let expected_encoded = hex::encode(&*kv.value);
                if actual_encoded != expected_encoded {
                    tracing::error!(
                        "State mismatch. Key: {}, actual: {}, expected: {}",
                        kv.key,
                        actual_encoded,
                        expected_encoded
                    );
                }
            } else {
                tracing::warn!("Raw state entry not found. Key: {}", kv.key.encode_hex());
            };
        }
        assert_eq!(actual_post_state_root, expected_post_state.state_root);
    }
}

pub async fn run_test_case(file_path: &str) -> Result<(), Box<dyn Error>> {
    // Config tracing subscriber
    setup_timed_tracing();

    // load test case
    let test_case = BlockImportHarness::load_test_case(&PathBuf::from(file_path));
    let test_case = BlockImportHarness::convert_test_case(test_case);

    // init node storage
    let storage = Arc::new(BlockImportHarness::init_node_storage());

    // initialize state keys if genesis block
    if test_case.block.is_genesis() {
        add_all_simple_state_entries(&storage.state_manager(), None).await?;
    }

    BlockImportHarness::commit_pre_state(&storage.state_manager(), test_case.pre_state).await?;

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

    // import block
    let post_state_root =
        BlockImportHarness::import_block(storage.clone(), test_case.block).await?;

    // assertions
    BlockImportHarness::assert_post_state(
        &storage.state_manager(),
        post_state_root,
        test_case.post_state,
    )
    .await;

    Ok(())
}

fn get_parent_block_header(file_path: &str) -> BlockHeader {
    let parent_block_test_file_path = {
        let file_str = file_path.to_string();
        let reg = Regex::new(r"(\d{8})\.json$").unwrap();
        // Get parent block test case file path
        reg.replace(&file_str, |caps: &regex::Captures| {
            let num_str = &caps[1];
            let num: u64 = num_str.parse().unwrap_or(0);
            let decremented = num.saturating_sub(1);
            format!("{:0width$}.json", decremented, width = num_str.len())
        })
        .to_string()
    };
    let parent_block_test_case = BlockImportHarness::convert_test_case(
        BlockImportHarness::load_test_case(&PathBuf::from(parent_block_test_file_path)),
    );
    parent_block_test_case.block.header
}
