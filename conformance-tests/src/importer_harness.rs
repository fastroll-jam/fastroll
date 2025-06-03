use fr_asn_types::types::common::{AsnBlock, AsnByteArray, AsnByteSequence, AsnOpaqueHash};
use fr_block::types::block::Block;
use fr_common::{ByteSequence, Hash32, StateKey};
use fr_node::roles::importer::BlockImporter;
use fr_state::{
    manager::StateManager,
    test_utils::{add_all_simple_state_entries, init_db_and_manager},
};
use fr_storage::node_storage::NodeStorage;
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
    pub state_root: Hash32,
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
    // TODO: add `reports`, `safrole` test cases
    const PATH_PREFIX: &'static str = "jamtestvectors-polkajam-traces/traces/fallback";

    fn load_test_case(filename: &Path) -> AsnTestCase {
        let path = PathBuf::from(Self::PATH_PREFIX).join(filename);
        let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
        let json_str = fs::read_to_string(&full_path).expect("Failed to read test vector file");
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
        let (header_db, xt_db, state_manager) = init_db_and_manager(None);
        NodeStorage::new(
            Arc::new(state_manager),
            Arc::new(header_db),
            Arc::new(xt_db),
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
        Ok(())
    }

    async fn import_block(
        storage: Arc<NodeStorage>,
        block: Block,
    ) -> Result<Hash32, Box<dyn Error>> {
        let post_state_root = BlockImporter::import_block(storage, block).await?;
        Ok(post_state_root)
    }

    async fn _extract_post_state() -> Result<RawState, Box<dyn Error>> {
        // TODO: Check if enumerating on all state entries would be effective
        unimplemented!()
    }

    async fn assert_post_state(
        state_manager: &StateManager,
        actual_post_state_root: Hash32,
        expected_post_state: RawState,
    ) {
        assert_eq!(actual_post_state_root, expected_post_state.state_root);
        for kv in expected_post_state.keyvals {
            let actual_val = state_manager
                .get_raw_state_entry_from_db(&kv.key)
                .await
                .expect("state value should exist")
                .unwrap();
            assert_eq!(actual_val, kv.value.into_vec());
        }
    }
}

pub async fn run_test_case(filename: &str) -> Result<(), Box<dyn Error>> {
    // load test case
    let filename = PathBuf::from(filename);
    let test_case = BlockImportHarness::load_test_case(&filename);
    let test_case = BlockImportHarness::convert_test_case(test_case);

    // init node storage
    let storage = Arc::new(BlockImportHarness::init_node_storage());

    // initialize state keys if genesis block
    if test_case.block.is_genesis() {
        add_all_simple_state_entries(&storage.state_manager(), None).await?;
    }

    BlockImportHarness::commit_pre_state(&storage.state_manager(), test_case.pre_state).await?;

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
