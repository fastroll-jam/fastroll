use crate::asn_types::common::{AsnBlock, AsnByteArray, AsnByteSequence, AsnOpaqueHash};
use fr_block::types::block::Block;
use fr_common::{ByteSequence, Hash32, StateKey};
use fr_state::{manager::StateManager, test_utils::init_db_and_manager};
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

    fn convert_input_type(test_input: AsnRawState) -> RawState {
        test_input.into()
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
        _storage: Arc<NodeStorage>,
        _block: Block,
    ) -> Result<Hash32, Box<dyn Error>> {
        unimplemented!()
    }

    async fn extract_post_state() -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    fn assert_post_state() {}
}

pub async fn run_test_case(filename: &str) -> Result<(), Box<dyn Error>> {
    // load test case
    let filename = PathBuf::from(filename);
    let test_case = BlockImportHarness::load_test_case(&filename);
    let pre_state = BlockImportHarness::convert_input_type(test_case.pre_state);

    // init node storage
    let storage = BlockImportHarness::init_node_storage();

    BlockImportHarness::commit_pre_state(&storage.state_manager(), pre_state).await?;

    Ok(())
}
