use fr_asn_types::types::common::{AsnBlock, AsnByteArray, AsnByteSequence, AsnOpaqueHash};
use fr_block::types::block::Block;
use fr_codec::prelude::*;
use fr_common::{ByteSequence, Hash32, ServiceId, StateKey};
use fr_node::roles::importer::BlockImporter;
use fr_state::{
    error::StateManagerError,
    manager::StateManager,
    state_utils::StateKeyConstant as SC,
    test_utils::{add_all_simple_state_entries, init_db_and_manager},
    types::{
        AccountMetadata, AccumulateHistory, AccumulateQueue, ActiveSet, AuthPool, AuthQueue,
        BlockHistory, DisputesState, EpochEntropy, OnChainStatistics, PastSet, PendingReports,
        PrivilegedServices, SafroleState, StagingSet, Timeslot,
    },
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

impl KeyValue {
    /// Add the raw key-value pair as a typed entry to the `StateManager`.
    pub async fn add_to_state_manager(
        &self,
        state_manager: &StateManager,
    ) -> Result<(), StateManagerError> {
        // TODO: Handle invalid state key(s). Currently naively classifies state key kinds.

        let first_byte = self.key.as_slice()[0];
        // FIXME: add state with const 16 (GP v0.6.7)
        if first_byte <= 15 || first_byte == 255 {
            // The entry represents simple state
            let state_key_constant = SC::try_from(first_byte).unwrap();
            match state_key_constant {
                SC::AuthPool => {
                    state_manager
                        .add_auth_pool(AuthPool::decode(&mut self.value.as_slice())?)
                        .await?;
                }
                SC::AuthQueue => {
                    state_manager
                        .add_auth_queue(AuthQueue::decode(&mut self.value.as_slice())?)
                        .await?;
                }
                SC::BlockHistory => {
                    state_manager
                        .add_block_history(BlockHistory::decode(&mut self.value.as_slice())?)
                        .await?;
                }
                SC::SafroleState => {
                    state_manager
                        .add_safrole(SafroleState::decode(&mut self.value.as_slice())?)
                        .await?;
                }
                SC::DisputesState => {
                    state_manager
                        .add_disputes(DisputesState::decode(&mut self.value.as_slice())?)
                        .await?;
                }
                SC::EpochEntropy => {
                    state_manager
                        .add_epoch_entropy(EpochEntropy::decode(&mut self.value.as_slice())?)
                        .await?;
                }
                SC::StagingSet => {
                    state_manager
                        .add_staging_set(StagingSet::decode(&mut self.value.as_slice())?)
                        .await?;
                }
                SC::ActiveSet => {
                    state_manager
                        .add_active_set(ActiveSet::decode(&mut self.value.as_slice())?)
                        .await?;
                }
                SC::PastSet => {
                    state_manager
                        .add_past_set(PastSet::decode(&mut self.value.as_slice())?)
                        .await?;
                }
                SC::PendingReports => {
                    state_manager
                        .add_pending_reports(PendingReports::decode(&mut self.value.as_slice())?)
                        .await?;
                }

                SC::Timeslot => {
                    state_manager
                        .add_timeslot(Timeslot::decode(&mut self.value.as_slice())?)
                        .await?;
                }
                SC::PrivilegedServices => {
                    state_manager
                        .add_privileged_services(PrivilegedServices::decode(
                            &mut self.value.as_slice(),
                        )?)
                        .await?;
                }
                SC::OnChainStatistics => {
                    state_manager
                        .add_onchain_statistics(OnChainStatistics::decode(
                            &mut self.value.as_slice(),
                        )?)
                        .await?;
                }
                SC::AccumulateQueue => {
                    state_manager
                        .add_accumulate_queue(AccumulateQueue::decode(&mut self.value.as_slice())?)
                        .await?;
                }
                SC::AccumulateHistory => {
                    state_manager
                        .add_accumulate_history(AccumulateHistory::decode(
                            &mut self.value.as_slice(),
                        )?)
                        .await?;
                }
                SC::AccountMetadata => {
                    let values = self.value.as_slice();
                    let buf = vec![values[1], values[3], values[5], values[7]];
                    let service_id = ServiceId::decode_fixed(&mut buf.as_slice(), 4)?;
                    state_manager
                        .add_account_metadata(
                            service_id,
                            AccountMetadata::decode(&mut self.value.as_slice())?,
                        )
                        .await?;
                }
            }
            return Ok(());
        }

        // TODO: account storage entries

        Ok(())
    }
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
            kv.add_to_state_manager(state_manager).await?;
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
            assert_eq!(actual_val, kv.value.into_vec())
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
    add_all_simple_state_entries(&storage.state_manager(), None).await?;

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
