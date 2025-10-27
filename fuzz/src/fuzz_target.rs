use crate::{
    types::{
        Ancestry, FuzzFeatures, FuzzMessageKind, HeaderHash, KeyValue, PeerInfo, State, StateRoot,
        TrieKey,
    },
    utils::{validate_socket_path, StreamUtils},
};
use fr_block::{
    ancestors::AncestorEntry,
    header_db::BlockHeaderDBError,
    post_state_root_db::PostStateRootDbError,
    types::block::{Block, BlockHeader, BlockHeaderError},
};
use fr_codec::JamCodecError;
use fr_common::{ByteSequence, CommonTypeError};
use fr_config::StorageConfig;
use fr_limited_vec::LimitedVecError;
use fr_node::{
    reexports::AccountStateChanges,
    roles::importer::{BlockCommitMode, BlockImportOutput, BlockImporter},
};
use fr_state::{error::StateManagerError, manager::StateCommitArtifact};
use fr_storage::node_storage::{NodeStorage, NodeStorageError};
use std::{
    collections::{BTreeSet, HashMap},
    io::Error as IoError,
    string::FromUtf8Error,
    sync::Arc,
};
use tempfile::{tempdir, TempDir};
use thiserror::Error;
use tokio::{
    net::{UnixListener, UnixStream},
    time::error::Elapsed,
};

#[derive(Debug, Error)]
pub enum FuzzTargetError {
    #[error("IoError: {0}")]
    IoError(#[from] IoError),
    #[error("FromUtf8Error: {0}")]
    FromUtf8Error(#[from] FromUtf8Error),
    #[error("ElapsedError: {0}")]
    ElapsedError(#[from] Elapsed),
    #[error("CommonTypeError: {0}")]
    CommonTypeError(#[from] CommonTypeError),
    #[error("LimitedVecError: {0}")]
    LimitedVecError(#[from] LimitedVecError),
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
    #[error("BlockHeaderError: {0}")]
    BlockHeaderError(#[from] BlockHeaderError),
    #[error("BlockHeaderDBError: {0}")]
    BlockHeaderDBError(#[from] BlockHeaderDBError),
    #[error("PostStateRootDbError: {0}")]
    PostStateRootDbError(#[from] PostStateRootDbError),
    #[error("NodeStorageError: {0}")]
    NodeStorageError(#[from] NodeStorageError),
    #[error("First request message is not a peer info")]
    NotPeerInfo,
    #[error("Invalid message kind: {0}")]
    InvalidMessageKind(String),
    #[error("Invalid socket path: {0}")]
    InvalidSocketPath(String),
}

/// Collection of the state keys of the latest chain state.
///
/// This is used specifically for fuzz target to support `GetState` message kind, since the main
/// JAM client runner doesn't inherently support tracking the full list of available state keys.
#[derive(Default)]
struct LatestStateKeys {
    header_hash: HeaderHash,
    state_keys: BTreeSet<TrieKey>,
}

impl LatestStateKeys {
    fn update_header_hash(&mut self, header_hash: HeaderHash) {
        self.header_hash = header_hash;
    }

    fn insert_state_key(&mut self, state_key: TrieKey) {
        self.state_keys.insert(state_key);
    }

    fn remove_state_key(&mut self, state_key: TrieKey) {
        self.state_keys.remove(&state_key);
    }
}

/// A block header and its uncommitted state change artifacts
/// that can be either committed or discarded after forks get resolved.
#[derive(Clone)]
struct StagedBlock {
    header: BlockHeader,
    account_state_changes: AccountStateChanges,
    state_commit_artifact: Option<StateCommitArtifact>,
}

/// The state that keeps minimal context to support simple forking.
#[derive(Default)]
struct SimpleForkState {
    /// The header hash of the last finalized block.
    last_finalized: Option<HeaderHash>,
    /// The collection of blocks that are staged but not committed or dropped yet.
    staged_blocks: HashMap<HeaderHash, StagedBlock>,
}

impl SimpleForkState {
    fn last_finalized(&self) -> Option<&HeaderHash> {
        self.last_finalized.as_ref()
    }

    fn set_last_finalized(&mut self, last_finalized: HeaderHash) {
        self.last_finalized = Some(last_finalized);
    }

    fn insert_staged_block(&mut self, header_hash: HeaderHash, block: StagedBlock) {
        self.staged_blocks.insert(header_hash, block);
    }

    fn take_staged_block(&mut self, header_hash: &HeaderHash) -> Option<StagedBlock> {
        self.staged_blocks.remove(header_hash)
    }
}

pub struct FuzzTargetRunner {
    pub(crate) node_storage: Arc<NodeStorage>,
    latest_state_keys: LatestStateKeys,
    target_peer_info: PeerInfo,
    fuzz_features: FuzzFeatures,
    fork_state: SimpleForkState,
    _temp_dir: TempDir,
}

impl FuzzTargetRunner {
    /// Creates a `FuzzTargetRunner` with a temporary DB path.
    pub fn new(target_peer_info: PeerInfo) -> Result<Self, FuzzTargetError> {
        let _temp_dir = tempdir()?;
        let temp_db_path = _temp_dir.path().join("fuzz_target_db");
        Ok(Self {
            _temp_dir,
            node_storage: Arc::new(NodeStorage::new(StorageConfig::from_path(temp_db_path))?),
            latest_state_keys: LatestStateKeys::default(),
            target_peer_info,
            fuzz_features: FuzzFeatures::default(),
            fork_state: SimpleForkState::default(),
        })
    }

    fn node_storage(&self) -> Arc<NodeStorage> {
        self.node_storage.clone()
    }

    /// Insert ancestor entries into in-memory `AncestorSet`
    pub(crate) async fn set_ancestors(&self, ancestors: Ancestry) -> Result<(), FuzzTargetError> {
        let entries: Vec<AncestorEntry> = ancestors
            .into_iter()
            .map(|i| (i.slot, i.header_hash))
            .collect();
        self.node_storage()
            .header_db()
            .batch_insert_to_ancestor_set(entries)?;
        Ok(())
    }

    fn apply_account_state_changes(&mut self, changes: &AccountStateChanges) {
        for change in changes.inner.values() {
            for added_key in &change.added_state_keys {
                self.latest_state_keys.insert_state_key(added_key.clone());
            }
            for removed_key in &change.removed_state_keys {
                self.latest_state_keys.remove_state_key(removed_key.clone());
            }
        }
    }

    fn determine_block_commit_mode(&self, block: &Block) -> BlockCommitMode {
        if !self.fuzz_features.with_forking || block.is_genesis() {
            return BlockCommitMode::Immediate;
        }

        if let Some(finalized_parent) = self.fork_state.last_finalized() {
            if block.header.parent_hash() == finalized_parent {
                // The imported block is extending the finalized block; simple forking occurred
                return BlockCommitMode::StageOnly;
            }
        }

        BlockCommitMode::Immediate
    }

    fn stage_block(
        &mut self,
        header_hash: HeaderHash,
        header: BlockHeader,
        account_state_changes: AccountStateChanges,
        state_commit_artifact: Option<StateCommitArtifact>,
    ) {
        self.fork_state.insert_staged_block(
            header_hash,
            StagedBlock {
                header,
                account_state_changes,
                state_commit_artifact,
            },
        );
    }

    async fn apply_staged_block_commit(
        &mut self,
        header_hash: HeaderHash,
        staged_block: StagedBlock,
    ) -> Result<(), FuzzTargetError> {
        if let Some(artifact) = &staged_block.state_commit_artifact {
            self.node_storage()
                .state_manager()
                .apply_dirty_cache_commit(artifact)
                .await?;
        }
        self.apply_account_state_changes(&staged_block.account_state_changes);
        self.node_storage()
            .header_db()
            .set_best_header(staged_block.header);
        self.fork_state.set_last_finalized(header_hash);
        Ok(())
    }

    /// Resolves simple forking by finalizing a staged block if the new block is extending it.
    async fn finalize_if_parent_staged(
        &mut self,
        staged_parent_hash: &HeaderHash,
    ) -> Result<(), FuzzTargetError> {
        if let Some(staged_block) = self.fork_state.take_staged_block(staged_parent_hash) {
            // Apply state commitment of the new finalized block
            self.apply_staged_block_commit(staged_parent_hash.clone(), staged_block)
                .await?;

            // Clear the staged blocks of the fork state
            self.fork_state.staged_blocks.clear();
        }
        Ok(())
    }

    pub async fn run_as_fuzz_target(&mut self, socket_path: String) -> Result<(), FuzzTargetError> {
        // Validate socket path input
        validate_socket_path(&socket_path)?;

        // Cleanup existing socket files at the path
        let _ = std::fs::remove_file(&socket_path);

        let listener = UnixListener::bind(&socket_path)?;
        tracing::info!("JAM Fuzzer target server listening on {socket_path}");

        let mut is_first_session = true;

        // Continuously accept new connections after closing the previous session.
        while let Ok((stream, _addr)) = listener.accept().await {
            tracing::info!("Accepted a connection from the fuzzer");

            if is_first_session {
                is_first_session = false;
            } else {
                // Reset storage & state for the new session
                *self = FuzzTargetRunner::new(self.target_peer_info.clone())?;
            }

            self.handle_fuzzer_session(stream).await?;
            tracing::info!("Fuzzer session ended");
        }
        Ok(())
    }

    async fn handle_fuzzer_session(
        &mut self,
        mut stream: UnixStream,
    ) -> Result<(), FuzzTargetError> {
        // First message must be the PeerInfo handshake
        self.handle_handshake(&mut stream).await?;

        // Handle incoming messages
        let mut is_first_block = true;
        loop {
            match StreamUtils::read_message(&mut stream).await {
                Ok(message_kind) => {
                    self.process_message(&mut stream, message_kind, &mut is_first_block)
                        .await?
                }
                Err(e) => {
                    if let FuzzTargetError::IoError(io_error) = e {
                        // Normal disconnection (EOF)
                        if io_error.kind() == std::io::ErrorKind::UnexpectedEof {
                            tracing::info!("Fuzzer session disconnected gracefully");
                            return Ok(());
                        }
                    } else {
                        // Other errors
                        return Err(e);
                    }
                }
            }
        }
    }

    async fn handle_handshake(&mut self, stream: &mut UnixStream) -> Result<(), FuzzTargetError> {
        let message_kind = StreamUtils::read_message(stream).await?;

        if let FuzzMessageKind::PeerInfo(peer_info) = message_kind {
            // Set fuzz features
            let features = FuzzFeatures::from(peer_info.fuzz_features);
            self.fuzz_features = features.clone();

            tracing::info!(
                "[PeerInfo][RECV] Fuzzer info: fuzz_version={} feature_ancestors={} feature_forking={} name={} jam_version={} app_version={}",
                peer_info.fuzz_version,
                features.with_ancestors,
                features.with_forking,
                String::from_utf8(peer_info.app_name)?,
                peer_info.jam_version,
                peer_info.app_version,
            );

            StreamUtils::send_message(
                stream,
                FuzzMessageKind::PeerInfo(self.target_peer_info.clone()),
            )
            .await?;
            Ok(())
        } else {
            Err(FuzzTargetError::NotPeerInfo)
        }
    }

    async fn process_message(
        &mut self,
        stream: &mut UnixStream,
        message_kind: FuzzMessageKind,
        is_first_block: &mut bool,
    ) -> Result<(), FuzzTargetError> {
        match message_kind {
            FuzzMessageKind::Initialize(init) => {
                tracing::info!("[RECV][Initialize] Received message");
                let storage = self.node_storage();
                let state_manager = storage.state_manager();

                let parent_header = init.header;
                let parent_header_hash = parent_header.hash()?;
                self.latest_state_keys
                    .update_header_hash(parent_header_hash.clone());

                // Add state entries
                for kv in init.state.0 {
                    state_manager
                        .add_raw_state_entry(&kv.key, kv.value.into_vec())
                        .await?;
                    self.latest_state_keys.insert_state_key(kv.key);
                }
                state_manager.commit_dirty_cache().await?;
                let state_root = state_manager.merkle_root().await?;

                // Initialize the simple fork state
                self.fork_state = SimpleForkState::default();
                self.fork_state
                    .set_last_finalized(parent_header_hash.clone());

                // Initialize `BlockHeaderDB` & `PostStateRootDB`
                storage.header_db().set_best_header(parent_header);
                storage
                    .post_state_root_db()
                    .set_post_state_root(&parent_header_hash, state_root.clone())
                    .await?;

                if self.fuzz_features.with_ancestors {
                    // Set Ancestor set
                    self.set_ancestors(init.ancestry).await?;
                }

                StreamUtils::send_message(
                    stream,
                    FuzzMessageKind::StateRoot(StateRoot(state_root.clone())),
                )
                .await?;
                tracing::info!("[SEND][Initialize] root={state_root}");
                Ok(())
            }
            FuzzMessageKind::ImportBlock(import_block) => {
                tracing::info!("[RECV][ImportBlock] Received message");
                let storage = self.node_storage();
                let block = import_block.0;
                let header_hash = block.header.hash()?;
                self.latest_state_keys
                    .update_header_hash(header_hash.clone());

                // Resolve forks if the new block is extending one of the staged blocks
                self.finalize_if_parent_staged(block.header.parent_hash())
                    .await?;

                let block_commit_mode = self.determine_block_commit_mode(&block);

                let block_header = block.header.clone();
                match BlockImporter::import_block(
                    storage.clone(),
                    block,
                    *is_first_block,
                    self.fuzz_features.with_ancestors,
                    block_commit_mode,
                )
                .await
                {
                    Ok(BlockImportOutput {
                        post_state_root,
                        account_state_changes,
                        state_commit_artifact,
                    }) => {
                        match block_commit_mode {
                            BlockCommitMode::Immediate => {
                                self.apply_account_state_changes(&account_state_changes);
                                self.fork_state.set_last_finalized(header_hash.clone());
                            }
                            BlockCommitMode::StageOnly => {
                                self.stage_block(
                                    header_hash.clone(),
                                    block_header,
                                    account_state_changes,
                                    state_commit_artifact,
                                );
                            }
                        }

                        // Update `PostStateRootDB`
                        storage
                            .post_state_root_db()
                            .set_post_state_root(&header_hash, post_state_root.clone())
                            .await?;

                        // Send message: StateRoot
                        StreamUtils::send_message(
                            stream,
                            FuzzMessageKind::StateRoot(StateRoot(post_state_root.clone())),
                        )
                        .await?;
                        tracing::info!("[SEND][ImportBlock] root={post_state_root}");
                    }
                    Err(e) => {
                        tracing::debug!("Invalid block - import failed: {e:?}");

                        // Rollback the state cache (revert all dirty entries)
                        storage.state_manager().rollback_dirty_cache();

                        // Send message: Error
                        StreamUtils::send_message(
                            stream,
                            FuzzMessageKind::Error(e.to_string().into_bytes()),
                        )
                        .await?;
                        tracing::info!("[SEND][ImportBlock] Err {}", e.to_string());
                    }
                };
                if *is_first_block {
                    *is_first_block = false;
                }
                Ok(())
            }
            FuzzMessageKind::GetState(get_state) => {
                tracing::info!("[RECV][GetState] Received message");
                let requested_header_hash = get_state.0;
                if self.latest_state_keys.header_hash != requested_header_hash {
                    tracing::error!("Latest header hash mismatch: requested ({requested_header_hash}) observed ({})", self.latest_state_keys.header_hash);
                    // Send `State` message anyway
                }

                let state_manager = self.node_storage().state_manager();
                let mut post_state = Vec::new();
                // State keys are ordered (BTreeSet)
                for state_key in self.latest_state_keys.state_keys.iter() {
                    if let Some(val) = state_manager.get_raw_state_entry(state_key).await? {
                        post_state.push(KeyValue {
                            key: state_key.clone(),
                            value: ByteSequence::from_vec(val),
                        });
                    }
                }
                StreamUtils::send_message(stream, FuzzMessageKind::State(State(post_state)))
                    .await?;
                tracing::info!("Session terminated by GetState request");
                Ok(())
            }
            e => Err(FuzzTargetError::InvalidMessageKind(format!("{e:?}"))),
        }
    }
}
