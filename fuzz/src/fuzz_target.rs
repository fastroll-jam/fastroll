use crate::{
    types::{FuzzMessageKind, HeaderHash, KeyValue, PeerInfo, State, StateRoot, TrieKey},
    utils::{validate_socket_path, StreamUtils},
};
use fr_block::{post_state_root_db::PostStateRootDbError, types::block::BlockHeaderError};
use fr_codec::JamCodecError;
use fr_common::ByteSequence;
use fr_config::StorageConfig;
use fr_node::roles::importer::BlockImporter;
use fr_state::error::StateManagerError;
use fr_storage::node_storage::NodeStorage;
use std::{collections::BTreeSet, io::Error as IoError, string::FromUtf8Error, sync::Arc};
use tempfile::tempdir;
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
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
    #[error("BlockHeaderError: {0}")]
    BlockHeaderError(#[from] BlockHeaderError),
    #[error("PostStateRootDbError: {0}")]
    PostStateRootDbError(#[from] PostStateRootDbError),
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

pub struct FuzzTargetRunner {
    node_storage: Arc<NodeStorage>,
    latest_state_keys: LatestStateKeys,
    target_peer_info: PeerInfo,
}

impl FuzzTargetRunner {
    /// Creates a `FuzzTargetRunner` with using `tempfile::tempdir` for DB path derivation.
    pub fn new(target_peer_info: PeerInfo) -> Self {
        Self {
            node_storage: Arc::new(
                NodeStorage::new(StorageConfig::from_path(
                    tempdir().unwrap().path().join("fuzz_target_db "),
                ))
                .expect("Failed to initialize NodeStorage with tempdir"),
            ),
            latest_state_keys: LatestStateKeys::default(),
            target_peer_info,
        }
    }

    fn node_storage(&self) -> Arc<NodeStorage> {
        self.node_storage.clone()
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
                *self = FuzzTargetRunner::new(self.target_peer_info.clone());
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
        loop {
            match StreamUtils::read_message(&mut stream).await {
                Ok(message_kind) => self.process_message(&mut stream, message_kind).await?,
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

    async fn handle_handshake(&self, stream: &mut UnixStream) -> Result<(), FuzzTargetError> {
        let message_kind = StreamUtils::read_message(stream).await?;

        if let FuzzMessageKind::PeerInfo(peer_info) = message_kind {
            tracing::info!(
                "[PeerInfo] Fuzzer info: name={} app_version={} jam_version={}",
                String::from_utf8(peer_info.name)?,
                peer_info.app_version,
                peer_info.jam_version
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
    ) -> Result<(), FuzzTargetError> {
        match message_kind {
            FuzzMessageKind::SetState(set_state) => {
                tracing::info!("[SetState] Received message");
                let storage = self.node_storage();
                let state_manager = storage.state_manager();

                let parent_header = set_state.header;
                let parent_header_hash = parent_header.hash()?;
                self.latest_state_keys
                    .update_header_hash(parent_header_hash.clone());

                // Add state entries
                for kv in set_state.state.0 {
                    state_manager
                        .add_raw_state_entry(&kv.key, kv.value.into_vec())
                        .await?;
                    self.latest_state_keys.insert_state_key(kv.key);
                }
                state_manager.commit_dirty_cache().await?;
                let state_root = state_manager.merkle_root();

                // Initialize `BlockHeaderDB` & `PostStateRootDB`
                storage.header_db().set_best_header(parent_header);
                storage
                    .post_state_root_db()
                    .set_post_state_root(&parent_header_hash, state_root.clone())
                    .await?;

                StreamUtils::send_message(stream, FuzzMessageKind::StateRoot(StateRoot(state_root)))
                    .await
            }
            FuzzMessageKind::ImportBlock(import_block) => {
                tracing::info!("[ImportBlock] Received message");
                let storage = self.node_storage();
                let block = import_block.0;
                let header_hash = block.header.hash()?;
                self.latest_state_keys
                    .update_header_hash(header_hash.clone());
                let pre_state_root = storage.state_manager().merkle_root();
                let post_state_root =
                    match BlockImporter::import_block(storage.clone(), block).await {
                        Ok((post_state_root, account_state_changes)) => {
                            account_state_changes.inner.values().for_each(|change| {
                                for added_key in &change.added_state_keys {
                                    self.latest_state_keys.insert_state_key(added_key.clone());
                                }
                                for removed_key in &change.removed_state_keys {
                                    self.latest_state_keys.remove_state_key(removed_key.clone());
                                }
                            });

                            // Update `PostStateRootDB`
                            storage
                                .post_state_root_db()
                                .set_post_state_root(&header_hash, post_state_root.clone())
                                .await?;

                            post_state_root
                        }
                        Err(e) => {
                            tracing::debug!("Invalid block - import failed: {e:?}");
                            // Return pre-state root for invalid blocks
                            pre_state_root
                        }
                    };
                StreamUtils::send_message(
                    stream,
                    FuzzMessageKind::StateRoot(StateRoot(post_state_root)),
                )
                .await
            }
            FuzzMessageKind::GetState(get_state) => {
                tracing::info!("[GetState] Received message");
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
