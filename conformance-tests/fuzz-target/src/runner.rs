use crate::types::{
    FuzzMessageKind, FuzzProtocolMessage, HeaderHash, KeyValue, PeerInfo, State, StateRoot, TrieKey,
};
use fr_codec::prelude::*;
use fr_common::ByteSequence;
use fr_node::roles::importer::BlockImporter;
use fr_state::test_utils::init_db_and_manager;
use fr_storage::node_storage::NodeStorage;
use std::{collections::BTreeSet, error::Error, path::Path, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};

const DEFAULT_SOCKET_PATH: &str = "/tmp/jam_target.sock";

#[cfg(unix)]
fn is_socket_file(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt;
    metadata.file_type().is_socket()
}

#[cfg(not(unix))]
fn is_socket_file(_metadata: &std::fs::Metadata) -> bool {
    false
}

pub fn validate_socket_path(socket_path: &str) -> Result<(), Box<dyn Error>> {
    if socket_path.is_empty() {
        return Err("Socket path cannot be empty".into());
    }

    // Check input length
    if socket_path.len() > 200 {
        return Err("Socket path is too long".into());
    }

    let path = Path::new(socket_path);

    // Enforce absolute path
    if !path.is_absolute() {
        return Err("Socket path should be absolute (start with `/`)".into());
    }

    // Check whether parent directory exists and is writable
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            return Err(format!("Parent directory does not exist: {}", parent.display()).into());
        }

        let metadata = std::fs::metadata(parent)?;
        if metadata.permissions().readonly() {
            return Err(format!("Parent directory is read-only: {}", parent.display()).into());
        }
    }

    // Check if a file already exists at the path
    if path.exists() {
        let metadata = std::fs::metadata(path)?;
        if !is_socket_file(&metadata) {
            return Err(format!("Regular file exists at the path: {}", path.display()).into());
        }
    }

    Ok(())
}

#[derive(Default)]
struct LatestStateKeys {
    header_hash: HeaderHash,
    state_keys: BTreeSet<TrieKey>,
}

#[allow(dead_code)]
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
    pub fn new(target_peer_info: PeerInfo) -> Self {
        let (header_db, xt_db, state_manager, post_state_root_db) = init_db_and_manager(None);
        let node_storage = Arc::new(NodeStorage::new(
            Arc::new(state_manager),
            Arc::new(header_db),
            Arc::new(xt_db),
            Arc::new(post_state_root_db),
        ));
        Self {
            node_storage,
            latest_state_keys: LatestStateKeys::default(),
            target_peer_info,
        }
    }

    fn node_storage(&self) -> Arc<NodeStorage> {
        self.node_storage.clone()
    }

    pub async fn run_as_fuzz_target(
        &self,
        socket_path: Option<String>,
    ) -> Result<(), Box<dyn Error>> {
        let socket_path = socket_path.unwrap_or(DEFAULT_SOCKET_PATH.to_string());

        // Validate socket path input
        validate_socket_path(&socket_path)?;

        // Cleanup existing socket files at the path
        let _ = std::fs::remove_file(&socket_path);

        let listener = UnixListener::bind(&socket_path)?;
        tracing::info!("JAM Fuzzer target server listening on {socket_path}");

        // A single connection is used for the fuzzing
        let (stream, _addr) = listener.accept().await?;
        tracing::info!("Accepted a connection from the fuzzer");

        self.handle_fuzzer_session(stream).await?;
        tracing::info!("Fuzzer session ended");
        Ok(())
    }

    async fn handle_fuzzer_session(&self, mut stream: UnixStream) -> Result<(), Box<dyn Error>> {
        // First message must be the PeerInfo handshake
        self.handle_handshake(&mut stream).await?;

        // Handle incoming messages
        loop {
            let message_kind = Self::read_message(&mut stream).await?;
            self.process_message(&mut stream, message_kind).await?;
        }
    }

    async fn read_message(stream: &mut UnixStream) -> Result<FuzzMessageKind, Box<dyn Error>> {
        let mut length_buf = [0u8; 4];
        stream.read_exact(&mut length_buf).await?;
        let message_len = u32::decode_fixed(&mut length_buf.as_slice(), 4)?;

        let mut message_buf = vec![0u8; message_len as usize];
        stream.read_exact(&mut message_buf).await?;
        let message_kind = FuzzMessageKind::decode(&mut message_buf.as_slice())?;
        Ok(message_kind)
    }

    async fn send_message(
        stream: &mut UnixStream,
        message_kind: FuzzMessageKind,
    ) -> Result<(), Box<dyn Error>> {
        let message = FuzzProtocolMessage::from_kind(message_kind)?;
        stream.write_all(&message.encode()?).await?;
        stream.flush().await?;
        Ok(())
    }

    async fn handle_handshake(&self, stream: &mut UnixStream) -> Result<(), Box<dyn Error>> {
        let message_kind = Self::read_message(stream).await?;

        if let FuzzMessageKind::PeerInfo(peer_info) = message_kind {
            tracing::info!(
                "Fuzzer peer info: name={} app_version={} jam_version={}",
                String::from_utf8(peer_info.name)?,
                peer_info.app_version,
                peer_info.jam_version
            );
            Self::send_message(
                stream,
                FuzzMessageKind::PeerInfo(self.target_peer_info.clone()),
            )
            .await?;
            Ok(())
        } else {
            Err("First request message is not a peer info".into())
        }
    }

    async fn process_message(
        &self,
        stream: &mut UnixStream,
        message_kind: FuzzMessageKind,
    ) -> Result<(), Box<dyn Error>> {
        match message_kind {
            FuzzMessageKind::ImportBlock(import_block) => {
                let storage = self.node_storage();
                let pre_state_root = storage.state_manager().merkle_root();
                let post_state_root =
                    match BlockImporter::import_block(storage, import_block.0).await {
                        Ok(post_state_root) => post_state_root,
                        Err(e) => {
                            tracing::debug!("Invalid block - import failed: {e:?}");
                            // Return pre-state root for invalid blocks
                            pre_state_root
                        }
                    };
                // TODO: keep the latest { header hash -> post state key-vals } entry
                Self::send_message(
                    stream,
                    FuzzMessageKind::StateRoot(StateRoot(post_state_root)),
                )
                .await
            }
            FuzzMessageKind::SetState(set_state) => {
                // TODO: keep the latest { header hash -> post state key-vals } entry
                let state_manager = self.node_storage().state_manager();
                for kv in set_state.state.0 {
                    state_manager
                        .add_raw_state_entry(&kv.key, kv.value.into_vec())
                        .await?;
                }
                state_manager.commit_dirty_cache().await?;
                let state_root = state_manager.merkle_root();
                Self::send_message(stream, FuzzMessageKind::StateRoot(StateRoot(state_root))).await
            }
            FuzzMessageKind::GetState(get_state) => {
                let requested_header_hash = get_state.0;
                if self.latest_state_keys.header_hash != requested_header_hash {
                    tracing::error!("Latest header hash mismatch: requested ({requested_header_hash}) observed ({})", self.latest_state_keys.header_hash);
                    // Send `State` message anyway
                }

                let state_manager = self.node_storage().state_manager();
                let mut post_state = State(Vec::new());
                // State keys are ordered (BTreeSet)
                for state_key in self.latest_state_keys.state_keys.iter() {
                    if let Some(val) = state_manager.get_raw_state_entry(state_key).await? {
                        post_state.0.push(KeyValue {
                            key: state_key.clone(),
                            value: ByteSequence::from_vec(val),
                        });
                    }
                }
                Self::send_message(stream, FuzzMessageKind::State(post_state)).await?;
                Err("Session terminated by GetState request".into())
            }
            e => Err(format!("Invalid message kind: {e:?}").into()),
        }
    }
}
