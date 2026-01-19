use crate::{
    fuzz_target::{FuzzTargetError, FuzzTargetRunner},
    types::{
        Ancestry, FuzzMessageKind, GetState, ImportBlock, Initialize, PeerInfo, State, StateRoot,
        Version,
    },
    utils::StreamUtils,
    versions::{FUZZ_FEATURES_LOCAL_TEST, FUZZ_PROTO_VERSION},
};
use fr_block::types::block::{Block, BlockHeader, BlockHeaderError};
use fr_common::{
    utils::serde::{FileReader, FileReaderError},
    versions::{CLIENT_VERSION, SPEC_VERSION},
    ByteEncodable,
};
use fr_test_utils::importer_harness::{AsnGenesisBlockTestCase, AsnTestCase};
use std::{
    fs,
    io::Error as IoError,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};
use tempfile::tempdir;
use thiserror::Error;
use tokio::{
    net::UnixStream,
    task::JoinHandle,
    time::{error::Elapsed, sleep, timeout, Instant},
};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const SOCKET_READY_TIMEOUT: Duration = Duration::from_secs(10);
const SOCKET_POLL_INTERVAL: Duration = Duration::from_millis(20);

#[derive(Debug, Error)]
pub enum FuzzerError {
    #[error("IoError: {0}")]
    IoError(#[from] IoError),
    #[error("FileReaderError: {0}")]
    FileReaderError(#[from] FileReaderError),
    #[error("FuzzTargetError: {0}")]
    FuzzTargetError(#[from] FuzzTargetError),
    #[error("Timeout: {0}")]
    Timeout(#[from] Elapsed),
    #[error("JoinError: {0}")]
    JoinError(#[from] tokio::task::JoinError),
    #[error("Failed to connect to fuzz socket {path}: {source}")]
    ConnectFailed { path: String, source: IoError },
    #[error("Unexpected handshake response: {kind}")]
    UnexpectedHandshakeResp { kind: String },
    #[error("Unexpected Initialize response: {kind}")]
    UnexpectedInitializeResp { kind: String },
    #[error("Unexpected GetState response: {kind}")]
    UnexpectedGetStateResp { kind: String },
    #[error("Unexpected ImportBlock response for {path}: {kind}")]
    UnexpectedImportResp { path: String, kind: String },
    #[error("Fuzz ImportBlock error for {path}: {error}")]
    FuzzImportError { path: String, error: String },
    #[error("Trace directory {path} has less than 2 test cases")]
    TraceInsufficientCases { path: String },
    #[error("Initialize state root mismatch for {path}: expected={expected}, got={got}")]
    InitializeStateRootMismatch {
        path: String,
        expected: String,
        got: String,
    },
    #[error("State root mismatch for {path}: expected={expected}, got={got}")]
    StateRootMismatch {
        path: String,
        expected: String,
        got: String,
    },
    #[error("Fuzz target exited early: {result}")]
    FuzzTargetExitedEarly { result: String },
    #[error("Fuzz target did not create socket at {path}")]
    SocketNotCreated { path: String },
    #[error("Failed to construct fuzz socket path")]
    InvalidSocketPath,
    #[error("BlockHeaderError: {0}")]
    BlockHeaderError(#[from] BlockHeaderError),
}

struct FuzzClient {
    stream: UnixStream,
}

impl FuzzClient {
    async fn connect(socket_path: &Path) -> Result<Self, FuzzerError> {
        let deadline = Instant::now() + SOCKET_READY_TIMEOUT;
        loop {
            match UnixStream::connect(socket_path).await {
                Ok(stream) => return Ok(Self { stream }),
                Err(err)
                    if err.kind() == std::io::ErrorKind::NotFound && Instant::now() < deadline =>
                {
                    sleep(SOCKET_POLL_INTERVAL).await;
                }
                Err(err) => {
                    return Err(FuzzerError::ConnectFailed {
                        path: socket_path.display().to_string(),
                        source: err,
                    });
                }
            }
        }
    }

    async fn read_response(&mut self) -> Result<FuzzMessageKind, FuzzerError> {
        Ok(timeout(DEFAULT_TIMEOUT, StreamUtils::read_message(&mut self.stream)).await??)
    }

    async fn handshake(&mut self, peer_info: PeerInfo) -> Result<PeerInfo, FuzzerError> {
        StreamUtils::send_message(&mut self.stream, FuzzMessageKind::PeerInfo(peer_info)).await?;
        match self.read_response().await? {
            FuzzMessageKind::PeerInfo(info) => Ok(info),
            kind => Err(FuzzerError::UnexpectedHandshakeResp {
                kind: format!("{kind:?}"),
            }),
        }
    }

    async fn initialize(&mut self, init: Initialize) -> Result<StateRoot, FuzzerError> {
        StreamUtils::send_message(&mut self.stream, FuzzMessageKind::Initialize(init)).await?;
        match self.read_response().await? {
            FuzzMessageKind::StateRoot(root) => Ok(root),
            kind => Err(FuzzerError::UnexpectedInitializeResp {
                kind: format!("{kind:?}"),
            }),
        }
    }

    async fn import_block(
        &mut self,
        import_block: ImportBlock,
    ) -> Result<FuzzMessageKind, FuzzerError> {
        StreamUtils::send_message(&mut self.stream, FuzzMessageKind::ImportBlock(import_block))
            .await?;
        self.read_response().await
    }

    async fn get_state(&mut self, get_state: GetState) -> Result<State, FuzzerError> {
        StreamUtils::send_message(&mut self.stream, FuzzMessageKind::GetState(get_state)).await?;
        match self.read_response().await? {
            FuzzMessageKind::State(state) => Ok(state),
            kind => Err(FuzzerError::UnexpectedGetStateResp {
                kind: format!("{kind:?}"),
            }),
        }
    }
}

struct TraceSuite {
    genesis: Option<(PathBuf, AsnGenesisBlockTestCase)>,
    cases: Vec<(PathBuf, AsnTestCase)>,
}

#[derive(Clone, Debug)]
pub struct FuzzImportTiming {
    pub path: PathBuf,
    pub duration: Duration,
}

fn load_trace_suite(trace_dir: &Path) -> Result<TraceSuite, FuzzerError> {
    let mut json_files: Vec<PathBuf> = fs::read_dir(trace_dir)?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect();
    json_files.sort();

    let mut genesis = None;
    let mut cases = Vec::with_capacity(json_files.len());
    for path in json_files {
        if path.file_name().and_then(|name| name.to_str()) == Some("genesis.json") {
            let test_case: AsnGenesisBlockTestCase = FileReader::read_json(&path)?;
            genesis = Some((path, test_case));
        } else {
            let test_case: AsnTestCase = FileReader::read_json(&path)?;
            cases.push((path, test_case));
        }
    }

    Ok(TraceSuite { genesis, cases })
}

fn app_version() -> Version {
    Version::from_str(CLIENT_VERSION).expect("client version invalid")
}

fn jam_version() -> Version {
    Version::from_str(SPEC_VERSION).expect("spec version invalid")
}

fn target_peer_info() -> PeerInfo {
    PeerInfo::new(
        FUZZ_PROTO_VERSION,
        FUZZ_FEATURES_LOCAL_TEST,
        jam_version(),
        app_version(),
        "FastRoll".to_string(),
    )
}

fn fuzzer_peer_info() -> PeerInfo {
    PeerInfo::new(
        FUZZ_PROTO_VERSION,
        FUZZ_FEATURES_LOCAL_TEST,
        jam_version(),
        app_version(),
        "FastRollFuzzer".to_string(),
    )
}

async fn run_fuzz_target(
    socket_path: String,
) -> Result<JoinHandle<Result<(), FuzzTargetError>>, FuzzerError> {
    let mut fuzz_target = FuzzTargetRunner::new(target_peer_info())?;
    let server_jh = tokio::spawn(async move { fuzz_target.run_as_fuzz_target(socket_path).await });
    Ok(server_jh)
}

async fn run_fuzz_trace_dir_internal<F>(
    trace_dir: &str,
    mut on_import: F,
) -> Result<(), FuzzerError>
where
    F: FnMut(&Path, Duration),
{
    // Load block traces
    let trace_dir = Path::new(trace_dir);
    let trace_suite = load_trace_suite(trace_dir)?;
    let mut cases = trace_suite.cases;
    let min_cases = if trace_suite.genesis.is_some() { 1 } else { 2 };
    if cases.len() < min_cases {
        return Err(FuzzerError::TraceInsufficientCases {
            path: trace_dir.display().to_string(),
        });
    }

    // Run socket server (fuzz target)
    let temp_dir = tempdir()?;
    let socket_path = temp_dir.path().join("fuzz_socket");
    let socket_str = socket_path
        .to_str()
        .ok_or(FuzzerError::InvalidSocketPath)?
        .to_string();
    let mut server_jh = Some(run_fuzz_target(socket_str).await?);

    // Wait for the target to bind and create the socket file
    let socket_ready_deadline = Instant::now() + SOCKET_READY_TIMEOUT;
    while !socket_path.exists() && Instant::now() < socket_ready_deadline {
        if let Some(handle) = server_jh.as_ref() {
            if handle.is_finished() {
                let result = server_jh.take().unwrap().await?;
                return Err(FuzzerError::FuzzTargetExitedEarly {
                    result: format!("{result:?}"),
                });
            }
        }
        sleep(SOCKET_POLL_INTERVAL).await;
    }
    if !socket_path.exists() {
        return Err(FuzzerError::SocketNotCreated {
            path: socket_path.display().to_string(),
        });
    }

    // Connect to the client (fuzzer)
    let mut client = FuzzClient::connect(&socket_path).await?;

    // Handshakes as client
    client.handshake(fuzzer_peer_info()).await?;

    // Initialize
    let (init_path, init_post_state, init_post_state_root, init_header) =
        if let Some((genesis_path, genesis_case)) = trace_suite.genesis {
            let genesis_header: BlockHeader = genesis_case.header.into();
            let genesis_state_root = genesis_case.state.state_root.clone();
            (
                genesis_path,
                genesis_case.state,
                genesis_state_root,
                genesis_header,
            )
        } else {
            let (init_path, init_case) = cases[0].clone();
            let init_block: Block = init_case.block.clone().into();
            let init_post_state_root = init_case.post_state.state_root.clone();
            cases = cases.split_off(1);
            (
                init_path,
                init_case.post_state,
                init_post_state_root,
                init_block.header,
            )
        };

    let init = Initialize {
        header: init_header,
        state: init_post_state.into(),
        ancestry: Ancestry::default(),
    };
    let init_root = client.initialize(init).await?;
    if init_root.0 != init_post_state_root {
        return Err(FuzzerError::InitializeStateRootMismatch {
            path: init_path.display().to_string(),
            expected: init_post_state_root.to_hex(),
            got: init_root.0.to_hex(),
        });
    }

    // Fuzz target imports blocks
    for (case_path, case) in cases.iter() {
        let block: Block = case.block.clone().into();
        let expected_root = case.post_state.state_root.clone();
        let import_start = Instant::now();
        let response = client.import_block(ImportBlock(block.clone())).await?;

        // Block import hook: per-block measurement, stats, etc.
        on_import(case_path, import_start.elapsed());
        match response {
            FuzzMessageKind::StateRoot(root) => {
                if root.0 != expected_root {
                    let header_hash = block.header.hash()?;
                    let _ = client.get_state(GetState(header_hash)).await?;
                    return Err(FuzzerError::StateRootMismatch {
                        path: case_path.display().to_string(),
                        expected: expected_root.to_hex(),
                        got: root.0.to_hex(),
                    });
                }
            }
            FuzzMessageKind::Error(err) => {
                if case.pre_state.state_root != case.post_state.state_root {
                    return Err(FuzzerError::FuzzImportError {
                        path: case_path.display().to_string(),
                        error: String::from_utf8_lossy(&err).into_owned(),
                    });
                }
            }
            kind => {
                return Err(FuzzerError::UnexpectedImportResp {
                    path: case_path.display().to_string(),
                    kind: format!("{kind:?}"),
                });
            }
        }
    }

    // Cleanup
    if let Some(handle) = server_jh.take() {
        handle.abort();
    }

    Ok(())
}

pub async fn run_fuzz_trace_dir(trace_dir: &str) -> Result<(), FuzzerError> {
    run_fuzz_trace_dir_internal(trace_dir, |_path, _elapsed| {}).await
}

/// Runs a fuzz trace directory and returns per-block import timings.
pub async fn run_fuzz_trace_dir_with_timings(
    trace_dir: &str,
) -> Result<Vec<FuzzImportTiming>, FuzzerError> {
    let mut timings = Vec::new();
    run_fuzz_trace_dir_internal(trace_dir, |path, duration| {
        timings.push(FuzzImportTiming {
            path: path.to_path_buf(),
            duration,
        });
    })
    .await?;
    Ok(timings)
}
