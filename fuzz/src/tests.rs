#![allow(dead_code, unused_imports)]
#[cfg(test)]
mod fuzz_target_tests {
    use crate::{
        fuzz_target::{FuzzTargetError, FuzzTargetRunner},
        types::{
            Ancestry, AncestryItem, FuzzMessageKind, GetState, HeaderHash, ImportBlock, Initialize,
            PeerInfo, State, StateRoot, Version,
        },
        utils::StreamUtils,
    };
    use fr_block::types::block::BlockHeader;
    use fr_common::{
        utils::{serde::FileReader, tracing::setup_tracing},
        ByteEncodable,
    };
    use fr_test_utils::importer_harness::AsnTestCase as BlockImportCase;
    use std::{path::PathBuf, str::FromStr, time::Duration};
    use tempfile::tempdir;
    use tokio::{net::UnixStream, task::JoinHandle, time::timeout};

    fn cleanup_socket(path: &str) {
        std::fs::remove_file(path).unwrap();
    }

    fn create_test_peer_info(name: &str) -> PeerInfo {
        PeerInfo::new(
            1,
            0,
            Version::from_str("0.5.0").unwrap(),
            Version::from_str("0.1.0").unwrap(),
            name.to_string(),
        )
    }

    fn init_fuzz_target_runner() -> FuzzTargetRunner {
        FuzzTargetRunner::new(create_test_peer_info("TestFastRoll"))
            .expect("Failed to create FuzzTargetRunner")
    }

    fn load_test_case(block_number: usize) -> BlockImportCase {
        let path = format!("src/data/0000000{block_number}.json");
        let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
        FileReader::read_json(&full_path).expect("Failed to read from JSON")
    }

    #[allow(dead_code)]
    fn load_all_test_cases() -> Vec<BlockImportCase> {
        let filenames = ["00000001", "00000002", "00000003", "00000004", "00000005"];
        filenames
            .iter()
            .map(|&filename| {
                let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join(format!("./data/{filename}.json"));
                FileReader::read_json(&full_path).expect("Failed to read from JSON")
            })
            .collect()
    }

    fn run_fuzz_target(socket_path: String) -> Result<JoinHandle<()>, FuzzTargetError> {
        let mut fuzz_target = init_fuzz_target_runner();
        let server_jh = tokio::spawn(async move {
            if let Err(e) = fuzz_target.run_as_fuzz_target(socket_path).await {
                tracing::error!("Fuzz target runner error: {e:?}");
            }
        });
        Ok(server_jh)
    }

    struct MockFuzzer;
    impl MockFuzzer {
        /// Send PeerInfo (handshake) message to the fuzz target and receive PeerInfo message.
        async fn handshake(client: &mut UnixStream) -> Result<PeerInfo, FuzzTargetError> {
            StreamUtils::send_message(
                client,
                FuzzMessageKind::PeerInfo(create_test_peer_info("TestFuzzer")),
            )
            .await?;
            let res = timeout(Duration::from_secs(3), StreamUtils::read_message(client)).await??;
            match res {
                FuzzMessageKind::PeerInfo(info) => Ok(info),
                kind => panic!("[PeerInfo] Expected PeerInfo response. Got: {kind:?}"),
            }
        }

        /// Send Initialize message to the fuzz target and receive StateRoot message.
        async fn initialize(
            client: &mut UnixStream,
            initialize_message: Initialize,
        ) -> Result<StateRoot, FuzzTargetError> {
            StreamUtils::send_message(client, FuzzMessageKind::Initialize(initialize_message))
                .await?;
            let res = timeout(Duration::from_secs(3), StreamUtils::read_message(client)).await??;
            match res {
                FuzzMessageKind::StateRoot(root) => Ok(root),
                kind => panic!("[Initialize] Expected StateRoot response. Got: {kind:?}"),
            }
        }

        /// Send ImportBlock message to the fuzz target and receive StateRoot message.
        async fn import_block(
            client: &mut UnixStream,
            import_block_message: ImportBlock,
        ) -> Result<FuzzMessageKind, FuzzTargetError> {
            StreamUtils::send_message(client, FuzzMessageKind::ImportBlock(import_block_message))
                .await?;
            let res = timeout(Duration::from_secs(3), StreamUtils::read_message(client)).await??;
            Ok(res)
        }

        /// Send GetState message to the fuzz target and receive State message.
        async fn get_state(
            client: &mut UnixStream,
            get_state_message: GetState,
        ) -> Result<State, FuzzTargetError> {
            StreamUtils::send_message(client, FuzzMessageKind::GetState(get_state_message)).await?;
            let res = timeout(Duration::from_secs(3), StreamUtils::read_message(client)).await??;
            match res {
                FuzzMessageKind::State(state) => Ok(state),
                kind => panic!("[GetState] Expected State response. Got: {kind:?}"),
            }
        }
    }

    #[tokio::test]
    async fn test_fuzz_handshake() -> Result<(), FuzzTargetError> {
        setup_tracing();
        let _temp_dir_sock = tempdir().unwrap();
        let socket_path = _temp_dir_sock
            .path()
            .join("fuzz_socket")
            .to_str()
            .unwrap()
            .to_string();

        // Run server (fuzz target)
        let _server_jh = run_fuzz_target(socket_path.clone())?;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect client (fuzzer)
        let mut client = UnixStream::connect(socket_path.clone()).await?;

        // --- Handshake
        let peer_info = MockFuzzer::handshake(&mut client).await?;
        assert_eq!(peer_info, create_test_peer_info("TestFastRoll"));

        // Cleanup
        cleanup_socket(&socket_path);
        Ok(())
    }

    #[tokio::test]
    async fn test_fuzz_initialize_set_ancestry() -> Result<(), FuzzTargetError> {
        let ancestor_1 = HeaderHash::from_hex("0x1")?;
        let ancestor_2 = HeaderHash::from_hex("0x2")?;
        let ancestor_3 = HeaderHash::from_hex("0x3")?;
        let ancestry = Ancestry::try_from(vec![
            AncestryItem {
                slot: 1,
                header_hash: ancestor_1.clone(),
            },
            AncestryItem {
                slot: 2,
                header_hash: ancestor_2.clone(),
            },
            AncestryItem {
                slot: 3,
                header_hash: ancestor_3.clone(),
            },
        ])?;
        let fuzz_target = init_fuzz_target_runner();
        fuzz_target.set_ancestors(ancestry).await?;

        assert!(fuzz_target
            .node_storage
            .header_db()
            .header_exists_in_ancestor_set(&(1, ancestor_1)));
        assert!(fuzz_target
            .node_storage
            .header_db()
            .header_exists_in_ancestor_set(&(2, ancestor_2)));
        assert!(fuzz_target
            .node_storage
            .header_db()
            .header_exists_in_ancestor_set(&(3, ancestor_3)));
        Ok(())
    }

    // Handshake + Initialize
    #[tokio::test]
    async fn test_fuzz_initialize() -> Result<(), FuzzTargetError> {
        setup_tracing();
        let _temp_dir_sock = tempdir().unwrap();
        let socket_path = _temp_dir_sock
            .path()
            .join("fuzz_socket")
            .to_str()
            .unwrap()
            .to_string();

        // Run server (fuzz target)
        let _server_jh = run_fuzz_target(socket_path.clone())?;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect client (fuzzer)
        let mut client = UnixStream::connect(socket_path.clone()).await?;

        // --- Handshake
        let _ = MockFuzzer::handshake(&mut client).await?;

        // Load test case
        let test_case = load_test_case(1);

        // Test with post-state of the case
        let test_state = test_case.post_state;

        // --- Initialize
        let root = MockFuzzer::initialize(
            &mut client,
            Initialize {
                header: test_case.block.header.into(),
                state: test_state.clone().into(),
                ancestry: Ancestry::default(),
            },
        )
        .await?;
        assert_eq!(root.0, test_state.state_root);

        // Cleanup
        cleanup_socket(&socket_path);
        Ok(())
    }

    #[tokio::test]
    async fn test_fuzz_reinitialize_in_same_session() -> Result<(), FuzzTargetError> {
        setup_tracing();
        let _temp_dir_sock = tempdir().unwrap();
        let socket_path = _temp_dir_sock
            .path()
            .join("fuzz_socket")
            .to_str()
            .unwrap()
            .to_string();

        let _server_jh = run_fuzz_target(socket_path.clone())?;
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut client = UnixStream::connect(socket_path.clone()).await?;
        let _ = MockFuzzer::handshake(&mut client).await?;

        let test_case_1 = load_test_case(1);
        let test_case_2 = load_test_case(2);

        let root_1 = MockFuzzer::initialize(
            &mut client,
            Initialize {
                header: test_case_1.block.header.clone().into(),
                state: test_case_1.post_state.clone().into(),
                ancestry: Ancestry::default(),
            },
        )
        .await?;
        assert_eq!(root_1.0, test_case_1.post_state.state_root);

        let root_2 = MockFuzzer::initialize(
            &mut client,
            Initialize {
                header: test_case_2.block.header.clone().into(),
                state: test_case_2.post_state.clone().into(),
                ancestry: Ancestry::default(),
            },
        )
        .await?;
        assert_eq!(root_2.0, test_case_2.post_state.state_root);

        cleanup_socket(&socket_path);
        Ok(())
    }

    // Handshake + Initialize + ImportBlock
    #[cfg(feature = "tiny")]
    #[tokio::test]
    async fn test_fuzz_import_single_block() -> Result<(), FuzzTargetError> {
        setup_tracing();
        let _temp_dir_sock = tempdir().unwrap();
        let socket_path = _temp_dir_sock
            .path()
            .join("fuzz_socket")
            .to_str()
            .unwrap()
            .to_string();

        // Run server (fuzz target)
        let _server_jh = run_fuzz_target(socket_path.clone())?;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect client (fuzzer)
        let mut client = UnixStream::connect(socket_path.clone()).await?;

        // --- Handshake
        let _ = MockFuzzer::handshake(&mut client).await?;

        // Load test case
        let test_case_1 = load_test_case(1); // Block #1
        let test_case_2 = load_test_case(2); // Block #2

        // --- Initialize (post-state of Block #1 == pre-state of Block #2)
        let _root = MockFuzzer::initialize(
            &mut client,
            Initialize {
                header: test_case_1.block.header.clone().into(),
                state: test_case_1.post_state.clone().into(),
                ancestry: Ancestry::default(),
            },
        )
        .await?;

        // --- ImportBlock (Block #2)
        let import_res =
            MockFuzzer::import_block(&mut client, ImportBlock(test_case_2.block.into())).await?;
        match import_res {
            FuzzMessageKind::StateRoot(root) => {
                assert_eq!(root.0, test_case_2.post_state.state_root);
            }
            kind => panic!("[ImportBlock] Valid Block: Expected StateRoot response. Got: {kind:?}"),
        }

        // Cleanup
        cleanup_socket(&socket_path);
        Ok(())
    }

    // Handshake + Initialize + ImportBlock (invalid)
    #[cfg(feature = "tiny")]
    #[tokio::test]
    async fn test_fuzz_import_single_invalid_block() -> Result<(), FuzzTargetError> {
        setup_tracing();
        let _temp_dir_sock = tempdir().unwrap();
        let socket_path = _temp_dir_sock
            .path()
            .join("fuzz_socket")
            .to_str()
            .unwrap()
            .to_string();

        // Run server (fuzz target)
        let _server_jh = run_fuzz_target(socket_path.clone())?;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect client (fuzzer)
        let mut client = UnixStream::connect(socket_path.clone()).await?;

        // --- Handshake
        let _ = MockFuzzer::handshake(&mut client).await?;

        // Load test case
        let test_case_1 = load_test_case(1); // Block #1
        let mut test_case_2 = load_test_case(2); // Block #2
        test_case_2.block.header.slot = 0; // Fault injection

        // --- Initialize (post-state of Block #1 == pre-state of Block #2)
        let _root = MockFuzzer::initialize(
            &mut client,
            Initialize {
                header: test_case_1.block.header.clone().into(),
                state: test_case_1.post_state.clone().into(),
                ancestry: Ancestry::default(),
            },
        )
        .await?;

        // --- ImportBlock (Block #2; invalid)
        let import_res =
            MockFuzzer::import_block(&mut client, ImportBlock(test_case_2.block.into())).await?;
        // Invalid block; should return `Error` message
        match import_res {
            FuzzMessageKind::Error(e) => {
                println!("Fuzz Error: {}", String::from_utf8(e)?);
            }
            kind => panic!("[ImportBlock] Invalid Block: Expected Error response. Got: {kind:?}"),
        }

        // Cleanup
        cleanup_socket(&socket_path);
        Ok(())
    }

    // Handshake + Initialize + ImportBlock
    #[cfg(feature = "tiny")]
    #[tokio::test]
    async fn test_fuzz_import_two_blocks() -> Result<(), FuzzTargetError> {
        setup_tracing();
        let _temp_dir_sock = tempdir().unwrap();
        let socket_path = _temp_dir_sock
            .path()
            .join("fuzz_socket")
            .to_str()
            .unwrap()
            .to_string();

        // Run server (fuzz target)
        let _server_jh = run_fuzz_target(socket_path.clone())?;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect client (fuzzer)
        let mut client = UnixStream::connect(socket_path.clone()).await?;

        // --- Handshake
        let _ = MockFuzzer::handshake(&mut client).await?;

        // Load test case
        let test_case_1 = load_test_case(1); // Block #1
        let test_case_2 = load_test_case(2); // Block #2
        let test_case_3 = load_test_case(3); // Block #3

        // --- Initialize (post-state of Block #1 == pre-state of Block #2)
        let _root = MockFuzzer::initialize(
            &mut client,
            Initialize {
                header: test_case_1.block.header.clone().into(),
                state: test_case_1.post_state.clone().into(),
                ancestry: Ancestry::default(),
            },
        )
        .await?;

        // --- ImportBlock (Block #2)
        let import_2_res =
            MockFuzzer::import_block(&mut client, ImportBlock(test_case_2.block.into())).await?;
        match import_2_res {
            FuzzMessageKind::StateRoot(root) => {
                assert_eq!(root.0, test_case_2.post_state.state_root);
            }
            kind => panic!("[ImportBlock] Valid Block: Expected StateRoot response. Got: {kind:?}"),
        }

        // --- ImportBlock (Block #3)
        let import_3_res =
            MockFuzzer::import_block(&mut client, ImportBlock(test_case_3.block.into())).await?;
        match import_3_res {
            FuzzMessageKind::StateRoot(root) => {
                assert_eq!(root.0, test_case_3.post_state.state_root);
            }
            kind => panic!("[ImportBlock] Valid Block: Expected StateRoot response. Got: {kind:?}"),
        }

        // Cleanup
        cleanup_socket(&socket_path);
        Ok(())
    }

    // Handshake + Initialize + ImportBlock + GetState
    #[cfg(feature = "tiny")]
    #[tokio::test]
    async fn test_fuzz_get_state() -> Result<(), FuzzTargetError> {
        setup_tracing();
        let _temp_dir_sock = tempdir().unwrap();
        let socket_path = _temp_dir_sock
            .path()
            .join("fuzz_socket")
            .to_str()
            .unwrap()
            .to_string();

        // Run server (fuzz target)
        let _server_jh = run_fuzz_target(socket_path.clone())?;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect client (fuzzer)
        let mut client = UnixStream::connect(socket_path.clone()).await?;

        // --- Handshake
        let _ = MockFuzzer::handshake(&mut client).await?;

        // Load test case
        let test_case_1 = load_test_case(1); // Block #1
        let test_case_2 = load_test_case(2); // Block #2
        let test_case_3 = load_test_case(3); // Block #3

        // --- Initialize (post-state of Block #1 == pre-state of Block #2)
        let _root = MockFuzzer::initialize(
            &mut client,
            Initialize {
                header: test_case_1.block.header.clone().into(),
                state: test_case_1.post_state.clone().into(),
                ancestry: Ancestry::default(),
            },
        )
        .await?;

        // --- ImportBlock (Block #2)
        let _import_2_res =
            MockFuzzer::import_block(&mut client, ImportBlock(test_case_2.block.into())).await?;

        // --- ImportBlock (Block #3)
        let _import_3_res =
            MockFuzzer::import_block(&mut client, ImportBlock(test_case_3.block.clone().into()))
                .await?;

        // --- GetState
        let last_header_hash = BlockHeader::from(test_case_3.block.header).hash()?;
        let state = MockFuzzer::get_state(&mut client, GetState(last_header_hash)).await?;
        // Display the state report
        tracing::info!("-------------------- GetState Report --------------------");
        for kv in state.0.into_iter() {
            tracing::info!("k: {}", kv.key);
            tracing::debug!("k: {}, v: {}", kv.key, kv.value);
        }

        // Cleanup
        cleanup_socket(&socket_path);
        Ok(())
    }

    #[cfg(feature = "tiny")]
    #[tokio::test]
    async fn test_fuzz_multiple_sessions() -> Result<(), FuzzTargetError> {
        setup_tracing();
        let _temp_dir_sock = tempdir().unwrap();
        let socket_path = _temp_dir_sock
            .path()
            .join("fuzz_socket")
            .to_str()
            .unwrap()
            .to_string();

        // Run server (fuzz target)
        let _server_jh = run_fuzz_target(socket_path.clone())?;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // --- Session #1
        tracing::info!("--- Starting Session #1");
        {
            // Connect client (fuzzer)
            let mut client_1 = UnixStream::connect(socket_path.clone()).await?;

            // --- Handshake
            let _ = MockFuzzer::handshake(&mut client_1).await?;

            // Load test case
            let test_case_1 = load_test_case(1); // Block #1
            let test_case_2 = load_test_case(2); // Block #2
            let test_case_3 = load_test_case(3); // Block #3

            // --- Initialize (post-state of Block #1 == pre-state of Block #2)
            let _root = MockFuzzer::initialize(
                &mut client_1,
                Initialize {
                    header: test_case_1.block.header.clone().into(),
                    state: test_case_1.post_state.clone().into(),
                    ancestry: Ancestry::default(),
                },
            )
            .await?;

            // --- ImportBlock (Block #2)
            let _import_2_res =
                MockFuzzer::import_block(&mut client_1, ImportBlock(test_case_2.block.into()))
                    .await?;

            // --- ImportBlock (Block #3)
            let _import_3_res = MockFuzzer::import_block(
                &mut client_1,
                ImportBlock(test_case_3.block.clone().into()),
            )
            .await?;

            // --- GetState
            let last_header_hash = BlockHeader::from(test_case_3.block.header).hash()?;
            let _state = MockFuzzer::get_state(&mut client_1, GetState(last_header_hash)).await?;
        } // Session #1 drops

        tokio::time::sleep(Duration::from_millis(100)).await;

        // --- Session #2
        tracing::info!("--- Starting Session #2");
        {
            // Connect client (fuzzer)
            let mut client_2 = UnixStream::connect(socket_path.clone()).await?;

            // --- Handshake
            let peer_info = MockFuzzer::handshake(&mut client_2).await?;
            assert_eq!(peer_info, create_test_peer_info("TestFastRoll"));

            // Load test case
            let test_case_1 = load_test_case(1); // Block #1
            let test_case_2 = load_test_case(2); // Block #2
            let test_case_3 = load_test_case(3); // Block #3

            // --- Initialize (post-state of Block #1 == pre-state of Block #2)
            let root = MockFuzzer::initialize(
                &mut client_2,
                Initialize {
                    header: test_case_1.block.header.clone().into(),
                    state: test_case_1.post_state.clone().into(),
                    ancestry: Ancestry::default(),
                },
            )
            .await?;
            assert_eq!(root.0, test_case_1.post_state.state_root);

            // --- ImportBlock (Block #2)
            let import_2_res =
                MockFuzzer::import_block(&mut client_2, ImportBlock(test_case_2.block.into()))
                    .await?;
            match import_2_res {
                FuzzMessageKind::StateRoot(root) => {
                    assert_eq!(root.0, test_case_2.post_state.state_root);
                }
                kind => {
                    panic!("[ImportBlock] Valid Block: Expected StateRoot response. Got: {kind:?}")
                }
            }

            // --- ImportBlock (Block #3)
            let import_3_res =
                MockFuzzer::import_block(&mut client_2, ImportBlock(test_case_3.block.into()))
                    .await?;
            match import_3_res {
                FuzzMessageKind::StateRoot(root) => {
                    assert_eq!(root.0, test_case_3.post_state.state_root);
                }
                kind => {
                    panic!("[ImportBlock] Valid Block: Expected StateRoot response. Got: {kind:?}")
                }
            }
        }

        // Cleanup
        cleanup_socket(&socket_path);
        Ok(())
    }
}
