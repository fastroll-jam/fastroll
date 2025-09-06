#![allow(dead_code, unused_imports)]
#[cfg(test)]
mod fuzz_target_tests {
    use crate::{
        fuzz_target::{FuzzTargetError, FuzzTargetRunner},
        types::{
            FuzzMessageKind, GetState, ImportBlock, PeerInfo, SetState, State, StateRoot, Version,
        },
        utils::StreamUtils,
    };
    use fr_block::types::block::BlockHeader;
    use fr_common::utils::{serde::FileLoader, tracing::setup_tracing};
    use fr_test_utils::importer_harness::AsnTestCase as BlockImportCase;
    use std::{path::PathBuf, str::FromStr, time::Duration};
    use tempfile::tempdir;
    use tokio::{net::UnixStream, task::JoinHandle, time::timeout};

    fn temp_socket_path() -> String {
        let path = PathBuf::from_str("/tmp").unwrap();
        path.join(tempdir().unwrap().path())
            .to_str()
            .unwrap()
            .to_string()
    }

    fn cleanup_socket(path: &str) {
        std::fs::remove_file(path).unwrap();
    }

    fn create_test_peer_info(name: &str) -> PeerInfo {
        PeerInfo::new(
            name.to_string(),
            Version::from_str("0.1.0").unwrap(),
            Version::from_str("0.5.0").unwrap(),
        )
    }

    fn init_fuzz_target_runner() -> FuzzTargetRunner {
        FuzzTargetRunner::new(create_test_peer_info("TestFastRoll"))
    }

    fn load_test_case(block_number: usize) -> BlockImportCase {
        let path = format!("src/data/0000000{block_number}.json");
        let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
        FileLoader::load_from_json_file(&full_path)
    }

    #[allow(dead_code)]
    fn load_all_test_cases() -> Vec<BlockImportCase> {
        let filenames = ["00000001", "00000002", "00000003", "00000004", "00000005"];
        filenames
            .iter()
            .map(|&filename| {
                let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join(format!("./data/{filename}.json"));
                FileLoader::load_from_json_file(&full_path)
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

        /// Send SetState message to the fuzz target and receive StateRoot message.
        async fn set_state(
            client: &mut UnixStream,
            set_state_message: SetState,
        ) -> Result<StateRoot, FuzzTargetError> {
            StreamUtils::send_message(client, FuzzMessageKind::SetState(set_state_message)).await?;
            let res = timeout(Duration::from_secs(3), StreamUtils::read_message(client)).await??;
            match res {
                FuzzMessageKind::StateRoot(root) => Ok(root),
                kind => panic!("[SetState] Expected StateRoot response. Got: {kind:?}"),
            }
        }

        /// Send ImportBlock message to the fuzz target and receive StateRoot message.
        async fn import_block(
            client: &mut UnixStream,
            import_block_message: ImportBlock,
        ) -> Result<StateRoot, FuzzTargetError> {
            StreamUtils::send_message(client, FuzzMessageKind::ImportBlock(import_block_message))
                .await?;
            let res = timeout(Duration::from_secs(3), StreamUtils::read_message(client)).await??;
            match res {
                FuzzMessageKind::StateRoot(root) => Ok(root),
                kind => panic!("[ImportBlock] Expected StateRoot response. Got: {kind:?}"),
            }
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
        let socket_path = temp_socket_path();

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

    // Handshake + SetState
    #[tokio::test]
    async fn test_fuzz_set_state() -> Result<(), FuzzTargetError> {
        setup_tracing();
        let socket_path = temp_socket_path();

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

        // --- SetState
        let root = MockFuzzer::set_state(
            &mut client,
            SetState {
                header: test_case.block.header.into(),
                state: test_state.clone().into(),
            },
        )
        .await?;
        assert_eq!(root.0, test_state.state_root);

        // Cleanup
        cleanup_socket(&socket_path);
        Ok(())
    }

    // Handshake + SetState + ImportBlock
    #[cfg(feature = "tiny")]
    #[tokio::test]
    #[ignore] // FIXME: block test cases should be aligned with GP v0.7.1
    async fn test_fuzz_import_single_block() -> Result<(), FuzzTargetError> {
        setup_tracing();
        let socket_path = temp_socket_path();

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

        // --- SetState (post-state of Block #1 == pre-state of Block #2)
        let _root = MockFuzzer::set_state(
            &mut client,
            SetState {
                header: test_case_1.block.header.clone().into(),
                state: test_case_1.post_state.clone().into(),
            },
        )
        .await?;

        // --- ImportBlock (Block #2)
        let root =
            MockFuzzer::import_block(&mut client, ImportBlock(test_case_2.block.into())).await?;
        assert_eq!(root.0, test_case_2.post_state.state_root);

        // Cleanup
        cleanup_socket(&socket_path);
        Ok(())
    }

    // Handshake + SetState + ImportBlock (invalid)
    #[cfg(feature = "tiny")]
    #[tokio::test]
    #[ignore] // FIXME: block test cases should be aligned with GP v0.7.1
    async fn test_fuzz_import_single_invalid_block() -> Result<(), FuzzTargetError> {
        setup_tracing();
        let socket_path = temp_socket_path();

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

        // --- SetState (post-state of Block #1 == pre-state of Block #2)
        let _root = MockFuzzer::set_state(
            &mut client,
            SetState {
                header: test_case_1.block.header.clone().into(),
                state: test_case_1.post_state.clone().into(),
            },
        )
        .await?;

        // --- ImportBlock (Block #2; invalid)
        let root =
            MockFuzzer::import_block(&mut client, ImportBlock(test_case_2.block.into())).await?;
        // Invalid block; should return the last valid state root
        assert_eq!(root.0, test_case_1.post_state.state_root);

        // Cleanup
        cleanup_socket(&socket_path);
        Ok(())
    }

    // Handshake + SetState + ImportBlock
    #[cfg(feature = "tiny")]
    #[tokio::test]
    #[ignore] // FIXME: block test cases should be aligned with GP v0.7.1
    async fn test_fuzz_import_two_blocks() -> Result<(), FuzzTargetError> {
        setup_tracing();
        let socket_path = temp_socket_path();

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

        // --- SetState (post-state of Block #1 == pre-state of Block #2)
        let _root = MockFuzzer::set_state(
            &mut client,
            SetState {
                header: test_case_1.block.header.clone().into(),
                state: test_case_1.post_state.clone().into(),
            },
        )
        .await?;

        // --- ImportBlock (Block #2)
        let root =
            MockFuzzer::import_block(&mut client, ImportBlock(test_case_2.block.into())).await?;
        assert_eq!(root.0, test_case_2.post_state.state_root);

        // --- ImportBlock (Block #3)
        let root =
            MockFuzzer::import_block(&mut client, ImportBlock(test_case_3.block.into())).await?;
        assert_eq!(root.0, test_case_3.post_state.state_root);

        // Cleanup
        cleanup_socket(&socket_path);
        Ok(())
    }

    // Handshake + SetState + ImportBlock + GetState
    #[cfg(feature = "tiny")]
    #[tokio::test]
    #[ignore] // FIXME: block test cases should be aligned with GP v0.7.1
    async fn test_fuzz_get_state() -> Result<(), FuzzTargetError> {
        setup_tracing();
        let socket_path = temp_socket_path();

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

        // --- SetState (post-state of Block #1 == pre-state of Block #2)
        let _root = MockFuzzer::set_state(
            &mut client,
            SetState {
                header: test_case_1.block.header.clone().into(),
                state: test_case_1.post_state.clone().into(),
            },
        )
        .await?;

        // --- ImportBlock (Block #2)
        let _root =
            MockFuzzer::import_block(&mut client, ImportBlock(test_case_2.block.into())).await?;

        // --- ImportBlock (Block #3)
        let _root =
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
    #[ignore] // FIXME: block test cases should be aligned with GP v0.7.1
    async fn test_fuzz_multiple_sessions() -> Result<(), FuzzTargetError> {
        setup_tracing();
        let socket_path = temp_socket_path();

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

            // --- SetState (post-state of Block #1 == pre-state of Block #2)
            let _root = MockFuzzer::set_state(
                &mut client_1,
                SetState {
                    header: test_case_1.block.header.clone().into(),
                    state: test_case_1.post_state.clone().into(),
                },
            )
            .await?;

            // --- ImportBlock (Block #2)
            let _root =
                MockFuzzer::import_block(&mut client_1, ImportBlock(test_case_2.block.into()))
                    .await?;

            // --- ImportBlock (Block #3)
            let _root = MockFuzzer::import_block(
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

            // --- SetState (post-state of Block #1 == pre-state of Block #2)
            let root = MockFuzzer::set_state(
                &mut client_2,
                SetState {
                    header: test_case_1.block.header.clone().into(),
                    state: test_case_1.post_state.clone().into(),
                },
            )
            .await?;
            assert_eq!(root.0, test_case_1.post_state.state_root);

            // --- ImportBlock (Block #2)
            let root =
                MockFuzzer::import_block(&mut client_2, ImportBlock(test_case_2.block.into()))
                    .await?;
            assert_eq!(root.0, test_case_2.post_state.state_root);

            // --- ImportBlock (Block #3)
            let root = MockFuzzer::import_block(
                &mut client_2,
                ImportBlock(test_case_3.block.clone().into()),
            )
            .await?;
            assert_eq!(root.0, test_case_3.post_state.state_root);
        }

        // Cleanup
        cleanup_socket(&socket_path);
        Ok(())
    }
}
