#[cfg(test)]
mod fuzz_target_tests {
    #![allow(dead_code)]
    use crate::{
        fuzz_target::FuzzTargetRunner,
        types::{FuzzMessageKind, ImportBlock, PeerInfo, SetState, Version},
        utils::StreamUtils,
    };
    use fr_common::utils::{serde::FileLoader, tracing::setup_tracing};
    use fr_integration::importer_harness::AsnTestCase as BlockImportCase;
    use std::{error::Error, path::PathBuf, str::FromStr, time::Duration};
    use tempfile::tempdir;
    use tokio::{net::UnixStream, task::JoinHandle, time::timeout};

    fn socket_path() -> String {
        let path = PathBuf::from_str("/tmp").unwrap();
        path.join(tempdir().unwrap().path())
            .to_str()
            .unwrap()
            .to_string()
    }

    fn create_test_peer_info(name: &str) -> PeerInfo {
        PeerInfo::new(
            name.to_string(),
            Version::from_str("0.1.0").unwrap(),
            Version::from_str("0.1.0").unwrap(),
        )
    }

    fn init_fuzz_target_runner() -> FuzzTargetRunner {
        FuzzTargetRunner::new_for_test(create_test_peer_info("TestFastRoll"))
    }

    fn load_test_case(block_number: usize) -> BlockImportCase {
        let path = format!("src/data/0000000{block_number}.json");
        let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
        FileLoader::load_from_json_file(&full_path)
    }

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

    fn run_fuzz_target(socket_path: String) -> Result<JoinHandle<()>, Box<dyn Error>> {
        let mut fuzz_target = init_fuzz_target_runner();
        let server_jh = tokio::spawn(async move {
            if let Err(e) = fuzz_target.run_as_fuzz_target(socket_path).await {
                tracing::error!("Fuzz target runner error: {e:?}");
            }
        });
        Ok(server_jh)
    }

    async fn handshake_as_fuzzer(
        client: &mut UnixStream,
    ) -> Result<FuzzMessageKind, Box<dyn Error>> {
        StreamUtils::send_message(
            client,
            FuzzMessageKind::PeerInfo(create_test_peer_info("TestFuzzer")),
        )
        .await?;
        StreamUtils::read_message(client).await
    }

    #[tokio::test]
    async fn test_fuzz_handshake() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let socket_path = socket_path();

        // Run server (fuzz target)
        let server_jh = run_fuzz_target(socket_path.clone())?;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect client (fuzzer)
        let mut client = UnixStream::connect(socket_path.clone()).await?;

        // Handshake
        let response = handshake_as_fuzzer(&mut client).await?;
        match response {
            FuzzMessageKind::PeerInfo(info) => {
                assert_eq!(info, create_test_peer_info("TestFastRoll"));
            }
            kind => panic!("Expected PeerInfo response. Got: {kind:?}"),
        }

        // Cleanup
        drop(client);
        server_jh.abort();
        let _ = std::fs::remove_file(&socket_path);
        Ok(())
    }

    // Handshake + SetState
    #[tokio::test]
    async fn test_fuzz_set_state() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let socket_path = socket_path();

        // Run server (fuzz target)
        let server_jh = run_fuzz_target(socket_path.clone())?;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect client (fuzzer)
        let mut client = UnixStream::connect(socket_path.clone()).await?;

        // Handshake
        let _ = handshake_as_fuzzer(&mut client).await?;

        // Load test case
        let test_case = load_test_case(1);

        // Test with post-state of the case
        let test_state = test_case.post_state;

        // Send message (SetState)
        StreamUtils::send_message(
            &mut client,
            FuzzMessageKind::SetState(SetState {
                header: test_case.block.header.into(),
                state: test_state.clone().into(),
            }),
        )
        .await?;

        // Receive response for SetState (StateRoot)
        let response = timeout(
            Duration::from_secs(3),
            StreamUtils::read_message(&mut client),
        )
        .await??;
        match response {
            FuzzMessageKind::StateRoot(root) => {
                assert_eq!(root.0, test_state.state_root);
            }
            kind => panic!("Expected StateRoot response. Got: {kind:?}"),
        }

        // Cleanup
        server_jh.abort();
        let _ = std::fs::remove_file(&socket_path);
        Ok(())
    }

    // Handshake + SetState + ImportBlock
    #[tokio::test]
    async fn test_fuzz_block_import_single() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let socket_path = socket_path();

        // Run server (fuzz target)
        let server_jh = run_fuzz_target(socket_path.clone())?;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect client (fuzzer)
        let mut client = UnixStream::connect(socket_path.clone()).await?;

        // Handshake
        let _ = handshake_as_fuzzer(&mut client).await?;

        // Load test case
        let test_case_1 = load_test_case(1); // Block #1
        let test_case_2 = load_test_case(2); // Block #2

        // --- Set State (post-state of Block #1 == pre-state of Block #2)

        // Send message (SetState)
        StreamUtils::send_message(
            &mut client,
            FuzzMessageKind::SetState(SetState {
                header: test_case_1.block.header.clone().into(),
                state: test_case_1.post_state.clone().into(),
            }),
        )
        .await?;

        // Receive response for SetState (StateRoot)
        let _response = timeout(
            Duration::from_secs(3),
            StreamUtils::read_message(&mut client),
        )
        .await??;

        // --- Import Block

        // Send message (ImportBlock)
        StreamUtils::send_message(
            &mut client,
            FuzzMessageKind::ImportBlock(ImportBlock(test_case_2.block.into())),
        )
        .await?;

        // Receive response for ImportBlock (StateRoot)
        let response = timeout(
            Duration::from_secs(3),
            StreamUtils::read_message(&mut client),
        )
        .await??;
        match response {
            FuzzMessageKind::StateRoot(root) => {
                assert_eq!(root.0, test_case_2.post_state.state_root);
            }
            kind => panic!("Expected StateRoot response. Got: {kind:?}"),
        }

        // Cleanup
        drop(client);
        server_jh.abort();
        let _ = std::fs::remove_file(&socket_path);
        Ok(())
    }

    // Handshake + SetState + ImportBlock (invalid)
    #[tokio::test]
    async fn test_fuzz_block_import_single_invalid_block() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let socket_path = socket_path();

        // Run server (fuzz target)
        let server_jh = run_fuzz_target(socket_path.clone())?;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect client (fuzzer)
        let mut client = UnixStream::connect(socket_path.clone()).await?;

        // Handshake
        let _ = handshake_as_fuzzer(&mut client).await?;

        // Load test case
        let test_case_1 = load_test_case(1); // Block #1
        let mut test_case_2 = load_test_case(2); // Block #2
        test_case_2.block.header.slot = 0; // Fault injection

        // --- Set State (post-state of Block #1 == pre-state of Block #2)

        // Send message (SetState)
        StreamUtils::send_message(
            &mut client,
            FuzzMessageKind::SetState(SetState {
                header: test_case_1.block.header.clone().into(),
                state: test_case_1.post_state.clone().into(),
            }),
        )
        .await?;

        // Receive response for SetState (StateRoot)
        let _response = timeout(
            Duration::from_secs(3),
            StreamUtils::read_message(&mut client),
        )
        .await??;

        // --- Import Block

        // Send message (ImportBlock; invalid block)
        StreamUtils::send_message(
            &mut client,
            FuzzMessageKind::ImportBlock(ImportBlock(test_case_2.block.into())),
        )
        .await?;

        // Receive response for ImportBlock (StateRoot)
        let response = timeout(
            Duration::from_secs(3),
            StreamUtils::read_message(&mut client),
        )
        .await??;
        match response {
            FuzzMessageKind::StateRoot(root) => {
                // Invalid block; should return the last valid state root
                assert_eq!(root.0, test_case_1.post_state.state_root);
            }
            kind => panic!("Expected StateRoot response. Got: {kind:?}"),
        }

        // Cleanup
        drop(client);
        server_jh.abort();
        let _ = std::fs::remove_file(&socket_path);
        Ok(())
    }
}
