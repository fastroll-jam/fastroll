#[cfg(test)]
mod fuzz_target_tests {
    #![allow(dead_code)]
    use crate::{
        fuzz_target::FuzzTargetRunner,
        types::{FuzzMessageKind, PeerInfo, SetState, Version},
        utils::StreamUtils,
    };
    use fr_common::utils::{serde::FileLoader, tracing::setup_tracing};
    use fr_integration::importer_harness::AsnTestCase as BlockImportCase;
    use std::{error::Error, path::PathBuf, str::FromStr, time::Duration};
    use tokio::{net::UnixStream, time::timeout};

    fn socket_path() -> String {
        String::from("/tmp/test_socket.sock")
    }

    fn create_test_peer_info(name: &str) -> PeerInfo {
        PeerInfo::new(
            name.to_string(),
            Version::from_str("0.1.0").unwrap(),
            Version::from_str("0.1.0").unwrap(),
        )
    }

    fn init_fuzz_target_runner() -> FuzzTargetRunner {
        FuzzTargetRunner::new(create_test_peer_info("TestFastRoll"))
    }

    fn load_test_case() -> BlockImportCase {
        let path = "src/data/00000001.json";
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

    #[tokio::test]
    async fn test_fuzz_set_state() -> Result<(), Box<dyn Error>> {
        setup_tracing();

        let socket_path = socket_path();

        // Run server (fuzz target)
        let mut fuzz_target = init_fuzz_target_runner();
        let socket_path_cloned = socket_path.clone();
        let server_jh = tokio::spawn(async move {
            if let Err(e) = fuzz_target.run_as_fuzz_target(socket_path_cloned).await {
                tracing::error!("Fuzz target runner error: {e:?}");
            }
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect client (fuzzer)
        let socket_path_cloned = socket_path.clone();
        let mut client = UnixStream::connect(socket_path_cloned).await?;

        // Handshake
        StreamUtils::send_message(
            &mut client,
            FuzzMessageKind::PeerInfo(create_test_peer_info("TestFuzzer")),
        )
        .await?;

        let _ = StreamUtils::read_message(&mut client).await?;

        // Load test case

        let test_case = load_test_case();

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
        drop(client);
        server_jh.abort();
        let _ = std::fs::remove_file(&socket_path);

        Ok(())
    }
}
