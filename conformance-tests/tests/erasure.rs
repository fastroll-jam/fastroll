//! Erasure codec conformance tests
mod erasure {
    use fr_asn_types::common::AsnByteSequence;
    use fr_common::utils::{serde::FileLoader, tracing::setup_timed_tracing};
    use fr_erasure_coding::ErasureCodec;
    use rand::{seq::SliceRandom, thread_rng};
    use serde::{Deserialize, Serialize};
    use std::path::{Path, PathBuf};

    const PATH_PREFIX_FULL: &str = "jamtestvectors/erasure/full";
    const PATH_PREFIX_TINY: &str = "jamtestvectors/erasure/tiny";

    // --- Types
    #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
    pub struct TestCase {
        data: AsnByteSequence,
        shards: Vec<AsnByteSequence>, // length of VALIDATOR_COUNT
    }

    pub fn test_encode_full(filename: &str) {
        let json_path = PathBuf::from(PATH_PREFIX_FULL).join(format!("{filename}.json"));
        let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(json_path);
        test_encode_internal(&full_path, ErasureCodec::new_full());
    }

    pub fn test_encode_tiny(filename: &str) {
        let json_path = PathBuf::from(PATH_PREFIX_TINY).join(format!("{filename}.json"));
        let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(json_path);
        test_encode_internal(&full_path, ErasureCodec::new_tiny());
    }

    fn test_encode_internal(path: &Path, rs: ErasureCodec) {
        setup_timed_tracing();
        let test_case: TestCase = FileLoader::load_from_json_file(path);
        let chunks = rs.erasure_encode(&test_case.data.0).unwrap();
        let chunks_expected = test_case
            .shards
            .into_iter()
            .map(|s| s.0)
            .collect::<Vec<_>>();
        assert_eq!(chunks, chunks_expected);
    }

    pub fn test_recover_full(filename: &str) {
        let json_path = PathBuf::from(PATH_PREFIX_FULL).join(format!("{filename}.json"));
        let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(json_path);
        test_recover_internal(&full_path, ErasureCodec::new_full());
    }

    pub fn test_recover_tiny(filename: &str) {
        let json_path = PathBuf::from(PATH_PREFIX_TINY).join(format!("{filename}.json"));
        let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(json_path);
        test_recover_internal(&full_path, ErasureCodec::new_tiny());
    }

    fn test_recover_internal(path: &Path, rs: ErasureCodec) {
        setup_timed_tracing();
        let test_case: TestCase = FileLoader::load_from_json_file(path);

        // Generate random chunk indices
        let mut indices: Vec<usize> = (0..rs.total_chunks()).collect();
        indices.shuffle(&mut thread_rng());
        let rand_chunk_indices = indices[..rs.msg_chunks()].to_vec();

        let mut chunks: Vec<Option<Vec<u8>>> = vec![None; rs.total_chunks()];
        for i in rand_chunk_indices {
            chunks[i] = Some(test_case.shards[i].0.clone());
        }
        let recovered = rs.erasure_recover(chunks).unwrap();
        let data_expected = test_case.data.0;
        // The erasure encoder input must be padded
        let data_expected_padded = ErasureCodec::zero_pad_data(&data_expected, rs.msg_chunks());
        if recovered != data_expected_padded {
            println!(
                "actual(len={}): {}\nexpected(len={}): {}",
                recovered.len(),
                hex::encode(&recovered),
                data_expected_padded.len(),
                hex::encode(&data_expected_padded)
            );
        }
        assert_eq!(recovered, data_expected_padded);
    }

    macro_rules! generate_erasure_tests {
        ($($name:ident: $path:expr,)*) => {
            paste::paste! {
                $(
                    #[test]
                    fn [<$name _encode_full>]() {
                        test_encode_full($path);
                    }
                    #[test]
                    fn [<$name _encode_tiny>]() {
                        test_encode_tiny($path);
                    }
                    #[test]
                    fn [<$name _recover_full>]() {
                        test_recover_full($path);
                    }
                    #[test]
                    fn [<$name _recover_tiny>]() {
                        test_recover_tiny($path);
                    }
                )*
            }
        };
    }

    generate_erasure_tests! {
        erasure_3: "ec-3",
        erasure_32: "ec-32",
        erasure_100: "ec-100",
        erasure_4096: "ec-4096",
        erasure_4104: "ec-4104",
        erasure_10000: "ec-10000",
    }
}
