//! Erasure codec conformance tests
mod erasure {
    use fr_asn_types::{types::common::AsnByteSequence, utils::AsnTypeLoader};
    use fr_common::utils::tracing::setup_timed_tracing;
    use fr_erasure_coding::ReedSolomon;
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
        test_encode_internal(&full_path, ReedSolomon::new_full());
    }

    pub fn test_encode_tiny(filename: &str) {
        let json_path = PathBuf::from(PATH_PREFIX_TINY).join(format!("{filename}.json"));
        let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(json_path);
        test_encode_internal(&full_path, ReedSolomon::new_tiny());
    }

    fn test_encode_internal(path: &Path, rs: ReedSolomon) {
        setup_timed_tracing();
        let test_case: TestCase = AsnTypeLoader::load_from_json_file(path);
        let shards = rs.erasure_encode(&test_case.data.0).unwrap();
        let shards_expected = test_case
            .shards
            .into_iter()
            .map(|s| s.0)
            .collect::<Vec<_>>();
        assert_eq!(shards, shards_expected);
    }

    pub fn test_recover_full(filename: &str) {
        let json_path = PathBuf::from(PATH_PREFIX_FULL).join(format!("{filename}.json"));
        let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(json_path);
        test_recover_internal(&full_path, ReedSolomon::new_full());
    }

    pub fn test_recover_tiny(filename: &str) {
        let json_path = PathBuf::from(PATH_PREFIX_TINY).join(format!("{filename}.json"));
        let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(json_path);
        test_recover_internal(&full_path, ReedSolomon::new_tiny());
    }

    fn test_recover_internal(path: &Path, rs: ReedSolomon) {
        setup_timed_tracing();
        let test_case: TestCase = AsnTypeLoader::load_from_json_file(path);

        // Generate random shard indices
        let mut indices: Vec<usize> = (0..rs.total_words()).collect();
        indices.shuffle(&mut thread_rng());
        let rand_shard_indices = indices[..rs.msg_words()].to_vec();

        let mut shards: Vec<Option<Vec<u8>>> = vec![None; rs.total_words()];
        for i in rand_shard_indices {
            shards[i] = Some(test_case.shards[i].0.clone());
        }
        let recovered = rs.erasure_recover(shards).unwrap();
        let data_expected = test_case.data.0;
        // The erasure encoder input must be padded
        let data_expected_padded = ReedSolomon::zero_pad_data(&data_expected, rs.msg_words());
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
        erasure_coding_3: "ec-3",
        erasure_coding_32: "ec-32",
        erasure_coding_100: "ec-100",
        erasure_coding_4096: "ec-4096",
        erasure_coding_4104: "ec-4104",
        erasure_coding_10000: "ec-10000",
    }
}
