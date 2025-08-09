//! Fisher-Yates Shuffle function integration tests
mod shuffle {
    use fr_common::Hash32;
    use fr_extrinsics::utils::shuffle::shuffle_with_hash;
    use serde::{Deserialize, Serialize};
    use std::{fs, path::PathBuf};

    const PATH: &str = "jamtestvectors/shuffle/shuffle_tests.json";

    #[derive(Serialize, Deserialize)]
    struct ShuffleTestData {
        input: u16, // input length
        entropy: String,
        output: Vec<u16>,
    }

    impl ShuffleTestData {
        fn generate_input(&self) -> Vec<u16> {
            (0..self.input).collect()
        }

        fn entropy_as_hash(&self) -> Hash32 {
            Hash32::new(
                hex::decode(&self.entropy)
                    .expect("Failed to decode entropy hexstring")
                    .try_into()
                    .expect("Invalid Hash32 input"),
            )
        }
    }

    fn load_test_data() -> Vec<ShuffleTestData> {
        let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(PATH);
        let json_str = fs::read_to_string(&full_path).expect("Failed to read test vector file");
        serde_json::from_str(&json_str).expect("Failed to parse JSON")
    }

    #[test]
    fn test_fisher_yates_shuffle() {
        let test_data_vec = load_test_data();
        for test_data in test_data_vec {
            let shuffle_input = test_data.generate_input();
            let shuffle_output = shuffle_with_hash(shuffle_input, &test_data.entropy_as_hash());

            assert_eq!(shuffle_output, test_data.output);
        }
    }
}
