use serde::{
    de,
    de::{DeserializeOwned, Visitor},
    Deserializer, Serialize, Serializer,
};
use std::{
    fmt, fs,
    path::{Path, PathBuf},
};

/// Generates test functions from provided test cases.
///
/// # Usage
/// ```text
/// generate_tests! {
///     test_name1: "path/to/case1",
///     test_name2: "path/to/case2",
/// }
/// ```
///
/// Each entry generates a test function that calls `run_test_case("path/to/case")`.
/// Ensure `run_test_case` is in scope and returns `Result<(), Box<dyn Error>>`.
#[macro_export]
macro_rules! generate_tests {
    ($($name:ident: $path:expr,)*) => {
        $(
            #[test]
            fn $name() -> Result<(), Box<dyn Error>> {
                run_test_case($path)
            }
        )*
    }
}

/// Loads a test case from the path to the test vectors.
pub(crate) fn load_test_case<T>(path: &Path) -> Result<T, ()>
where
    T: Serialize + DeserializeOwned,
{
    let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
    let json_str = fs::read_to_string(&full_path).expect("Failed to read test vector file");
    let test_case = serde_json::from_str(&json_str).expect("Failed to parse JSON");
    Ok(test_case)
}

// Helper deserializer to manage `0x` prefix
pub fn deserialize_hex<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    struct HexVisitor<const N: usize>;

    impl<'de, const N: usize> Visitor<'de> for HexVisitor<N> {
        type Value = [u8; N];

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "a 0x-prefixed hex string with {} bytes", N)
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let v = v.strip_prefix("0x").unwrap_or(v);
            let bytes = hex::decode(v).map_err(E::custom)?;
            bytes
                .try_into()
                .map_err(|_| E::custom(format!("Expected {} bytes", N)))
        }
    }

    deserializer.deserialize_str(HexVisitor)
}

// Helper serializer to manage `0x` prefix
pub fn serialize_hex<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex_string = format!("0x{}", hex::encode(bytes));
    serializer.serialize_str(&hex_string)
}
