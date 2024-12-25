use serde::{
    de::{Error, Visitor},
    Deserializer, Serializer,
};
use std::{fmt, fmt::Formatter};

/// Generates typed test functions from provided test cases.
///
/// # Usage
/// ```text
/// generate_typed_tests! {
///     TestType,
///     test_name1: "path/to/case1",
///     test_name2: "path/to/case2",
/// }
/// ```
///
/// The first entry represents type of the stat transition test.
/// For the following entries, each entry generates a test function
/// that calls `run_test_case::<TestType>("path/to/case")`.
///
/// Ensure `run_test_case` is in scope and returns `Result<(), TransitionError>`.
#[macro_export]
macro_rules! generate_typed_tests {
    ($test_type:ty, $($name:ident: $path:expr,)*) => {
        $(
            #[test]
            fn $name() -> Result<(), TransitionError> {
                run_test_case::<$test_type>($path)
            }
        )*
    }
}

// Helper deserializers to manage `0x` prefix
pub fn deserialize_hex_array<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
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
            E: Error,
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

pub fn deserialize_hex_vec<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    struct HexVisitor;

    impl<'de> Visitor<'de> for HexVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
            write!(formatter, "a 0x-prefixed hex string")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            let v = v.strip_prefix("0x").unwrap_or(v);
            let bytes = hex::decode(v).map_err(E::custom)?;
            bytes.try_into().map_err(E::custom)
        }
    }

    deserializer.deserialize_str(HexVisitor)
}

// Helper serializers to manage `0x` prefix
pub fn serialize_hex_array<S, const N: usize>(
    bytes: &[u8; N],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex_string = format!("0x{}", hex::encode(bytes));
    serializer.serialize_str(&hex_string)
}

pub fn serialize_hex_vec<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex_string = format!("0x{}", hex::encode(bytes));
    serializer.serialize_str(&hex_string)
}
