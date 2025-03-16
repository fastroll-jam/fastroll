use serde::{
    de::{Error, Visitor},
    Deserializer, Serializer,
};
use std::{fmt, fmt::Formatter};

/// Helper deserializer for bytes array to manage `0x` prefix
pub fn deserialize_hex_array<'de, D, const N: usize>(der: D) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    struct HexVisitor<const N: usize>;

    impl<const N: usize> Visitor<'_> for HexVisitor<N> {
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

    der.deserialize_str(HexVisitor)
}

/// Helper deserializer for bytes sequence to manage `0x` prefix
pub fn deserialize_hex_vec<'de, D>(der: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    struct HexVisitor;

    impl Visitor<'_> for HexVisitor {
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
            Ok(bytes)
        }
    }

    der.deserialize_str(HexVisitor)
}

/// Helper serializer for bytes array to manage `0x` prefix
pub fn serialize_hex_array<S, const N: usize>(bytes: &[u8; N], ser: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex_string = format!("0x{}", hex::encode(bytes));
    ser.serialize_str(&hex_string)
}

/// Helper serializer for bytes sequence to manage `0x` prefix
pub fn serialize_hex_vec<S>(bytes: &Vec<u8>, ser: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex_string = format!("0x{}", hex::encode(bytes));
    ser.serialize_str(&hex_string)
}
