//! Serde utils module

use serde::{
    de::{DeserializeOwned, Error, Visitor},
    Deserializer, Serialize, Serializer,
};
use std::{fmt, fmt::Formatter, fs, fs::File, io, io::Read, path::Path};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FileReaderError {
    #[error("IOError: {0}")]
    IOError(#[from] io::Error),
    #[error("SerdeJsonError: {0}")]
    SerdeJsonError(#[from] serde_json::error::Error),
}

pub struct FileReader;
impl FileReader {
    pub fn read_bytes(path: &Path) -> io::Result<Vec<u8>> {
        let mut file = File::open(path)?;
        let mut buffer = vec![];
        file.read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    pub fn read_json<T>(full_path: &Path) -> Result<T, FileReaderError>
    where
        T: Serialize + DeserializeOwned,
    {
        let json_str = fs::read_to_string(full_path)?;
        Ok(serde_json::from_str(&json_str)?)
    }
}

/// Helper deserializer for bytes array to manage `0x` prefix
pub fn deserialize_hex_array<'de, D, const N: usize>(der: D) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    struct HexVisitor<const N: usize>;

    impl<const N: usize> Visitor<'_> for HexVisitor<N> {
        type Value = [u8; N];

        fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
            write!(formatter, "a 0x-prefixed hex string with {N} bytes")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            let v = v.strip_prefix("0x").unwrap_or(v);
            let bytes = hex::decode(v).map_err(E::custom)?;
            bytes
                .try_into()
                .map_err(|_| E::custom(format!("Expected {N} bytes")))
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
