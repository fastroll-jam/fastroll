use crate::{HASH_SIZE, STATE_KEY_SIZE};
use fr_codec::prelude::*;
use std::{
    array::from_fn,
    fmt::{Display, Formatter},
    ops::{Deref, DerefMut},
};
use thiserror::Error;

pub mod ticket;
pub mod workloads;

/// Hash type aliases.
pub type BlockHeaderHash = Hash32;
pub type XtHash = Hash32;
pub type StateRoot = Hash32;
pub type EntropyHash = Hash32;
pub type WorkReportHash = Hash32;

/// 32-byte Hash type.
pub type Hash32 = ByteArray<HASH_SIZE>;

/// 31-byte State key type.
pub type StateKey = ByteArray<STATE_KEY_SIZE>;

/// Octets type; wrapper of `Vec<u8>`.
pub type Octets = ByteSequence;

/// The service id.
pub type ServiceId = u32;

/// The validator index.
pub type ValidatorIndex = u16;

/// The core index.
pub type CoreIndex = u16;

/// Token balance type.
pub type Balance = u64;

/// Signed integer gas type, representing potentially negative post gas after some execution
/// implying out-of-gas error.
pub type SignedGas = i64;

/// Unsigned integer gas type.
pub type UnsignedGas = u64;

/// Service account preimage lookup metadata map key.
/// A tuple of the hash and its preimage length in octets.
pub type LookupsKey = (Hash32, u32);

#[derive(Debug, Error)]
pub enum CommonTypeError {
    #[error("Failed to convert hexstring into ByteArray<{0}> type")]
    HexToByteArrayConversionError(usize),
    #[error("Failed to convert Vec<u8> into ByteArray<{0}> type")]
    SliceToByteArrayConversionError(usize),
}

pub trait ByteEncodable: Sized {
    fn as_slice(&self) -> &[u8];
    fn to_hex(&self) -> String;
    fn from_slice(slice: &[u8]) -> Result<Self, CommonTypeError>;
    fn from_hex(hex_str: &str) -> Result<Self, CommonTypeError>;
}

/// Bytes sequence type with no length limit.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteSequence(pub Vec<u8>);

impl Deref for ByteSequence {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ByteSequence {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Display for ByteSequence {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl JamEncode for ByteSequence {
    fn size_hint(&self) -> usize {
        self.0.len().size_hint() + self.0.len()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        // By default add length discriminator prefix for octets
        self.0.len().encode_to(dest)?;
        dest.write(self.0.as_slice());
        Ok(())
    }
}

impl JamDecode for ByteSequence {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        let len = usize::decode(input)?;
        let mut vec = vec![0u8; len];
        input
            .read(&mut vec)
            .map_err(|_| JamCodecError::InputError("Failed to Decode ByteSequence".into()))?;
        Ok(Self(vec))
    }
}

impl JamEncodeFixed for ByteSequence {
    const SIZE_UNIT: SizeUnit = SizeUnit::Bytes;

    fn encode_to_fixed<T: JamOutput>(
        &self,
        dest: &mut T,
        size: usize,
    ) -> Result<(), JamCodecError> {
        if self.len() != size {
            return Err(JamCodecError::InvalidSize(format!(
                "Vector length ({}) does not match the expected size in byte ({})",
                self.len(),
                size
            )));
        }
        dest.write(self.as_slice());
        Ok(())
    }
}

impl JamDecodeFixed for ByteSequence {
    const SIZE_UNIT: SizeUnit = SizeUnit::Bytes;

    fn decode_fixed<I: JamInput>(input: &mut I, size: usize) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        let mut buffer = vec![0u8; size];
        input.read(&mut buffer)?;
        Ok(Self(buffer))
    }
}

impl ByteSequence {
    pub fn new(data: &[u8]) -> Self {
        Self(data.to_vec())
    }

    pub fn from_vec(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

/// A bytes array type of size `N`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteArray<const N: usize>(pub [u8; N]);

impl<const N: usize> Deref for ByteArray<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> DerefMut for ByteArray<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> Display for ByteArray<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl<const N: usize> Default for ByteArray<N> {
    fn default() -> Self {
        let arr = from_fn(|_| 0u8);
        Self(arr)
    }
}

impl<const N: usize> JamEncode for ByteArray<N> {
    fn size_hint(&self) -> usize {
        N
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        dest.write(&self.0);
        Ok(())
    }
}

impl<const N: usize> JamDecode for ByteArray<N> {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        let mut array = [0u8; N];
        input
            .read(&mut array)
            .map_err(|_| JamCodecError::InputError("Failed to decode ByteArray".into()))?;
        Ok(Self(array))
    }
}

impl<const N: usize> ByteEncodable for ByteArray<N> {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    fn from_slice(slice: &[u8]) -> Result<Self, CommonTypeError> {
        let arr = slice
            .try_into()
            .map_err(|_| CommonTypeError::SliceToByteArrayConversionError(N))?;
        Ok(Self(arr))
    }

    fn from_hex(hex_str: &str) -> Result<Self, CommonTypeError> {
        let hex_stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        if hex_stripped.len() != N * 2 {
            return Err(CommonTypeError::HexToByteArrayConversionError(N));
        }

        // Decode hex string
        let octets = hex::decode(hex_stripped).expect("Failed decoding hexstring into ByteArray");
        Self::from_slice(&octets)
    }
}

impl<const N: usize> ByteArray<N> {
    pub fn new(data: [u8; N]) -> Self {
        Self(data)
    }

    pub fn encode_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl AsRef<[u8]> for Hash32 {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl TryFrom<&[u8]> for Hash32 {
    type Error = String;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != HASH_SIZE {
            return Err("Hash length mismatch".into());
        }

        let mut arr = Hash32::default();
        arr.copy_from_slice(value);

        Ok(arr)
    }
}
