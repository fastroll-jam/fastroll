use std::{
    error::Error,
    fmt,
    fmt::{Debug, Display, Formatter},
};

pub(crate) mod utils;

/// Error types for JAM SCALE Codec
#[derive(Debug)]
pub enum JamCodecError {
    InvalidSize(String),
    ConversionError(String),
    InputError(String),
    EncodingError(String),
}

impl Display for JamCodecError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            JamCodecError::InvalidSize(msg) => write!(f, "Invalid size: {}", msg),
            JamCodecError::ConversionError(msg) => write!(f, "Conversion error: {}", msg),
            JamCodecError::InputError(msg) => write!(f, "Input error: {}", msg),
            JamCodecError::EncodingError(msg) => write!(f, "Encoding error: {}", msg),
        }
    }
}

impl From<&'static str> for JamCodecError {
    fn from(desc: &'static str) -> JamCodecError {
        JamCodecError::InputError(desc.to_string())
    }
}

/// Trait that allows reading of data into a slice (this mirrors `Input` trait of `parity-scale-codec`)
pub trait JamInput {
    fn remaining_len(&mut self) -> Result<Option<usize>, JamCodecError>;

    fn read(&mut self, into: &mut [u8]) -> Result<(), JamCodecError>;

    fn read_byte(&mut self) -> Result<u8, JamCodecError> {
        let mut buf = [0u8];
        self.read(&mut buf[..])?;
        Ok(buf[0])
    }
}

impl<'a> JamInput for &'a [u8] {
    fn remaining_len(&mut self) -> Result<Option<usize>, JamCodecError> {
        Ok(Some(self.len()))
    }

    fn read(&mut self, into: &mut [u8]) -> Result<(), JamCodecError> {
        if into.len() > self.len() {
            return Err("Not enough data to fill buffer".into());
        }
        let len = into.len();
        into.copy_from_slice(&self[..len]);
        *self = &self[len..];
        Ok(())
    }
}

/// Trait that allows writing of data (this mirrors `Output` trait of `parity-scale-codec`)
pub trait JamOutput {
    /// Write to the output.
    fn write(&mut self, bytes: &[u8]);

    /// Write a single byte to the output.
    fn push_byte(&mut self, byte: u8) {
        self.write(&[byte]);
    }
}

impl JamOutput for Vec<u8> {
    fn write(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes)
    }
}

pub trait JamEncode {
    fn size_hint(&self) -> usize;

    // Variable length little-endian integer type encoding
    // The first byte includes both length-indicator prefix and part of the encoded data
    fn encode_to<T: JamOutput + ?Sized>(&self, dest: &mut T)
    where
        Self: Copy + TryInto<u64>,
        <Self as TryInto<u64>>::Error: Debug,
    {
        let x: u64 = (*self).try_into().expect("Value must fit into u64");

        // Case 1: for x == 0
        if x == 0 {
            dest.write(&[0]);
            return;
        }

        let mut encoded = Vec::new();
        let mut value = x;

        // Case 2: for x >= 1 and < 2^56
        for l in 0..8 {
            if value < 2u64.pow(7 * (l + 1)) {
                if l == 0 {
                    encoded.push(value as u8);
                } else {
                    encoded.push(255 - 2u8.pow(8 - l) + 1 + (value >> (8 * l)) as u8);
                    for _ in 0..l {
                        encoded.push((value & 0xFF) as u8);
                        value >>= 8;
                    }
                }
                dest.write(&encoded);
                return;
            }
        }

        // Case 3: for x >= 2^56 and < 2^64
        encoded.push(0xFF);
        encoded.extend_from_slice(&x.to_le_bytes());
        dest.write(&encoded);
    }

    // Fixed length little-endian integer type encoding
    fn encode_to_fixed<T: JamOutput + ?Sized>(&self, dest: &mut T, size_in_bytes: usize)
    where
        Self: Copy + TryInto<u64>,
        <Self as TryInto<u64>>::Error: Debug,
    {
        let mut buf = vec![0u8; size_in_bytes];
        let mut value: u64 = (*self).try_into().expect("The value must fit into u64");

        for buf_byte in buf.iter_mut().take(size_in_bytes) {
            *buf_byte = (value & 0xFF) as u8;
            value >>= 8;
        }

        if value != 0 {
            panic!("Value is too large to fit in {} bytes", size_in_bytes);
        }

        dest.write(&buf);
    }

    // Variable length little-endian integer type encoding
    fn encode(&self) -> Vec<u8>
    where
        Self: Copy + TryInto<u64>,
        <Self as TryInto<u64>>::Error: Debug,
    {
        let mut r = Vec::with_capacity(self.size_hint());
        self.encode_to(&mut r);
        r
    }

    // Fixed length little-endian integer type encoding
    fn encode_fixed(&self) -> Vec<u8>
    where
        Self: Copy + TryInto<u64>,
        <Self as TryInto<u64>>::Error: Debug,
    {
        let size = self.size_hint();
        let mut r = Vec::with_capacity(size);
        self.encode_to_fixed(&mut r, size);
        r
    }
}

pub trait JamDecode: Sized + TryFrom<u64> + Into<u64> {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: TryFrom<u64>,
        <Self as TryFrom<u64>>::Error: Display,
    {
        decode_impl(input)
    }

    fn decode_fixed<I: JamInput>(input: &mut I, size_in_bytes: usize) -> Result<Self, JamCodecError>
    where
        Self: TryFrom<u64>,
        <Self as TryFrom<u64>>::Error: Display,
    {
        let type_size = size_of::<Self>();
        if size_in_bytes != type_size {
            return Err(JamCodecError::InvalidSize(format!(
                "Invalid size for {}",
                std::any::type_name::<Self>()
            )));
        }

        let mut value: u64 = 0;
        for i in 0..size_in_bytes {
            value |= (input.read_byte()? as u64) << (8 * i);
        }

        Self::try_from(value).map_err(|e| JamCodecError::ConversionError(e.to_string()))
    }
}

fn decode_impl<I: JamInput, T: JamDecode + TryFrom<u64>>(input: &mut I) -> Result<T, JamCodecError>
where
    <T as TryFrom<u64>>::Error: Display,
{
    let first_byte = input.read_byte()?;

    // Case 1: x == 0
    if first_byte == 0 {
        return T::try_from(0).map_err(|e| JamCodecError::ConversionError(e.to_string()));
    }

    // Count the number of leading one(`1`)s to determine the length prefix
    let mut length_prefix = 0;
    for i in (0..8).rev() {
        if (first_byte & (1 << i)) != 0 {
            length_prefix += 1;
        } else {
            break;
        }
    }

    if length_prefix == 8 {
        // Case 3: x >= 2^56 and < 2^64
        let mut value: u64 = 0;
        for i in 0..8 {
            value |= (input.read_byte()? as u64) << (8 * i);
        }
        return T::try_from(value).map_err(|e| JamCodecError::ConversionError(e.to_string()));
    }

    // Case 2: 2^7l <= x < 2^7(l+1)
    let l = length_prefix;
    let quotient = (first_byte & ((1 << (8 - l)) - 1)) as u64;

    let mut remainder: u64 = 0;
    for i in 0..l {
        remainder |= (input.read_byte()? as u64) << (8 * i);
    }

    // Combine quotient and remainder to get the final value
    // According to the definition of SCALE encoding in the GP, the quotient is stored in the first
    // byte following the length prefixes, and the remainder is stored in the subsequent fixed-length
    // encoded data.
    let value = (quotient << (8 * l)) | remainder;
    T::try_from(value).map_err(|e| JamCodecError::ConversionError(e.to_string()))
}
