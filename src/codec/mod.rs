use std::{
    error::Error,
    fmt,
    fmt::{Debug, Display, Formatter},
    mem::size_of,
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
    fn read(&mut self, into: &mut [u8]) -> Result<(), JamCodecError>;

    fn read_byte(&mut self) -> Result<u8, JamCodecError> {
        let mut buf = [0u8];
        self.read(&mut buf[..])?;
        Ok(buf[0])
    }
}

impl<'a> JamInput for &'a [u8] {
    fn read(&mut self, into: &mut [u8]) -> Result<(), JamCodecError> {
        if into.len() > self.len() {
            return Err(JamCodecError::InputError(
                "Not enough data to fill buffer".into(),
            ));
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
        // Convert the value to u64
        let x: u64 = (*self).try_into().expect("Value must fit into u64");

        // Case 1: x == 0
        if x == 0 {
            dest.push_byte(0);
            return;
        }

        // Case 2: 1 <= x < 2^56
        if x < (1 << 56) {
            // determine l (0 to 7)
            let l = if (1..(1 << 7)).contains(&x) {
                0
            } else if ((1 << 7)..(1 << 14)).contains(&x) {
                1
            } else if ((1 << 14)..(1 << 21)).contains(&x) {
                2
            } else if ((1 << 21)..(1 << 28)).contains(&x) {
                3
            } else if ((1 << 28)..(1 << 35)).contains(&x) {
                4
            } else if ((1 << 35)..(1 << 42)).contains(&x) {
                5
            } else if ((1 << 42)..(1 << 49)).contains(&x) {
                6
            } else {
                7
            };

            // Set the prefix byte
            let prefix = if l == 0 { 0 } else { 0xFFu8 << (8 - l) };

            // Divide x by 2^8l
            let divisor = 1u64 << (8 * l);
            let quotient = x / divisor;
            let remainder = x % divisor;

            // Combine the prefix and quotient in the first byte
            let first_byte = prefix | (quotient as u8);
            dest.push_byte(first_byte);

            // Encode the remainder in little-endian format
            for i in 0..l {
                dest.push_byte(((remainder >> (8 * i)) & 0xFF) as u8);
            }
        }
        // Case 3: 2^56 <= x < 2^64
        else {
            dest.push_byte(0xFF);
            dest.write(&x.to_le_bytes());
        }
    }

    // Fixed length little-endian integer type encoding
    fn encode_to_fixed<T: JamOutput + ?Sized>(&self, dest: &mut T, size_in_bytes: usize)
    where
        Self: Copy + TryInto<u64>,
        <Self as TryInto<u64>>::Error: Debug,
    {
        let value: u64 = (*self).try_into().expect("The value must fit into u64");
        let bytes = value.to_le_bytes();

        if size_in_bytes > 8 {
            panic!("Size cannot be larger than 8 bytes for u64");
        }

        if bytes[size_in_bytes..].iter().any(|&b| b != 0) {
            panic!("Value is too large to fit in {} bytes", size_in_bytes);
        }

        dest.write(&bytes[..size_in_bytes]);
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

pub trait JamDecode: Sized + TryFrom<u64> {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: TryFrom<u64>,
        <Self as TryFrom<u64>>::Error: Display,
    {
        let first_byte = input.read_byte()?;

        // Case 1: x == 0
        if first_byte == 0 {
            return Self::try_from(0).map_err(|e| JamCodecError::ConversionError(e.to_string()));
        }

        // Count the number of leading one(`1`)s to determine the length prefix
        let length_prefix = first_byte.leading_ones() as usize;

        if length_prefix == 8 {
            // Case 3: 2^56 <= x < 2^64
            let mut value: u64 = 0;
            for i in 0..8 {
                value |= (input.read_byte()? as u64) << (8 * i);
            }
            return Self::try_from(value)
                .map_err(|e| JamCodecError::ConversionError(e.to_string()));
        }

        // Case 2: 2^7l <= x < 2^7(l+1)
        let l = length_prefix;
        let mask = 0xFFu8 >> l;
        let quotient = (first_byte & mask) as u64;

        let mut remainder: u64 = 0;
        for i in 0..l {
            remainder |= (input.read_byte()? as u64) << (8 * i);
        }

        // Combine quotient and remainder to get the final decoded value
        let value = (quotient << (8 * l)) | remainder;
        Self::try_from(value).map_err(|e| JamCodecError::ConversionError(e.to_string()))
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

macro_rules! impl_jam_codec_for_uint {
    ($($t:ty),*) => {
        $(
            impl JamEncode for $t {
                fn size_hint(&self) -> usize { size_of::<Self>()
                }
            }

            impl JamDecode for $t {
                // The `decode` and `decode_fixed` methods are provided by the default implementation
            }
        )*
    }
}

impl_jam_codec_for_uint!(u8, u16, u32, u64, usize); // Implement for primitive integer types

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to encode and then decode a value
    fn encode_decode<T: JamEncode + JamDecode + PartialEq + Debug + Copy>(
        value: T,
    ) -> Result<T, JamCodecError>
    where
        T: TryFrom<u64> + TryInto<u64>,
        <T as TryFrom<u64>>::Error: Display,
        <T as TryInto<u64>>::Error: Debug,
    {
        let encoded = value.encode();
        println!("\nValue: {:?}", value);
        println!("Encoded: {:02X?}", encoded);
        let mut slice = &encoded[..];
        let decoded = T::decode(&mut slice)?;
        println!("Decoded: {:?}", decoded);
        if value != decoded {
            println!("Mismatch: original {:?} != decoded {:?}", value, decoded);
        }
        Ok(decoded)
    }

    #[test]
    fn test_u8_codec() {
        assert_eq!(encode_decode(0u8).unwrap(), 0u8);
        assert_eq!(encode_decode(1u8).unwrap(), 1u8);
        assert_eq!(encode_decode(63u8).unwrap(), 63u8);
        assert_eq!(encode_decode(64u8).unwrap(), 64u8);
        assert_eq!(encode_decode(u8::MAX).unwrap(), u8::MAX);
    }

    #[test]
    fn test_u16_codec() {
        assert_eq!(encode_decode(0u16).unwrap(), 0u16);
        assert_eq!(encode_decode(1u16).unwrap(), 1u16);
        assert_eq!(encode_decode(63u16).unwrap(), 63u16);
        assert_eq!(encode_decode(64u16).unwrap(), 64u16);
        assert_eq!(encode_decode(16383u16).unwrap(), 16383u16);
        assert_eq!(encode_decode(16384u16).unwrap(), 16384u16);
        assert_eq!(encode_decode(u16::MAX).unwrap(), u16::MAX);
    }

    #[test]
    fn test_u32_codec() {
        assert_eq!(encode_decode(0u32).unwrap(), 0u32);
        assert_eq!(encode_decode(1u32).unwrap(), 1u32);
        assert_eq!(encode_decode(16384u32).unwrap(), 16384u32);
        assert_eq!(encode_decode(1048575u32).unwrap(), 1048575u32);
        assert_eq!(encode_decode(1048576u32).unwrap(), 1048576u32);
        assert_eq!(encode_decode(u32::MAX).unwrap(), u32::MAX);
    }

    #[test]
    fn test_u64_codec() {
        assert_eq!(encode_decode(0u64).unwrap(), 0u64);
        assert_eq!(encode_decode(1u64).unwrap(), 1u64);
        assert_eq!(encode_decode(1048575u64).unwrap(), 1048575u64);
        assert_eq!(encode_decode(1048576u64).unwrap(), 1048576u64);
        assert_eq!(encode_decode(1u64 << 32).unwrap(), 1u64 << 32);
        assert_eq!(encode_decode(1u64 << 56).unwrap(), 1u64 << 56);
        assert_eq!(encode_decode(u64::MAX).unwrap(), u64::MAX);
    }

    #[test]
    fn test_fixed_encoding() {
        let value: u32 = 0x12345678;
        let mut dest = Vec::new();
        value.encode_to_fixed(&mut dest, 4);
        assert_eq!(dest, vec![0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    #[should_panic(expected = "Value is too large to fit in 2 bytes")]
    fn test_fixed_encoding_overflow() {
        let value: u32 = 0x12345678;
        let mut dest = Vec::new();
        value.encode_to_fixed(&mut dest, 2);
    }

    #[test]
    fn test_decode_fixed() {
        let encoded = vec![0x78, 0x56, 0x34, 0x12];
        let mut slice = &encoded[..];
        let decoded = u32::decode_fixed(&mut slice, 4).unwrap();
        assert_eq!(decoded, 0x12345678);
    }

    #[test]
    fn test_decode_fixed_invalid_size() {
        let encoded = vec![0x78, 0x56, 0x34, 0x12];
        let mut slice = &encoded[..];
        assert!(matches!(
            u16::decode_fixed(&mut slice, 4),
            Err(JamCodecError::InvalidSize(_))
        ));
    }
}
