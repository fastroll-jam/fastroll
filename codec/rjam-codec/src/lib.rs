//! # Attribution Notice
//!
//! This library is heavily inspired by and incorporates components originally copied from the
//! [parity-scale-codec](https://github.com/paritytech/parity-scale-codec) repository.
//!
//! ## Modifications
//!
//! As the JAM protocol utilizes a modified version of the original SCALE codec, this library retains
//! much of its overall structure while significantly simplifying and adapting the implementation
//! to conform to the codec specifications defined in the Graypaper.
use bit_vec::BitVec;
#[cfg(feature = "derive")]
pub use rjam_codec_derive::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{Debug, Display},
    mem::size_of,
};
use thiserror::Error;

/// JAM codec error types.
#[derive(Debug, Error)]
pub enum JamCodecError {
    #[error("Invalid size: {0}")]
    InvalidSize(String),
    #[error("Conversion error: {0}")]
    ConversionError(String),
    #[error("Input error: {0}")]
    InputError(String),
    #[error("Encoding error: {0}")]
    EncodingError(String),
}

/// Trait that allows reading of data into a slice.
pub trait JamInput {
    /// Read the exact number of bytes required to fill the given buffer.
    fn read(&mut self, into: &mut [u8]) -> Result<(), JamCodecError>;

    /// Read a single byte from the input.
    fn read_byte(&mut self) -> Result<u8, JamCodecError> {
        let mut buf = [0u8];
        self.read(&mut buf[..])?;
        Ok(buf[0])
    }

    /// Returns the remaining length of bytes in the input.
    fn remaining_len(&self) -> usize;
}

impl JamInput for &[u8] {
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

    fn remaining_len(&self) -> usize {
        self.len()
    }
}

/// Trait that allows writing of data.
pub trait JamOutput {
    /// Writes to the output.
    fn write(&mut self, bytes: &[u8]);

    /// Writes a single byte to the output.
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

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError>;

    fn encode(&self) -> Result<Vec<u8>, JamCodecError> {
        let mut r = Vec::with_capacity(self.size_hint());
        self.encode_to(&mut r)?;
        Ok(r)
    }
}

pub trait JamDecode {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized;
}

// Implements a compact little-endian encoding for variable-length unsigned integer types.
// The first byte includes both length-indicator prefix and partially encoded data.
//
// In the first byte, the number of leading ones before 1-bit zero buffer is used to determine
// the final length of the encoding.
fn integer_encode_to<T: JamOutput, U: Copy + TryInto<u64>>(
    value: &U,
    dest: &mut T,
) -> Result<(), JamCodecError>
where
    <U as TryInto<u64>>::Error: Debug,
{
    // Convert the value to u64
    let x: u64 = (*value).try_into().expect("Value must fit into u64");

    // Case 1: x == 0
    if x == 0 {
        dest.push_byte(0);
        return Ok(());
    }

    // Case 2: 1 <= x < 2^56
    // Here, `l` is used to determine the number of bytes needed for encoding the integer.
    // The final encoded result is `l + 1` octets in length.
    //
    // `l` is defined as an integer in the range of [0, 8) which satisfies:
    // 2^{7 * l} <= x < 2^{7 * (l + 1)}.
    //
    // Therefore, `l` can be calculated as: floor(log2(x) / 7).
    if x < (1 << 56) {
        let l = if x == 0 { 0u8 } else { (x.ilog2() / 7) as u8 };

        // Set the prefix byte
        let leading_ones = if l == 0 {
            0u16
        } else {
            (1 << 8) - (1 << (8 - l))
        };

        let divisor = 1u64 << (8 * l);
        let quotient = x / divisor;
        let remainder = x % divisor;

        // Combine the prefix and quotient in the first byte
        let first_byte = leading_ones as u8 | (quotient as u8);
        dest.push_byte(first_byte);

        // Encode the remainder in little-endian format (fixed length of l)
        for i in 0..l {
            // Extract the i-th byte
            dest.push_byte(((remainder >> (8 * i)) & 0xFF) as u8);
        }
    }
    // Case 3: 2^56 <= x < 2^64
    else {
        dest.push_byte(0xFF); // prefix
        dest.write(&x.to_le_bytes()); // little-endian encoding
    }

    Ok(())
}

fn integer_size_hint<T: TryInto<u64>>(value: T) -> usize
where
    <T as TryInto<u64>>::Error: Debug,
{
    let x: u64 = value.try_into().expect("Value must fit into u64");

    if x == 0 {
        1 // 1-byte prefix only
    } else if x < (1 << 56) {
        x.ilog2().div_ceil(7) as usize
    } else {
        9 // 1-byte prefix + 8-byte little-endian encoding
    }
}

fn integer_decode<I: JamInput, U: TryFrom<u64>>(input: &mut I) -> Result<U, JamCodecError>
where
    <U as TryFrom<u64>>::Error: Debug + Display,
{
    let first_byte = input.read_byte()?;

    // Case 1: x == 0
    if first_byte == 0 {
        return U::try_from(0).map_err(|e| JamCodecError::ConversionError(e.to_string()));
    }

    // Count the number of leading 1-bits to determine the length prefix
    let length_prefix = first_byte.leading_ones() as usize;

    if length_prefix == 8 {
        // Case 3: 2^56 <= x < 2^64
        let value = u64::decode_fixed(input, 8)?;
        return U::try_from(value).map_err(|e| JamCodecError::ConversionError(e.to_string()));
    }

    // Case 2: 2^7l <= x < 2^7(l+1)
    let l = length_prefix;
    let mask = 0xFFu8 >> (l + 1);
    let quotient = (first_byte & mask) as u64;
    let remainder = u64::decode_fixed(input, l)?;

    // Combine quotient and remainder to get the final decoded value
    let value = (quotient << (8 * l)) | remainder;
    U::try_from(value).map_err(|e| JamCodecError::ConversionError(e.to_string()))
}

macro_rules! impl_jam_codec_for_uint {
    ($($t:ty),*) => {
        $(
            impl JamEncode for $t {
                fn size_hint(&self) -> usize {
                    integer_size_hint(*self)
                }

                fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
                    integer_encode_to(self, dest)
                }
            }

            impl JamDecode for $t {
                fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
                    integer_decode(input)
                }
            }
        )*
    }
}
impl_jam_codec_for_uint!(u8, u16, u32, u64, usize); // Implement for primitive unsigned integer types

impl JamEncode for bool {
    fn size_hint(&self) -> usize {
        1
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        dest.push_byte(*self as u8);
        Ok(())
    }
}

impl JamDecode for bool {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        match input.read_byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(JamCodecError::InputError("Invalid boolean value".into())),
        }
    }
}

impl<T: JamEncode> JamEncode for Option<T> {
    fn size_hint(&self) -> usize {
        // 1 byte for the presence marker
        match self {
            None => 1,
            Some(value) => 1 + value.size_hint(),
        }
    }

    fn encode_to<O: JamOutput>(&self, dest: &mut O) -> Result<(), JamCodecError> {
        match self {
            None => {
                0u8.encode_to(dest) // Encode the absence marker (0)
            }
            Some(value) => {
                1u8.encode_to(dest)?; // Encode the presence marker (1)
                value.encode_to(dest) // Encode the value
            }
        }
    }
}

impl<T: JamDecode> JamDecode for Option<T> {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        match input.read_byte()? {
            0 => Ok(None),
            1 => Ok(Some(T::decode(input)?)),
            _ => Err(JamCodecError::InputError("Invalid Option encoding".into())),
        }
    }
}

// Fixed-length general array codec without length discriminator.
impl<E: JamEncode, const N: usize> JamEncode for [E; N] {
    fn size_hint(&self) -> usize {
        self.iter().map(|e| e.size_hint()).sum()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.iter().try_for_each(|e| e.encode_to(dest))
    }
}

impl<E: JamDecode, const N: usize> JamDecode for [E; N] {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        let mut arr = Vec::with_capacity(N);
        for _ in 0..N {
            arr.push(E::decode(input)?);
        }
        arr.try_into()
            .map_err(|_| JamCodecError::InputError("Failed to convert Vec to array".into()))
    }
}

// Length discriminated codec for Vec<T> type.
// The length discriminator also follows the Jam Codec rules of integer types.
impl<T: JamEncode> JamEncode for Vec<T> {
    fn size_hint(&self) -> usize {
        // Size hint for the length prefix + sum of size hints for all elements
        self.len().size_hint() + self.iter().map(|e| e.size_hint()).sum::<usize>()
    }

    fn encode_to<O: JamOutput>(&self, dest: &mut O) -> Result<(), JamCodecError> {
        self.len().encode_to(dest)?; // length discriminator
        self.iter().try_for_each(|e| e.encode_to(dest))
    }
}

impl<T: JamDecode> JamDecode for Vec<T> {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        let len = usize::decode(input)?; // length discriminator
        let mut vec = Self::with_capacity(len);
        for _ in 0..len {
            vec.push(T::decode(input)?);
        }
        Ok(vec)
    }
}

impl JamEncode for BitVec {
    fn size_hint(&self) -> usize {
        let length_size = self.len().div_ceil(8).size_hint();
        length_size + self.len().div_ceil(8)
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        // Encode the length first
        let len = self.len();
        len.encode_to(dest)?; // Note: number of bits used for length discriminator (different from integers using number of bytes)

        // Fixed encoding of `length` bits
        self.encode_to_fixed(dest, len)
    }
}

impl JamDecode for BitVec {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        // Decode the length first
        let len = usize::decode(input)?;
        BitVec::decode_fixed(input, len)
    }
}

// Codec for simple dictionaries (BTreeMap).
impl<K: JamEncode + Eq + Ord, V: JamEncode> JamEncode for BTreeMap<K, V> {
    fn size_hint(&self) -> usize {
        if self.is_empty() {
            return self.len().size_hint();
        }
        // Sampling an entry to get the size hint of keys and values.
        let (sample_key, sample_value) = self.iter().next().expect("At least one entry exists.");
        self.len().size_hint() + (sample_key.size_hint() + sample_value.size_hint()) * self.len()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.len().encode_to(dest)?;

        let mut keys_sorted: Vec<_> = self.keys().collect();
        keys_sorted.sort();

        for key in keys_sorted {
            key.encode_to(dest)?;
            self.get(key).expect("Entry must exist").encode_to(dest)?;
        }
        Ok(())
    }
}

impl<K: JamDecode + Eq + Ord, V: JamDecode> JamDecode for BTreeMap<K, V> {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        let mut map = Self::new();
        let len = usize::decode(input)?;

        for _ in 0..len {
            let key = K::decode(input)?;
            let value = V::decode(input)?;
            map.insert(key, value);
        }
        Ok(map)
    }
}

// Length discriminated codec for simple ordered sets (BTreeSet).
// The length discriminator also follows the Jam Codec rules of integer types.
impl<T: JamEncode + Ord> JamEncode for BTreeSet<T> {
    fn size_hint(&self) -> usize {
        self.iter().map(|e| e.size_hint()).sum()
    }

    fn encode_to<O: JamOutput>(&self, dest: &mut O) -> Result<(), JamCodecError> {
        self.len().encode_to(dest)?; // length discriminator
        self.iter().try_for_each(|e| e.encode_to(dest))
    }
}

impl<T: JamDecode + Ord> JamDecode for BTreeSet<T> {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        let len = usize::decode(input)?; // length discriminator
        let mut set = Self::new();
        for _ in 0..len {
            set.insert(T::decode(input)?);
        }
        Ok(set)
    }
}

impl<T: JamEncode> JamEncode for Box<T> {
    fn size_hint(&self) -> usize {
        self.as_ref().size_hint()
    }

    fn encode_to<O: JamOutput>(&self, dest: &mut O) -> Result<(), JamCodecError> {
        self.as_ref().encode_to(dest)
    }
}

impl<T: JamDecode> JamDecode for Box<T> {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        Ok(Self::new(T::decode(input)?))
    }
}

pub enum SizeUnit {
    Bytes,
    Bits,
}

pub trait JamEncodeFixed {
    const SIZE_UNIT: SizeUnit; // whether the size counts the number of bytes or bits

    fn encode_to_fixed<T: JamOutput>(&self, dest: &mut T, size: usize)
        -> Result<(), JamCodecError>;

    fn encode_fixed(&self, size: usize) -> Result<Vec<u8>, JamCodecError> {
        let size_in_bytes = match Self::SIZE_UNIT {
            SizeUnit::Bytes => size,
            SizeUnit::Bits => size.div_ceil(8),
        };
        let mut r = Vec::with_capacity(size_in_bytes);
        self.encode_to_fixed(&mut r, size)?;
        Ok(r)
    }
}

pub trait JamDecodeFixed {
    const SIZE_UNIT: SizeUnit;

    fn decode_fixed<I: JamInput>(input: &mut I, size: usize) -> Result<Self, JamCodecError>
    where
        Self: Sized;
}

macro_rules! impl_jam_fixed_codec_for_uint {
    ($($t:ty),*) => {
        $(
            impl JamEncodeFixed for $t {
                const SIZE_UNIT: SizeUnit = SizeUnit::Bytes;

                fn encode_to_fixed<T: JamOutput>(&self, dest: &mut T, size_in_bytes: usize) -> Result<(), JamCodecError> {
                    if size_in_bytes > 8 {
                        return Err(JamCodecError::InvalidSize("Fixed encoding supports up to 8 bytes".into()));
                    }
                    let value: u64 = (*self).try_into().expect("The value must fit into u64");

                    if value as u128 > (1u128 << size_in_bytes * 8) - 1 {
                        return Err(JamCodecError::ConversionError(format!("Value {value} too large for {size_in_bytes} bytes")));
                    }
                    let bytes = value.to_le_bytes();
                    dest.write(&bytes[..size_in_bytes]);
                    Ok(())
                }
            }

            impl JamDecodeFixed for $t {
                const SIZE_UNIT: SizeUnit = SizeUnit::Bytes;

                fn decode_fixed<I: JamInput>(input: &mut I, size_in_bytes: usize) -> Result<Self, JamCodecError> {
                    let type_size = size_of::<Self>();
                    if size_in_bytes > type_size {
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
        )*
    }
}
impl_jam_fixed_codec_for_uint!(u8, u16, u32, u64, usize);

macro_rules! impl_jam_codec_for_tuple {
    ($($ty:ident),+) => {
        #[allow(non_snake_case)]
        impl<$($ty),+> JamEncode for ($($ty,)+)
        where
            $($ty: JamEncode,)+
        {
            fn size_hint(&self) -> usize {
                let ($($ty,)+) = self;
                0 $(+ $ty.size_hint())+
            }

            fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
                let ($($ty,)+) = self;
                $($ty.encode_to(dest)?;)+
                Ok(())
            }
        }

        impl<$($ty),+> JamDecode for ($($ty,)+)
        where
            $($ty: JamDecode,)+
        {
            fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
                Ok(($($ty::decode(input)?,)+))
            }
        }
    }
}

// Implement for tuples with 1 to 12 elements
impl_jam_codec_for_tuple!(T1);
impl_jam_codec_for_tuple!(T1, T2);
impl_jam_codec_for_tuple!(T1, T2, T3);
impl_jam_codec_for_tuple!(T1, T2, T3, T4);
impl_jam_codec_for_tuple!(T1, T2, T3, T4, T5);
impl_jam_codec_for_tuple!(T1, T2, T3, T4, T5, T6);
impl_jam_codec_for_tuple!(T1, T2, T3, T4, T5, T6, T7);
impl_jam_codec_for_tuple!(T1, T2, T3, T4, T5, T6, T7, T8);
impl_jam_codec_for_tuple!(T1, T2, T3, T4, T5, T6, T7, T8, T9);
impl_jam_codec_for_tuple!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10);
impl_jam_codec_for_tuple!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11);
impl_jam_codec_for_tuple!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12);

impl JamEncodeFixed for BitVec {
    const SIZE_UNIT: SizeUnit = SizeUnit::Bits;

    fn encode_to_fixed<T: JamOutput>(
        &self,
        dest: &mut T,
        size_in_bits: usize,
    ) -> Result<(), JamCodecError> {
        if self.len() != size_in_bits {
            return Err(JamCodecError::InvalidSize(format!(
                "Bitstring length ({}) does not match the expected size in bits ({})",
                self.len(),
                size_in_bits
            )));
        }

        // Pack bits into octets
        let mut current_byte = 0u8;
        let mut bit_count = 0;

        for bit in self.iter() {
            if bit {
                current_byte |= 1 << bit_count;
            }
            bit_count += 1;

            if bit_count == 8 {
                dest.push_byte(current_byte);
                current_byte = 0;
                bit_count = 0;
            }
        }

        // Push the last byte if there are remaining bits
        if bit_count > 0 {
            dest.push_byte(current_byte);
        }
        Ok(())
    }
}

impl JamDecodeFixed for BitVec {
    const SIZE_UNIT: SizeUnit = SizeUnit::Bits;

    fn decode_fixed<I: JamInput>(input: &mut I, size_in_bits: usize) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        let mut bv = Self::with_capacity(size_in_bits);
        let expected_bytes = size_in_bits.div_ceil(8);
        let mut bytes_read = 0;

        while bytes_read < expected_bytes {
            let byte = input.read_byte()?;
            bytes_read += 1;

            for i in 0..8 {
                if bv.len() < size_in_bits {
                    bv.push(byte & (1 << i) != 0);
                } else {
                    break;
                }
            }
        }
        Ok(bv)
    }
}

impl JamDecodeFixed for Vec<u8> {
    const SIZE_UNIT: SizeUnit = SizeUnit::Bytes;

    fn decode_fixed<I: JamInput>(input: &mut I, size: usize) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        let mut buffer = vec![0u8; size];
        input.read(&mut buffer)?;
        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to encode and then decode an integer value
    fn encode_decode<T>(value: T) -> T
    where
        T: JamEncode + JamDecode + PartialEq + Debug + Copy + TryFrom<u64> + TryInto<u64>,
        <T as TryFrom<u64>>::Error: Display,
        <T as TryInto<u64>>::Error: Debug,
    {
        let encoded = value.encode().unwrap();
        println!("\nValue: {value:?}");
        println!("Encoded: {encoded:02X?}");
        let mut slice = &encoded[..];
        let decoded = T::decode(&mut slice).unwrap();
        println!("Decoded: {decoded:?}");
        if value != decoded {
            println!("Mismatch: original {value:?} != decoded {decoded:?}");
        }
        decoded
    }

    #[test]
    fn test_u8_codec() {
        assert_eq!(encode_decode(0u8), 0u8);
        assert_eq!(encode_decode(1u8), 1u8);
        assert_eq!(encode_decode(63u8), 63u8);
        assert_eq!(encode_decode(64u8), 64u8);
        assert_eq!(encode_decode(u8::MAX), u8::MAX);
        assert_eq!(127u8.encode().unwrap(), vec![127]);
        assert_eq!(128u8.encode().unwrap(), vec![0b10000000, 128]); // 0b10000000 for prefix
    }

    #[test]
    fn test_u16_codec() {
        assert_eq!(encode_decode(0u16), 0u16);
        assert_eq!(encode_decode(1u16), 1u16);
        assert_eq!(encode_decode(63u16), 63u16);
        assert_eq!(encode_decode(64u16), 64u16);
        assert_eq!(encode_decode(16383u16), 16383u16);
        assert_eq!(encode_decode(16384u16), 16384u16);
        assert_eq!(encode_decode(u16::MAX), u16::MAX);
        assert_eq!(16383u16.encode().unwrap(), vec![0b10000000 | 0x3F, 0xFF]);
        assert_eq!(16384u16.encode().unwrap(), vec![0b11000000, 0x00, 0x40]);
    }

    #[test]
    fn test_u32_codec() {
        assert_eq!(encode_decode(0u32), 0u32);
        assert_eq!(encode_decode(1u32), 1u32);
        assert_eq!(encode_decode(16384u32), 16384u32);
        assert_eq!(encode_decode(1048575u32), 1048575u32);
        assert_eq!(encode_decode(1048576u32), 1048576u32);
        assert_eq!(encode_decode(u32::MAX), u32::MAX);
        assert_eq!(
            (1u32 << 21).encode().unwrap(),
            vec![0b11100000, 0x00, 0x00, 0x20]
        ); // 0b11100000 for prefix
    }

    #[test]
    fn test_u64_codec() {
        assert_eq!(encode_decode(0u64), 0u64);
        assert_eq!(encode_decode(1u64), 1u64);
        assert_eq!(encode_decode(1048575u64), 1048575u64);
        assert_eq!(encode_decode(1048576u64), 1048576u64);
        assert_eq!(encode_decode(1u64 << 32), 1u64 << 32);
        assert_eq!(encode_decode(1u64 << 56), 1u64 << 56);
        assert_eq!(encode_decode(u64::MAX), u64::MAX);
        assert_eq!(
            (1u64 << 28).encode().unwrap(),
            vec![0b11110000, 0x00, 0x00, 0x00, 0x10]
        ); // 0b11110000 for prefix
        assert_eq!(
            (1u64 << 35).encode().unwrap(),
            vec![0b11111000, 0x00, 0x00, 0x00, 0x00, 0x08]
        ); // 0b11111000 for prefix
        assert_eq!(
            (1u64 << 42).encode().unwrap(),
            vec![0b11111100, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04]
        ); // 0b11111100 for prefix
        assert_eq!(
            (1u64 << 49).encode().unwrap(),
            vec![0b11111110, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02]
        ); // 0b11111110 for prefix
        assert_eq!(
            (1u64 << 56).encode().unwrap(),
            vec![0b11111111, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
        ); // 0b11111111 for prefix
    }

    #[test]
    fn test_fixed_encoding() {
        let value: u32 = 0x12345678;
        let mut dest = Vec::new();
        value
            .encode_to_fixed(&mut dest, 4)
            .expect("Fixed encoding must succeed");
        assert_eq!(dest, vec![0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_fixed_encoding_overflow() {
        let value: u32 = 0x12345678;
        let mut dest = Vec::new();
        assert!(matches!(
            value.encode_to_fixed(&mut dest, 2),
            Err(JamCodecError::ConversionError(_))
        ))
    }

    #[test]
    fn test_decode_fixed() {
        let encoded = [0x78, 0x56, 0x34, 0x12];
        let mut slice = &encoded[..];
        let decoded = u32::decode_fixed(&mut slice, 4).unwrap();
        assert_eq!(decoded, 0x12345678);
    }

    #[test]
    fn test_decode_fixed_invalid_size() {
        let encoded = [0x78, 0x56, 0x34, 0x12];
        let mut slice = &encoded[..];
        assert!(matches!(
            u16::decode_fixed(&mut slice, 4),
            Err(JamCodecError::InvalidSize(_))
        ));
    }

    #[test]
    fn test_option_codec() {
        // Test None
        let none = None;
        let encoded_none = none.encode().unwrap();
        assert_eq!(encoded_none, vec![0]);
        let mut slice_none = &encoded_none[..];
        let decoded_none = Option::<u32>::decode(&mut slice_none).unwrap();
        assert_eq!(none, decoded_none);

        // Test Some
        let some = Some(42);
        let encoded_some = some.encode().unwrap();
        assert_eq!(encoded_some, vec![1, 42]);
        let mut slice_some = &encoded_some[..];
        let decoded_some = Option::<u32>::decode(&mut slice_some).unwrap();
        assert_eq!(some, decoded_some);

        // Test Some with a larger value
        let some_large = Some(1_000_000);
        let encoded_some_large = some_large.encode().unwrap();
        assert_eq!(encoded_some_large, vec![1, 207, 64, 66]);
        let mut slice_some_large = &encoded_some_large[..];
        let decoded_some_large = Option::<u32>::decode(&mut slice_some_large).unwrap();
        assert_eq!(some_large, decoded_some_large);

        // Test invalid encoding
        let invalid_encoding = [2]; // 2 is not a valid presence marker
        let mut slice_invalid = &invalid_encoding[..];
        assert!(matches!(
            Option::<u32>::decode(&mut slice_invalid),
            Err(JamCodecError::InputError(_))
        ));
    }

    #[test]
    fn test_array_codec() {
        // Test [u8; 4]
        let arr4 = [1, 2, 3, 4];
        let encoded_arr4 = arr4.encode().unwrap();
        assert_eq!(encoded_arr4, vec![1, 2, 3, 4]);
        let mut slice_arr4 = &encoded_arr4[..];
        let decoded_arr4 = <[u8; 4]>::decode(&mut slice_arr4).unwrap();
        assert_eq!(arr4, decoded_arr4);

        // Test [u8; 0] (empty array)
        let arr0: [u8; 0] = [];
        let encoded_arr0 = arr0.encode().unwrap();
        assert_eq!(encoded_arr0, vec![]);
        let mut slice_arr0 = &encoded_arr0[..];
        let decoded_arr0: [u8; 0] = <[u8; 0]>::decode(&mut slice_arr0).unwrap();
        assert_eq!(arr0, decoded_arr0);

        // Test [u8; 32] (hash value, etc.)
        let arr32: [u8; 32] = (1..=32)
            .collect::<Vec<_>>()
            .try_into()
            .expect("expected array of length 32");
        let encoded_arr32 = arr32.encode().unwrap();

        assert_eq!(encoded_arr32, (1..=32).collect::<Vec<_>>());
        let mut slice_arr32 = &encoded_arr32[..];
        let decoded_arr32: [u8; 32] = <[u8; 32]>::decode(&mut slice_arr32).unwrap();
        assert_eq!(arr32, decoded_arr32);

        // Test [u32; 3]
        let arr_u32: [u32; 3] = [1, 1000, 1_000_000];
        let encoded_arr_u32 = arr_u32.encode().unwrap();
        assert_eq!(encoded_arr_u32, vec![1, 131, 232, 207, 64, 66]);
        let mut slice_arr_u32 = &encoded_arr_u32[..];
        let decoded_arr_u32: [u32; 3] = <[u32; 3]>::decode(&mut slice_arr_u32).unwrap();
        assert_eq!(arr_u32, decoded_arr_u32);

        // Test [Option<u8>; 2]
        let arr_opt: [Option<u8>; 2] = [Some(42), None];
        let encoded_arr_opt = arr_opt.encode().unwrap();
        assert_eq!(encoded_arr_opt, vec![1, 42, 0]);
        let mut slice_arr_opt = &encoded_arr_opt[..];
        let decoded_arr_opt: [Option<u8>; 2] =
            <[Option<u8>; 2]>::decode(&mut slice_arr_opt).unwrap();
        assert_eq!(arr_opt, decoded_arr_opt);

        // Test decoding with insufficient input
        let insufficient_data = [1, 2, 3];
        let mut slice_insufficient = &insufficient_data[..];
        assert!(matches!(
            <[u8; 4]>::decode(&mut slice_insufficient),
            Err(JamCodecError::InputError(_))
        ));
    }

    #[test]
    fn test_vec_codec() {
        // Test empty Vec
        let empty_vec: Vec<u32> = vec![];
        let encoded_empty = empty_vec.encode().unwrap();
        assert_eq!(encoded_empty, vec![0]); // Just the length (0) encoded
        let mut slice_empty = &encoded_empty[..];
        let decoded_empty = Vec::<u32>::decode(&mut slice_empty).unwrap();
        assert_eq!(empty_vec, decoded_empty);

        // Test Vec with small integers
        let small_vec = vec![1, 2, 3];
        let encoded_small = small_vec.encode().unwrap();
        assert_eq!(encoded_small, vec![3, 1, 2, 3]); // Length (3) followed by elements
        let mut slice_small = &encoded_small[..];
        let decoded_small = Vec::<u8>::decode(&mut slice_small).unwrap();
        assert_eq!(small_vec, decoded_small);

        // Test Vec with larger integers
        let large_vec = vec![1, 1000, 1_000_000];
        let encoded_large = large_vec.encode().unwrap();
        assert_eq!(encoded_large, vec![3, 1, 131, 232, 207, 64, 66]);
        let mut slice_large = &encoded_large[..];
        let decoded_large = Vec::<u32>::decode(&mut slice_large).unwrap();
        assert_eq!(large_vec, decoded_large);

        // Test Vec of Option<u8>
        let opt_vec = vec![Some(42), None, Some(255)];
        let encoded_opt = opt_vec.encode().unwrap();
        assert_eq!(encoded_opt, vec![3, 1, 42, 0, 1, 1 << 7, 255]);
        let mut slice_opt = &encoded_opt[..];
        let decoded_opt = Vec::<Option<u8>>::decode(&mut slice_opt).unwrap();
        assert_eq!(opt_vec, decoded_opt);

        // Test decoding with insufficient input
        let insufficient_data = [3, 1, 2]; // Claims to have 3 elements but only has 2
        let mut slice_insufficient = &insufficient_data[..];
        assert!(matches!(
            Vec::<u8>::decode(&mut slice_insufficient),
            Err(JamCodecError::InputError(_))
        ));
    }

    #[test]
    fn test_bitvec_empty() {
        let bv = BitVec::new();
        let encoded = bv.encode().unwrap();
        assert_eq!(encoded, vec![0]); // Just the length (0) encoded

        let mut slice = &encoded[..];
        let decoded = BitVec::decode(&mut slice).unwrap();
        assert_eq!(bv, decoded);
    }

    #[test]
    fn test_bitvec_fixed_empty() {
        let bv = BitVec::new();
        let encoded = bv.encode_fixed(0).expect("Fixed encoding must succeed");
        assert_eq!(encoded, vec![]); // empty array

        let mut slice = &encoded[..];
        let decoded = BitVec::decode_fixed(&mut slice, 0).unwrap();
        assert_eq!(bv, decoded);
    }

    #[test]
    fn test_bitvec_partial_byte() {
        let mut bv = BitVec::new();
        bv.push(true);
        bv.push(false);
        bv.push(true);

        let encoded = bv.encode().unwrap();
        assert_eq!(encoded, vec![3, 0b00000101]);

        let mut slice = &encoded[..];
        let decoded = BitVec::decode(&mut slice).unwrap();
        assert_eq!(bv, decoded);
    }

    #[test]
    fn test_bitvec_fixed_partial_byte() {
        let mut bv = BitVec::new();
        bv.push(true);
        bv.push(false);
        bv.push(true);

        let encoded = bv.encode_fixed(3).expect("Fixed encoding must succeed");
        assert_eq!(encoded, vec![0b00000101]);

        let mut slice = &encoded[..];
        let decoded = BitVec::decode_fixed(&mut slice, 3).unwrap();
        assert_eq!(bv, decoded);
    }

    #[test]
    fn test_bitvec_multiple_bytes() {
        let mut bv = BitVec::new();
        for i in 0..20 {
            bv.push(i % 2 == 0);
        }

        let encoded = bv.encode().unwrap();
        assert_eq!(encoded, vec![20, 0b01010101, 0b01010101, 0b00000101]);

        let mut slice = &encoded[..];
        let decoded = BitVec::decode(&mut slice).unwrap();
        assert_eq!(bv, decoded);
    }

    #[test]
    fn test_bitvec_fixed_multiple_bytes() {
        let mut bv = BitVec::new();
        for i in 0..20 {
            bv.push(i % 2 == 0);
        }

        let encoded = bv.encode_fixed(20).expect("Fixed encoding must succeed");
        assert_eq!(encoded, vec![0b01010101, 0b01010101, 0b00000101]);

        let mut slice = &encoded[..];
        let decoded = BitVec::decode_fixed(&mut slice, 20).unwrap();
        assert_eq!(bv, decoded);
    }

    #[test]
    fn test_bitvec_large() {
        let mut bv = BitVec::new();
        for i in 0..1000 {
            bv.push(i % 3 == 0);
        }

        let encoded = bv.encode().unwrap();
        let mut slice = &encoded[..];
        let decoded = BitVec::decode(&mut slice).unwrap();
        assert_eq!(bv, decoded);
    }

    #[test]
    fn test_bitvec_fixed_large() {
        let mut bv = BitVec::new();
        for i in 0..1000 {
            bv.push(i % 3 == 0);
        }

        let encoded = bv.encode_fixed(1000).expect("Fixed encoding must succeed");
        let mut slice = &encoded[..];
        let decoded = BitVec::decode_fixed(&mut slice, 1000).unwrap();
        assert_eq!(bv, decoded);
    }

    #[test]
    fn test_bitvec_size_hint() {
        let mut bv = BitVec::new();
        for i in 0..100 {
            bv.push(i % 2 == 0);
        }

        let encoded = bv.encode().unwrap();
        assert_eq!(bv.size_hint(), encoded.len());
    }

    #[test]
    fn test_bitvec_partial_decode() {
        let mut bv = BitVec::new();
        for i in 0..20 {
            bv.push(i % 2 == 0);
        }

        let encoded = bv.encode().unwrap();
        let mut partial_slice = &encoded[..encoded.len() - 1];
        assert!(matches!(
            BitVec::decode(&mut partial_slice),
            Err(JamCodecError::InputError(_))
        ));
    }

    #[test]
    fn test_bitvec_fixed_partial_decode() {
        let mut bv = BitVec::new();
        for i in 0..20 {
            bv.push(i % 2 == 0);
        }

        let encoded = bv.encode_fixed(20).expect("Fixed encoding must succeed");
        let mut partial_slice = &encoded[..encoded.len() - 1];
        assert!(matches!(
            BitVec::decode_fixed(&mut partial_slice, 20),
            Err(JamCodecError::InputError(_))
        ));
    }

    #[test]
    fn test_bitvec_fixed_encode_length_mismatch() {
        let mut bv = BitVec::new();
        bv.push(true);
        bv.push(false);
        bv.push(true);

        let encoded = bv.encode_fixed(4);
        assert!(matches!(encoded, Err(JamCodecError::InvalidSize(_))));
    }

    #[test]
    fn test_map_empty() {
        let map: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
        let encoded = map.encode().unwrap();
        assert_eq!(encoded, vec![0]);

        let mut slice = &encoded[..];
        let decoded = BTreeMap::<u32, Vec<u8>>::decode(&mut slice).unwrap();
        assert_eq!(map, decoded);
    }

    #[test]
    fn test_map_simple() {
        let mut map = BTreeMap::new();
        map.insert(1u32, vec![1, 2, 3]);
        map.insert(2u32, vec![4, 5, 6]);
        map.insert(3u32, vec![7, 8, 9]);

        let encoded = map.encode().unwrap();
        let mut slice = &encoded[..];
        let decoded = BTreeMap::<u32, Vec<u8>>::decode(&mut slice).unwrap();
        assert_eq!(map, decoded);
    }

    #[test]
    fn test_map_complex() {
        let mut map = BTreeMap::new();
        map.insert(10u32, BitVec::from_bytes(&[0b10101010]));
        map.insert(20u32, BitVec::from_bytes(&[0b11001100, 0b11110000]));
        map.insert(30u32, BitVec::from_bytes(&[0b11111111]));

        let encoded = map.encode().unwrap();
        let mut slice = &encoded[..];
        let decoded = BTreeMap::<u32, BitVec>::decode(&mut slice).unwrap();
        assert_eq!(map, decoded);
    }

    #[test]
    fn test_map_nested() {
        let mut inner_map1 = BTreeMap::new();
        inner_map1.insert(1u8, vec![1, 2, 3]);
        inner_map1.insert(2u8, vec![4, 5, 6]);

        let mut inner_map2 = BTreeMap::new();
        inner_map2.insert(3u8, vec![7, 8, 9]);
        inner_map2.insert(4u8, vec![10, 11, 12]);

        let mut outer_map = BTreeMap::new();
        outer_map.insert(100u32, inner_map1);
        outer_map.insert(200u32, inner_map2);

        let encoded = outer_map.encode().unwrap();
        let mut slice = &encoded[..];
        let decoded = BTreeMap::<u32, BTreeMap<u8, Vec<u8>>>::decode(&mut slice).unwrap();
        assert_eq!(outer_map, decoded);
    }
}
