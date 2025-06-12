use crate::program::instruction::ImmSize;
use bit_vec::BitVec;
use fr_pvm_types::{
    common::RegValue,
    constants::{INIT_ZONE_SIZE, PAGE_SIZE},
};

/// Signed extension input size in octets.
pub enum SextInputSize {
    Octets0,
    Octets1,
    Octets2,
    Octets3,
    Octets4,
    Octets8,
}

impl SextInputSize {
    pub fn as_usize(&self) -> usize {
        match self {
            Self::Octets0 => 0,
            Self::Octets1 => 1,
            Self::Octets2 => 2,
            Self::Octets3 => 3,
            Self::Octets4 => 4,
            Self::Octets8 => 8,
        }
    }
}

impl From<ImmSize> for SextInputSize {
    fn from(value: ImmSize) -> Self {
        match value {
            ImmSize::Octets0 => Self::Octets0,
            ImmSize::Octets1 => Self::Octets1,
            ImmSize::Octets2 => Self::Octets2,
            ImmSize::Octets3 => Self::Octets3,
            ImmSize::Octets4 => Self::Octets4,
        }
    }
}

pub struct VMUtils;
impl VMUtils {
    //
    // Program initialization util functions
    //

    /// Represents `P` of the GP
    pub fn page_align(x: usize) -> usize {
        // P(x) = Z_P * ceil(x / Z_P)
        PAGE_SIZE * x.div_ceil(PAGE_SIZE)
    }

    /// Represents `Z` of the GP
    pub fn zone_align(x: usize) -> usize {
        // Z(x) = Z_Z * ceil(x / Z_Z)
        INIT_ZONE_SIZE * x.div_ceil(INIT_ZONE_SIZE)
    }

    //
    // Instruction arguments processing functions
    //

    /// Converts an unsigned integer to a signed integer of the same bit width.
    /// Represents `Z_n` of the GP
    /// # Arguments
    ///
    /// * `a`: The unsigned integer to convert.
    /// * `n`: The number of octets in the integer.
    ///
    /// # Returns
    ///
    /// The signed equivalent of the input, or None if `n` is greater than 8.
    pub(crate) fn unsigned_to_signed(a: u64, n: usize) -> Option<i64> {
        match n {
            0..=8 => {
                let max_positive = 1u64 << (8 * n - 1);
                if a < max_positive {
                    Some(a as i64)
                } else {
                    Some((a as i64) - (1i64.wrapping_shl(8 * n as u32)))
                }
            }
            _ => None,
        }
    }

    /// Converts a signed integer to an unsigned integer of the same bit width.
    /// Represents `{Z_n}^-1` of the GP
    ///
    /// # Arguments
    ///
    /// * `a`: The signed integer to convert.
    /// * `n`: The number of octets in the integer.
    ///
    /// # Returns
    ///
    /// The unsigned equivalent of the input, or None if `n` is greater than 8.
    #[allow(dead_code)]
    pub(crate) fn signed_to_unsigned(a: i64, n: usize) -> Option<u64> {
        match n {
            0..=8 => {
                let modulus = 1i64.wrapping_shl(8 * n as u32);
                Some(((modulus + a) % modulus) as u64)
            }
            _ => None,
        }
    }

    /// `Z_n` function with `n = 1`
    pub fn u8_to_i8(a: u8) -> i8 {
        let n = 1i8;
        if a < 1u8 << (8 * n - 1) {
            a as i8
        } else {
            ((a as i16) - (1i16 << (8 * n))) as i8
        }
    }

    /// `Z_n` function with `n = 2`
    pub fn u16_to_i16(a: u16) -> i16 {
        let n = 2i16;
        if a < 1u16 << (8 * n - 1) {
            a as i16
        } else {
            ((a as i32) - (1i32 << (8 * n))) as i16
        }
    }

    /// `Z_n` function with `n = 4`
    pub fn u32_to_i32(a: u32) -> i32 {
        let n = 4i32;
        if a < 1u32 << (8 * n - 1) {
            a as i32
        } else {
            ((a as i64) - (1i64 << (8 * n))) as i32
        }
    }

    /// `Z_n` function with `n = 8`
    pub fn u64_to_i64(a: u64) -> i64 {
        let n = 8i64;
        if a < 1u64 << (8 * n - 1) {
            a as i64
        } else {
            ((a as i128) - (1i128 << (8 * n))) as i64
        }
    }

    /// `{Z_n}^-1` function with `n = 1`
    pub fn i8_to_u8(a: i8) -> u8 {
        let n = 1;
        let modulus: i16 = 1 << (8 * n);
        ((modulus + a as i16) % modulus) as u8
    }

    /// `{Z_n}^-1` function with `n = 2`
    pub fn i16_to_u16(a: i16) -> u16 {
        let n = 2;
        let modulus: i32 = 1 << (8 * n);
        ((modulus + a as i32) % modulus) as u16
    }

    /// `{Z_n}^-1` function with `n = 3`
    pub fn i32_to_u32(a: i32) -> u32 {
        let n = 4;
        let modulus: i64 = 1 << (8 * n);
        ((modulus + a as i64) % modulus) as u32
    }

    /// `{Z_n}^-1` function with `n = 4`
    pub fn i64_to_u64(a: i64) -> u64 {
        let n = 8;
        let modulus: i128 = 1 << (8 * n);
        ((modulus + a as i128) % modulus) as u64
    }

    /// Converts an unsigned integer to its binary representation.
    /// Represents `B_n` of the GP
    ///
    /// # Arguments
    ///
    /// * `x`: The unsigned integer to convert.
    /// * `n`: The number of octets in the integer.
    ///
    /// # Returns
    ///
    /// A vector of booleans representing the binary form of the input,
    /// or None if `n` is greater than 8.
    #[allow(dead_code)]
    pub(crate) fn int_to_bits(x: u64, n: u64) -> Option<BitVec> {
        match n {
            0..=8 => {
                let mut result = BitVec::from_elem((8 * n) as usize, false);
                for i in 0..(8 * n) {
                    result.set(i as usize, (x >> i) & 1 == 1);
                }
                Some(result)
            }
            _ => None,
        }
    }

    /// `B_n` function with `n = 4`
    pub fn u32_to_bits(x: u32) -> BitVec {
        let n = 4;
        let mut result = BitVec::from_elem((8 * n) as usize, false);
        for i in 0..(8 * n) {
            result.set(i as usize, (x >> i) & 1 == 1);
        }
        result
    }

    /// `B_n` function with `n = 8`
    pub fn u64_to_bits(x: u64) -> BitVec {
        let n = 8;
        let mut result = BitVec::from_elem((8 * n) as usize, false);
        for i in 0..(8 * n) {
            result.set(i as usize, (x >> i) & 1 == 1);
        }
        result
    }

    /// Converts a binary representation back to an unsigned integer.
    /// Represents `{B_n}^-1` of the GP
    ///
    /// # Arguments
    ///
    /// * `x`: A vector of booleans representing the binary form.
    /// * `n`: The number of octets in the integer.
    ///
    /// # Returns
    ///
    /// The unsigned integer represented by the input binary form,
    /// or None if `n` is greater than 8, or if the input vector's length doesn't match `8 * n`.
    #[allow(dead_code)]
    pub(crate) fn bits_to_int(x: &BitVec, n: u64) -> Option<u64> {
        if n > 8 || x.len() != (8 * n) as usize {
            return None;
        }

        Some(
            x.iter()
                .enumerate()
                .fold(0, |acc, (i, bit)| acc | ((bit as u64) << i)),
        )
    }

    /// `{B_n}^-1` function with `n = 4`
    pub fn bits_to_u32(x: &BitVec) -> u32 {
        x.iter()
            .enumerate()
            .fold(0, |acc, (i, bit)| acc | ((bit as u32) << i))
    }

    /// `{B_n}^-1` function with `n = 8`
    pub fn bits_to_u64(x: &BitVec) -> u64 {
        x.iter()
            .enumerate()
            .fold(0, |acc, (i, bit)| acc | ((bit as u64) << i))
    }

    /// Performs signed extension on compactly encoded immediate argument octets, so that the
    /// argument can fit in the 64-bit register.
    /// Represents `X_n` of the GP.
    ///
    /// # Arguments
    ///
    /// * `compact_val`: The immediate value compactly encoded into an integer type.
    /// * `n`: The number of octets that the input integer `compact_val` represents.
    ///
    /// # Returns
    ///
    /// The sign-extended 64-bit unsigned integer.
    pub fn sext<T>(compact_val: T, n: SextInputSize) -> RegValue
    where
        T: Into<i128> + Copy,
    {
        if n.as_usize() == 0 {
            // zero is the only valid input for `compact_val` in this case
            return 0;
        }

        let val = compact_val.into();
        let msb = (val >> (8 * n.as_usize() - 1)) & 1;
        if msb == 1 {
            (val + (RegValue::MAX as i128 - (1 << (8 * n.as_usize() as i128)) + 1)) as RegValue
        } else {
            val as RegValue
        }
    }

    /// Signed modulo operations for i32
    pub fn smod_32(a: i32, b: i32) -> i32 {
        if b == 0 {
            a
        } else {
            let sgn = if a.is_positive() { 1 } else { -1 };
            sgn * (((a as i64).abs() as i32) % ((b as i64).abs() as i32))
        }
    }

    /// Signed modulo operations for i64
    pub fn smod_64(a: i64, b: i64) -> i64 {
        if b == 0 {
            a
        } else {
            let sgn = if a.is_positive() { 1 } else { -1 };
            sgn * (((a as i128).abs() as i64) % ((b as i128).abs() as i64))
        }
    }
}
