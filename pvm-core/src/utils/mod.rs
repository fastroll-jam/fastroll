use crate::{
    constants::{INIT_PAGE_SIZE, REGION_SIZE},
    types::common::RegValue,
};
use bit_vec::BitVec;

pub struct VMUtils;

impl VMUtils {
    //
    // Program initialization util functions
    //

    /// Represents `P` of the GP
    pub fn page_align(x: usize) -> usize {
        // P(x) = Z_G * ceil(x / Z_G)
        x.div_ceil(INIT_PAGE_SIZE)
    }

    /// Represents `Q` of the GP
    pub fn region_align(x: usize) -> usize {
        // Q(x) = Z_Q * ceil(x / Z_Q)
        x.div_ceil(REGION_SIZE)
    }

    //
    // Instruction arguments processing functions
    //

    /// Converts an unsigned integer to a signed integer of the same bit width.
    /// Represents `Z_n` of the GP
    /// # Arguments
    ///
    /// * `n`: The number of octets in the integer.
    /// * `a`: The unsigned integer to convert.
    ///
    /// # Returns
    ///
    /// The signed equivalent of the input, or None if `n` is 0 or greater than 4.
    pub fn unsigned_to_signed(n: u64, a: u64) -> Option<i64> {
        match n {
            1..=8 => {
                let max_positive = 1u64 << (8 * n - 1);
                if a < max_positive {
                    Some(a as i64)
                } else {
                    Some((a as i64) - (1i64 << (8 * n)))
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
    /// * `n`: The number of octets in the integer.
    /// * `a`: The signed integer to convert.
    ///
    /// # Returns
    ///
    /// The unsigned equivalent of the input, or None if `n` is 0 or greater than 8.
    pub fn signed_to_unsigned(n: u64, a: i64) -> Option<u64> {
        match n {
            1..=8 => {
                let modulus = 1i64 << (8 * n);
                Some(((modulus + a) % modulus) as u64)
            }
            _ => None,
        }
    }

    /// Converts an unsigned integer to its binary representation.
    /// Represents `B_n` of the GP
    ///
    /// # Arguments
    ///
    /// * `n`: The number of octets in the integer.
    /// * `x`: The unsigned integer to convert.
    ///
    /// # Returns
    ///
    /// A vector of booleans representing the binary form of the input,
    /// or None if `n` is 0 or greater than 8.
    pub fn int_to_bitvec(n: u64, x: u64) -> Option<BitVec> {
        match n {
            1..=8 => {
                let mut result = BitVec::from_elem((8 * n) as usize, false);
                for i in 0..(8 * n) {
                    result.set(i as usize, (x >> i) & 1 == 1);
                }
                Some(result)
            }
            _ => None,
        }
    }

    /// Converts a binary representation back to an unsigned integer.
    /// Represents `{B_n}^-1` of the GP
    ///
    /// # Arguments
    ///
    /// * `n`: The number of octets in the integer.
    /// * `x`: A vector of booleans representing the binary form.
    ///
    /// # Returns
    ///
    /// The unsigned integer represented by the input binary form,
    /// or None if `n` is 0 or greater than 8, or if the input vector's length doesn't match 8*n.
    pub fn bitvec_to_int(n: u64, x: &BitVec) -> Option<u64> {
        if n == 0 || n > 4 || x.len() != (8 * n) as usize {
            return None;
        }

        Some(
            x.iter()
                .enumerate()
                .fold(0, |acc, (i, bit)| acc | ((bit as u64) << i)),
        )
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
    /// The sign-extended 64-bit unsigned integer, or None if `n` is 0 or greater than 4.
    pub fn signed_extend<T>(compact_val: T, n: usize) -> Option<RegValue>
    where
        T: Into<u64> + Copy,
    {
        match n {
            1..=8 => {
                let val = compact_val.into();
                let msb = (val >> (8 * n - 1)) & 1;
                if msb == 1 {
                    Some(val + (RegValue::MAX - (1 << (8 * n)) + 1))
                } else {
                    Some(val)
                }
            }
            _ => None,
        }
    }
}
