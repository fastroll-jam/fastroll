use crate::constants::{PAGE_SIZE, SEGMENT_SIZE};
use bit_vec::BitVec;

pub struct VMUtils;

impl VMUtils {
    //
    // Program initialization util functions
    //

    pub fn p(x: usize) -> usize {
        // P(x) = Z_P * ceil(x / Z_P)
        x.div_ceil(PAGE_SIZE)
    }

    pub fn q(x: usize) -> usize {
        // Q(x) = Z_Q * ceil(x / Z_Q)
        x.div_ceil(SEGMENT_SIZE)
    }

    //
    // Instruction arguments processing functions
    //

    /// Converts an unsigned integer to a signed integer of the same bit width.
    /// Represents `Z_n` of the GP
    /// # Arguments
    ///
    /// * `n`: The number of octets (8-bit units) in the integer.
    /// * `a`: The unsigned integer to convert.
    ///
    /// # Returns
    ///
    /// The signed equivalent of the input, or None if `n` is 0 or greater than 4.
    pub fn unsigned_to_signed(n: u32, a: u32) -> Option<i32> {
        match n {
            1..=4 => {
                let max_positive = 1u32 << (8 * n - 1);
                if a < max_positive {
                    Some(a as i32)
                } else {
                    Some((a as i32) - (1i32 << (8 * n)))
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
    /// * `n`: The number of octets (8-bit units) in the integer.
    /// * `a`: The signed integer to convert.
    ///
    /// # Returns
    ///
    /// The unsigned equivalent of the input, or None if `n` is 0 or greater than 4.
    pub fn signed_to_unsigned(n: u32, a: i32) -> Option<u32> {
        match n {
            1..=4 => {
                let modulus = 1u32 << (8 * n);
                Some(((modulus as i64 + a as i64) % modulus as i64) as u32)
            }
            _ => None,
        }
    }

    /// Converts an unsigned integer to its binary representation.
    /// Represents `B_n` of the GP
    ///
    /// # Arguments
    ///
    /// * `n`: The number of octets (8-bit units) in the integer.
    /// * `x`: The unsigned integer to convert.
    ///
    /// # Returns
    ///
    /// A vector of booleans representing the binary form of the input,
    /// or None if `n` is 0 or greater than 4.
    pub fn int_to_bitvec(n: u32, x: u32) -> Option<BitVec> {
        match n {
            1..=4 => {
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
    /// * `n`: The number of octets (8-bit units) in the integer.
    /// * `x`: A vector of booleans representing the binary form.
    ///
    /// # Returns
    ///
    /// The unsigned integer represented by the input binary form,
    /// or None if `n` is 0 or greater than 4, or if the input vector's length doesn't match 8*n.
    pub fn bitvec_to_int(n: u32, x: &BitVec) -> Option<u32> {
        if n == 0 || n > 4 || x.len() != (8 * n) as usize {
            return None;
        }

        Some(
            x.iter()
                .enumerate()
                .fold(0, |acc, (i, bit)| acc | ((bit as u32) << i)),
        )
    }

    /// Performs signed extension on an unsigned integer.
    /// Represents `X_n` of the GP
    ///
    /// # Arguments
    ///
    /// * `n`: The number of octets (8-bit units) in the input integer.
    /// * `x`: The unsigned integer to extend.
    ///
    /// # Returns
    ///
    /// The sign-extended 32-bit unsigned integer, or None if `n` is 0 or greater than 4.
    pub fn signed_extend(n: u32, x: u32) -> Option<u32> {
        match n {
            1..=4 => {
                let msb = x >> (8 * n - 1);
                let extension = msb * (u32::MAX - (1 << (8 * n)) + 1);
                Some(x + extension)
            }
            _ => None,
        }
    }
}
