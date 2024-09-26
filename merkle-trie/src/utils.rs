use crate::types::MerkleError;
use bit_vec::BitVec;
use rjam_common::{Hash32, Octets};
use std::{collections::Bound, ops::RangeBounds};

/// The `bits` function of the GP.
pub(crate) fn bytes_to_lsb_bits(data: &[u8]) -> BitVec {
    let mut bits = BitVec::with_capacity(data.len() * 8);
    for &byte in data {
        for i in 0..8 {
            bits.push(byte & (1 << i) != 0);
        }
    }
    bits
}

/// The inverse function of `bits` of the GP.
pub(crate) fn lsb_bits_to_bytes(bits: &BitVec) -> Octets {
    let mut bytes = Vec::with_capacity((bits.len() + 7) / 8);
    let mut current_byte = 0u8;
    for (i, bit) in bits.iter().enumerate() {
        if bit {
            current_byte |= 1 << (i % 8);
        }
        if i % 8 == 7 {
            bytes.push(current_byte);
            current_byte = 0;
        }
    }
    // push remaining bits as the last byte
    if bits.len() % 8 != 0 {
        bytes.push(current_byte);
    }
    bytes
}

pub(crate) fn bitvec_to_hash32(data: &BitVec) -> Result<Hash32, MerkleError> {
    let bytes = lsb_bits_to_bytes(data);
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| MerkleError::InvalidByteLength(data.len()))
}

pub(crate) fn slice_bitvec<R>(bits: &BitVec, range: R) -> Result<BitVec, MerkleError>
where
    R: RangeBounds<usize>,
{
    let start = match range.start_bound() {
        Bound::Included(&start) => start,
        Bound::Excluded(&start) => start + 1,
        Bound::Unbounded => 0,
    };

    let end = match range.end_bound() {
        Bound::Included(&end) => end + 1,
        Bound::Excluded(&end) => end,
        Bound::Unbounded => bits.len(),
    };

    if start > bits.len() || end > bits.len() || end < start {
        return Err(MerkleError::InvalidBitVecSliceRange);
    }

    Ok(bits
        .iter()
        .skip(start)
        .take(end.saturating_sub(start))
        .collect())
}
