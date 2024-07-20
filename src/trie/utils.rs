use crate::common::{Hash32, Octets};
use bit_vec::BitVec;
use blake2::{digest::consts::U32, Blake2b, Digest};
use std::ops::{Bound, RangeBounds};
use thiserror::Error;

// State Merklization Util Functions

pub(crate) const NODE_SIZE_BITS: usize = 512;
const NODE_SIZE_BYTES: usize = NODE_SIZE_BITS / 8;
pub(crate) const EMPTY_HASH: Hash32 = [0u8; 32];

type Blake2b256 = Blake2b<U32>;

#[derive(Debug, Error)]
pub enum MerklizationError {
    #[error("Blake2b hash length mismatch")]
    HashLengthMismatch,
    #[error("Expected 32 bytes, got {0}")]
    InvalidByteLength(usize),
    #[error("Node not found")]
    NodeNotFound,
    #[error("Failed to store node")]
    StoreNodeError,
    #[error("Failed to get node")]
    GetNodeError,
    #[error("Hash length mismatch")]
    HashLengthMismatchError,
}

// Black2b-256 hash
pub(crate) fn blake2b_256(value: &[u8]) -> Result<Hash32, MerklizationError> {
    let mut hasher = Blake2b256::new();
    hasher.update(value);
    let result = hasher.finalize();
    result
        .as_slice()
        .try_into()
        .map_err(|_| MerklizationError::HashLengthMismatch)
}

// The `bits` function
pub(crate) fn bytes_to_lsb_bits(data: Octets) -> BitVec {
    let mut bits = BitVec::new();
    for byte in data {
        for i in 0..8 {
            bits.push((byte >> i) & 1 == 1);
        }
    }
    bits
}

// The inverse function of `bits`
pub(crate) fn lsb_bits_to_bytes(bits: BitVec) -> Octets {
    let mut bytes = vec![];
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
    // Push remaining bits as the last byte
    if bits.len() % 8 != 0 {
        bytes.push(current_byte);
    }
    bytes
}

pub(crate) fn bytes_to_hash(data: Octets) -> Result<Hash32, MerklizationError> {
    if data.len() != 32 {
        return Err(MerklizationError::InvalidByteLength(data.len()));
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&data);
    Ok(hash)
}

pub(crate) fn bitvec_to_hash(data: BitVec) -> Result<Hash32, MerklizationError> {
    let bytes: Octets = lsb_bits_to_bytes(data);
    bytes_to_hash(bytes)
}

// BitVec helper function
pub(crate) fn slice_bitvec<R>(bits: &BitVec, range: R) -> BitVec
where
    R: RangeBounds<usize>,
{
    let len = bits.len();

    let start = match range.start_bound() {
        Bound::Included(&start) => start,
        Bound::Excluded(&start) => start + 1,
        Bound::Unbounded => 0,
    };

    let end = match range.end_bound() {
        Bound::Included(&end) => end + 1,
        Bound::Excluded(&end) => end,
        Bound::Unbounded => len,
    };

    let mut sliced_bits = BitVec::new();
    for i in start..end {
        if let Some(bit) = bits.get(i) {
            sliced_bits.push(bit);
        }
    }
    sliced_bits
}
