use crate::common::{Hash32, Octets};
use bit_vec::BitVec;
use blake2::{digest::consts::U32, Blake2b, Digest};
use std::ops::{Bound, RangeBounds};

// State Merklization

const NODE_SIZE_BITS: usize = 512;
const NODE_SIZE_BYTES: usize = NODE_SIZE_BITS / 8;

type Blake2b256 = Blake2b<U32>;

// The `bits` function
fn bytes_to_lsb_bits(data: Octets) -> BitVec {
    let mut bits = BitVec::new();
    for byte in data {
        for i in 0..8 {
            bits.push((byte >> i) & 1 == 1);
        }
    }

    bits
}

// The inverse function of `bits`
fn lsb_bits_to_bytes(bits: BitVec) -> Octets {
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

// Black2b-256 hash
fn blake2b_256(value: &[u8]) -> Hash32 {
    let mut hasher = Blake2b256::new();
    hasher.update(value);
    let result = hasher.finalize();
    result
        .as_slice()
        .try_into()
        .expect("Blake2b hash length mismatch")
}

// BitVec helper function
fn slice_bitvec<R>(bits: &BitVec, range: R) -> BitVec
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

// Node encoding functions
// TODO: should return BitVec instead?
fn encode_branch(left: Hash32, right: Hash32) -> Octets {
    let mut node = BitVec::from_elem(NODE_SIZE_BITS, false);
    node.set(0, false); // indicator for the Branch Node
    node.extend(slice_bitvec(&bytes_to_lsb_bits(left.to_vec()), 1..));
    node.extend(bytes_to_lsb_bits(right.to_vec()));
    lsb_bits_to_bytes(node)
}

fn encode_leaf(key: Hash32, value: Octets) -> Octets {
    let mut node = BitVec::from_elem(NODE_SIZE_BITS, false);
    node.set(0, true); // indicator for the Leaf Node
    if value.len() <= 32 {
        node.set(1, false); // indicator for the Embedded-value Leaf
        let length_bits = bytes_to_lsb_bits(vec![value.len() as u8]); // E_1 SCALE integer encoding

        for i in 0..6 {
            node.set(2 + i, length_bits[i]); // 6 bits for the embedded value size
        }
        node.extend(slice_bitvec(&bytes_to_lsb_bits(key.to_vec()), 0..248));
        node.extend(bytes_to_lsb_bits(value.to_vec()));

        while node.len() < NODE_SIZE_BITS {
            node.push(false); // filling the remaining bits with zeroes
        }
    } else {
        node.set(1, true); // indicator for the Regular Leaf
        node.extend(slice_bitvec(&bytes_to_lsb_bits(key.to_vec()), 0..248));
        node.extend(bytes_to_lsb_bits(blake2b_256(&value).to_vec()));
    }
    lsb_bits_to_bytes(node)
}
