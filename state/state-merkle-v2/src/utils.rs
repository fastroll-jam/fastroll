use crate::StateMerkleError;
use bitvec::{prelude::*, slice::BitSliceIndex};
use fr_common::Hash32;
use std::ops::RangeBounds;

/// The `bits` function of the GP (MSB-first encoding for each byte)
pub(crate) fn bits_encode_msb(data: &[u8]) -> BitVec<u8, Msb0> {
    BitVec::from_slice(data)
}

/// The inverse function of `bits` of the GP.
pub(crate) fn bits_decode_msb(bits: BitVec<u8, Msb0>) -> Vec<u8> {
    bits.into_vec()
}

pub(crate) fn slice_bitvec<'a, I>(
    bits: &'a BitVec<u8, Msb0>,
    range: I,
) -> Result<I::Immut, StateMerkleError>
where
    I: BitSliceIndex<'a, u8, Msb0>,
{
    bits.get(range)
        .ok_or(StateMerkleError::InvalidBitVecSliceRange)
}

pub(crate) fn bitvec_to_hash(data: BitVec<u8, Msb0>) -> Result<Hash32, StateMerkleError> {
    let data_len = data.len();
    let bytes = bits_decode_msb(data);
    bytes
        .as_slice()
        .try_into()
        .map(Hash32::new)
        .map_err(|_| StateMerkleError::InvalidByteLength(data_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bits_encode_decode_msb() {
        let input = vec![160, 0];
        let encoded = bits_encode_msb(&input);
        let expected = bitvec![u8, Msb0; 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(encoded, expected);

        let decoded = bits_decode_msb(encoded);
        assert_eq!(input, decoded);
    }

    #[test]
    fn test_slice_bitvec() {
        let bv = bitvec![u8, Msb0; 1, 0, 1, 1, 1, 0];
        let bv_slice = slice_bitvec(&bv, 1..5).unwrap();
        let bv_slice_owned = bv_slice.to_bitvec();
        let expected = bitvec![u8, Msb0; 0, 1, 1, 1];
        assert_eq!(bv_slice_owned, expected);
    }
}
