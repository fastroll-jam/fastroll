use fr_codec::prelude::*;
use fr_common::Hash32;
use fr_crypto::Blake2b256;

/// Fisher-Yates shuffle function.
pub fn shuffle(mut elems: Vec<u16>, randoms: Vec<u32>) -> Vec<u16> {
    let elems_len = elems.len();
    if elems_len == 0 {
        return vec![];
    }

    let mut result = Vec::with_capacity(elems_len);

    for (i, random) in randoms.into_iter().enumerate() {
        if i >= elems_len {
            break;
        }

        let range = elems_len - i;
        let idx = (random as usize) % range;
        result.push(elems[idx]);

        if i < elems_len - 1 {
            elems[idx] = elems[range - 1];
        }
    }

    result
}

/// Fisher-Yates shuffle function that consumes a 32-byte hash value to produce the random sequence.
pub fn shuffle_with_hash(elems: Vec<u16>, hash: &Hash32) -> Vec<u16> {
    let elems_len = elems.len();
    let randoms = hash_to_randoms_vec(hash, elems_len);
    shuffle(elems, randoms)
}

fn hash_to_randoms_vec(hash: &Hash32, output_len: usize) -> Vec<u32> {
    let mut output = Vec::with_capacity(output_len);

    for i in 0..(output_len as u32) {
        let hash_input_val: u32 = i / 8;
        let hash_input_bytes = hash_input_val.encode_fixed(4).unwrap();
        let new_hash =
            fr_crypto::hash::<Blake2b256>(&[hash.as_slice(), hash_input_bytes.as_slice()].concat())
                .unwrap();

        let hash_slice_start_idx: usize = (4 * i as usize) % 32;
        let hash_slice_end_idx: usize = hash_slice_start_idx + 4;

        let vec_elem = u32::decode_fixed(
            &mut &new_hash.0[hash_slice_start_idx..hash_slice_end_idx],
            4,
        )
        .unwrap();

        output.push(vec_elem);
    }

    output
}
