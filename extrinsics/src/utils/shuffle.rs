use fr_codec::prelude::*;
use fr_common::{Hash32, HASH_SIZE};
use fr_crypto::Blake2b256;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ShuffleError {
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
}

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
pub fn shuffle_with_hash(elems: Vec<u16>, hash: &Hash32) -> Result<Vec<u16>, ShuffleError> {
    let elems_len = elems.len();
    let randoms = hash_to_randoms_vec(hash, elems_len)?;
    Ok(shuffle(elems, randoms))
}

fn hash_to_randoms_vec(hash: &Hash32, output_len: usize) -> Result<Vec<u32>, ShuffleError> {
    let mut output = Vec::with_capacity(output_len);

    for i in 0..(output_len as u32) {
        let hash_input_val: u32 = i / 8;
        let hash_input_bytes = hash_input_val.encode_fixed(4)?;
        let mut buf = Vec::with_capacity(HASH_SIZE + hash_input_bytes.len());
        buf.extend(hash.as_slice());
        buf.extend(hash_input_bytes);

        let new_hash = match fr_crypto::hash::<Blake2b256>(&buf) {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Failed to derive shuffle randomness hash. Using an empty hash value instead: {e}");
                Hash32::default()
            }
        };

        let hash_slice_start_idx: usize = (4 * i as usize) % 32;
        let hash_slice_end_idx: usize = hash_slice_start_idx + 4;

        let vec_elem = u32::decode_fixed(
            &mut &new_hash.0[hash_slice_start_idx..hash_slice_end_idx],
            4,
        )?;

        output.push(vec_elem);
    }

    Ok(output)
}
