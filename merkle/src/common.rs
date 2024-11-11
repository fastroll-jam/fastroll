use rjam_codec::JamCodecError;
use rjam_common::HASH32_EMPTY;
use rjam_crypto::{hash, CryptoError, Hasher};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MerkleError {
    #[error("CryptoError: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
}

pub fn node<H: Hasher>(data: &[Vec<u8>]) -> Result<Vec<u8>, MerkleError> {
    const HASH_PREFIX: &[u8] = b"node";

    if data.is_empty() {
        return Ok(HASH32_EMPTY.to_vec());
    }

    if data.len() == 1 {
        return Ok(data[0].clone());
    }

    let left = node::<H>(&data[..((data.len() + 1) / 2)])?;
    let right = node::<H>(&data[((data.len() + 1) / 2)..])?;

    let mut hash_input = Vec::with_capacity(HASH_PREFIX.len() + left.len() + right.len());
    hash_input.extend_from_slice(HASH_PREFIX);
    hash_input.extend(&left);
    hash_input.extend(&right);

    Ok(hash::<H>(&hash_input)?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rjam_crypto::Blake2b256;

    #[test]
    fn test_node_empty() -> Result<(), MerkleError> {
        let data: &[Vec<u8>] = &[];
        let root = node::<Blake2b256>(data)?;

        assert_eq!(root, HASH32_EMPTY.to_vec());
        Ok(())
    }

    #[test]
    fn test_node_single_element() -> Result<(), MerkleError> {
        let data: &[Vec<u8>] = &[vec![0, 1]];
        let root = node::<Blake2b256>(data)?;

        assert_eq!(root, vec![0, 1]);
        Ok(())
    }

    #[test]
    fn test_node_two_elements() -> Result<(), MerkleError> {
        let data: &[Vec<u8>] = &[vec![10, 11], vec![12, 13]];
        let root = node::<Blake2b256>(data)?;

        let expected =
            hash::<Blake2b256>(&[b"node".to_vec(), vec![10, 11], vec![12, 13]].concat())?.to_vec();

        assert_eq!(root, expected);
        Ok(())
    }

    #[test]
    fn test_node_three_elements() -> Result<(), MerkleError> {
        let data: &[Vec<u8>] = &[vec![10, 11], vec![12, 13], vec![14, 15]];
        let root = node::<Blake2b256>(data)?;

        let hash_10111213 =
            hash::<Blake2b256>(&[b"node".to_vec(), vec![10, 11], vec![12, 13]].concat())?.to_vec();
        let expected =
            hash::<Blake2b256>(&[b"node".to_vec(), hash_10111213, vec![14, 15]].concat())?.to_vec();

        assert_eq!(root, expected);
        Ok(())
    }

    #[test]
    fn test_node_five_elements() -> Result<(), MerkleError> {
        let data: &[Vec<u8>] = &[vec![0, 1], vec![2, 3], vec![4, 5], vec![6, 7], vec![8, 9]];
        let root = node::<Blake2b256>(data)?;

        let hash_0123 =
            hash::<Blake2b256>(&[b"node".to_vec(), vec![0, 1], vec![2, 3]].concat())?.to_vec();
        let hash_012345 =
            hash::<Blake2b256>(&[b"node".to_vec(), hash_0123, vec![4, 5]].concat())?.to_vec();
        let hash_6789 =
            hash::<Blake2b256>(&[b"node".to_vec(), vec![6, 7], vec![8, 9]].concat())?.to_vec();
        let expected =
            hash::<Blake2b256>(&[b"node".to_vec(), hash_012345, hash_6789].concat())?.to_vec();

        assert_eq!(root, expected);
        Ok(())
    }
}
