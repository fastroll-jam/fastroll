use crate::common::MerkleError;
use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::{Hash32, HASH_SIZE};
use rjam_crypto::{hash, Hasher, Keccak256};
use std::marker::PhantomData;

/// Merkle Mountain Range representation.
#[derive(Debug, Clone)]
pub struct MerkleMountainRange<H: Hasher> {
    pub peaks: Vec<Option<Hash32>>,
    _hasher: PhantomData<H>,
}

impl<H: Hasher> PartialEq for MerkleMountainRange<H> {
    fn eq(&self, other: &Self) -> bool {
        let self_super_peak = self.super_peak().unwrap();
        let other_super_peak = other.super_peak().unwrap();
        self_super_peak == other_super_peak
    }
}

impl<H: Hasher> Eq for MerkleMountainRange<H> {}

impl<H: Hasher> JamEncode for MerkleMountainRange<H> {
    fn size_hint(&self) -> usize {
        self.peaks.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.peaks.encode_to(dest)
    }
}

impl<H: Hasher> JamDecode for MerkleMountainRange<H> {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        let peaks = Vec::<Option<Hash32>>::decode(input)?;
        let mmr = MerkleMountainRange::new_from_peaks(peaks);

        Ok(mmr)
    }
}

impl<H: Hasher> Default for MerkleMountainRange<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: Hasher> MerkleMountainRange<H> {
    pub fn new() -> Self {
        Self {
            peaks: vec![],
            _hasher: PhantomData,
        }
    }

    pub fn new_from_peaks(peaks: Vec<Option<Hash32>>) -> Self {
        Self {
            peaks,
            _hasher: PhantomData,
        }
    }

    pub fn append(&mut self, leaf_value: Hash32) -> Result<(), MerkleError> {
        let mut curr_root = leaf_value; // Initialize to the leaf value to be appended.
        let mut index: usize = 0; // Initialize to 0.
        loop {
            // Looping until we find an empty peak or exceed the length of the peaks.
            if index >= self.peaks.len() {
                // If we've reached an index beyond the current peaks, just add the current root.
                // This implies the curr_root will be the highest root.
                self.peaks.push(Some(curr_root));
                return Ok(());
            } else if self.peaks[index].is_none() {
                // If the peak at the current index is empty, place the new root here.
                self.peaks[index] = Some(curr_root);
                return Ok(());
            } else {
                // Otherwise, we need to merge the current peak with the new root and move to the next index.
                let old_root = self.peaks[index].unwrap();

                let mut new_parent_data = [0u8; 64];
                new_parent_data[..32].copy_from_slice(&*old_root);
                new_parent_data[32..].copy_from_slice(&*curr_root);

                // Calculate the new root by hashing the concatenated data of the two children.
                curr_root = hash::<H>(&new_parent_data)?;

                // Delete the existing tree root which will be merged to the new, larger tree.
                self.peaks[index] = None;

                // Move to the next peak index
                index += 1;
            }
        }
    }

    // Alternative implementation
    // Note: we should pass the new leaf value to be appended to the parameter `curr_root`.
    pub fn append_recursive(&mut self, curr_root: Hash32, index: usize) -> Result<(), MerkleError> {
        if index >= self.peaks.len() {
            self.peaks.push(Some(curr_root));
            Ok(())
        } else if self.peaks[index].is_none() {
            self.peaks[index] = Some(curr_root);
            Ok(())
        } else {
            let old_root = self.peaks[index].unwrap();
            let mut new_parent_data = [0u8; 64];
            new_parent_data[..32].copy_from_slice(&*old_root);
            new_parent_data[32..].copy_from_slice(&*curr_root);
            let new_root = hash::<H>(&new_parent_data)?;

            self.peaks[index] = None;

            // Recursive call
            self.append_recursive(new_root, index + 1)
        }
    }

    /// MMR super-peak function that yields a single hash value committing to all the peaks.
    pub fn super_peak(&self) -> Result<Hash32, MerkleError> {
        let mut peaks = self.peaks.iter().filter_map(|p| *p);

        let Some(mut result) = peaks.next() else {
            return Ok(Hash32::default());
        };

        let prefix: &[u8] = b"peak";
        for peak in peaks {
            let mut buf = Vec::with_capacity(prefix.len() + 2 * HASH_SIZE);
            buf.extend_from_slice(prefix);
            buf.extend_from_slice(result.as_slice());
            buf.extend_from_slice(peak.as_slice());
            result = hash::<Keccak256>(&buf)?;
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rjam_common::ByteArray;
    use rjam_crypto::Blake2b256;

    // Helper function to create a Hash32 from a u8 value
    fn create_hash(value: u8) -> Hash32 {
        let mut hash = [0u8; 32];
        hash[0] = value;
        ByteArray::new(hash)
    }

    #[test]
    fn test_append_single_leaf() {
        let mut mmr = MerkleMountainRange::<Blake2b256>::new();
        let leaf = create_hash(1);
        assert!(mmr.append(leaf).is_ok());
        assert_eq!(mmr.peaks, vec![Some(leaf)]);
    }

    #[test]
    fn test_append_two_leaves() {
        let mut mmr = MerkleMountainRange::<Blake2b256>::new();
        let leaf1 = create_hash(1);
        let leaf2 = create_hash(2);
        assert!(mmr.append(leaf1).is_ok());
        assert!(mmr.append(leaf2).is_ok());

        let expected_root = {
            let mut data = [0u8; 64];
            data[..32].copy_from_slice(&*leaf1);
            data[32..].copy_from_slice(&*leaf2);
            hash::<Blake2b256>(&data).unwrap()
        };

        assert_eq!(mmr.peaks, vec![None, Some(expected_root)]);
    }

    #[test]
    fn test_append_three_leaves() {
        let mut mmr = MerkleMountainRange::<Blake2b256>::new();
        let leaf1 = create_hash(1);
        let leaf2 = create_hash(2);
        let leaf3 = create_hash(3);
        assert!(mmr.append(leaf1).is_ok());
        assert!(mmr.append(leaf2).is_ok());
        assert!(mmr.append(leaf3).is_ok());

        let expected_root12 = {
            let mut data = [0u8; 64];
            data[..32].copy_from_slice(&*leaf1);
            data[32..].copy_from_slice(&*leaf2);
            hash::<Blake2b256>(&data).unwrap()
        };

        assert_eq!(mmr.peaks, vec![Some(leaf3), Some(expected_root12)]);
    }

    #[test]
    fn test_append_four_leaves() {
        let mut mmr = MerkleMountainRange::<Blake2b256>::new();
        let leaf1 = create_hash(1);
        let leaf2 = create_hash(2);
        let leaf3 = create_hash(3);
        let leaf4 = create_hash(4);
        assert!(mmr.append(leaf1).is_ok());
        assert!(mmr.append(leaf2).is_ok());
        assert!(mmr.append(leaf3).is_ok());
        assert!(mmr.append(leaf4).is_ok());

        let expected_root1234 = {
            let root12 = {
                let mut data = [0u8; 64];
                data[..32].copy_from_slice(&*leaf1);
                data[32..].copy_from_slice(&*leaf2);
                hash::<Blake2b256>(&data).unwrap()
            };
            let root34 = {
                let mut data = [0u8; 64];
                data[..32].copy_from_slice(&*leaf3);
                data[32..].copy_from_slice(&*leaf4);
                hash::<Blake2b256>(&data).unwrap()
            };
            let mut data = [0u8; 64];
            data[..32].copy_from_slice(&*root12);
            data[32..].copy_from_slice(&*root34);
            hash::<Blake2b256>(&data).unwrap()
        };

        assert_eq!(mmr.peaks, vec![None, None, Some(expected_root1234)]);
    }

    #[test]
    fn test_append_full_mmr() {
        let n = 10;
        let num_elements = (1 << n) - 1; // 2^n - 1

        let mut mmr = MerkleMountainRange::<Blake2b256>::new();

        // Append 2^n - 1 elements
        for i in 0..num_elements {
            assert!(mmr.append(create_hash(i as u8)).is_ok());
        }

        // The number of peaks must be n.
        assert_eq!(mmr.peaks.len(), n);

        // All peaks must be Some.
        assert!(mmr.peaks.iter().all(|&peak| peak.is_some()));
    }
}
