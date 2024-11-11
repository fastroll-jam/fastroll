use crate::{
    error::StateMerkleError,
    types::*,
    utils::{bytes_to_lsb_bits, slice_bitvec},
};
use bit_vec::BitVec;
use rjam_codec::JamDecodeFixed;
use rjam_common::{Hash32, Octets};
use rjam_crypto::{hash, Blake2b256};

pub struct MerkleNodeCodec;

impl MerkleNodeCodec {
    //
    // Node encoding functions
    //

    /// Encodes a branch node from its left and right child hashes.
    ///
    /// Drops the first bit of the left child hash to fit node data in 512 bits.
    /// Uses the first bit as a node type indicator (0 for branch).
    pub(crate) fn encode_branch(left: &Hash32, right: &Hash32) -> Result<BitVec, StateMerkleError> {
        let mut node = BitVec::from_elem(NODE_SIZE_BITS, false);
        node.set(0, false); // indicator for the branch node
        node.extend(slice_bitvec(&bytes_to_lsb_bits(left.as_slice()), 1..)?);
        node.extend(bytes_to_lsb_bits(right.as_slice()));

        Ok(node)
    }

    /// Encodes a leaf node from a state key and its value encoded with `JamCodec`.
    ///
    /// If value <= 32 bytes: Directly encodes value with length in the first byte (embedded leaf).
    /// If value > 32 bytes: Encodes Blake2b-256 hash of value (regular leaf).
    ///
    /// Uses first bit as node type indicator (1 for leaf) and second bit for leaf type indicator
    /// (0 for embedded leaf and 1 for regular leaf)
    pub(crate) fn encode_leaf(
        state_key: &Hash32,
        state_value: &[u8],
    ) -> Result<BitVec, StateMerkleError> {
        let mut node = BitVec::from_elem(NODE_SIZE_BITS, false);
        node.set(0, true); // indicator for the leaf node
        if state_value.len() <= 32 {
            node.set(1, false); // indicator for the embedded leaf node
            let length_bits = bytes_to_lsb_bits(&[state_value.len() as u8]);

            for i in 0..6 {
                node.set(2 + i, length_bits[i]); // 6 bits for the embedded value size
            }
            node.extend(slice_bitvec(
                &bytes_to_lsb_bits(state_key.as_slice()),
                0..248,
            )?);
            node.extend(bytes_to_lsb_bits(state_value));

            while node.len() < NODE_SIZE_BITS {
                node.push(false); // zero padding for the remaining bits
            }
        } else {
            node.set(1, true); // indicator for the regular leaf node
            node.extend(BitVec::from_elem(6, false)); // fill the first byte with zeros
            node.extend(slice_bitvec(
                &bytes_to_lsb_bits(state_key.as_slice()),
                0..248,
            )?);
            let value_hash = hash::<Blake2b256>(state_value)?;
            node.extend(bytes_to_lsb_bits(value_hash.as_slice()));
        }

        Ok(node)
    }

    //
    // Node decoding functions
    //

    /// Extracts the hash identity of one of the two child nodes from a branch node data.
    ///
    /// This function takes the raw data of a branch node and returns the hash of the specified child
    /// (left or right) in `BitVec` type. For the left child, it returns 511 bits (missing the first bit),
    /// while for the right child, it returns the full 512 bits.
    ///
    /// The returned `BitVec` allows for efficient prediction and confirmation of the left child's full hash
    /// by trying both 0 and 1 for the missing first bit when retrieving the actual node.
    ///
    /// `get_node_from_hash_bits` method of `MerkleDB` handles the both cases and fetch node with the hash bits key.
    pub(crate) fn get_child_hash_bits(
        node_data: &[u8],
        child_type: &ChildType,
    ) -> Result<BitVec, StateMerkleError> {
        // check node data length
        let len = node_data.len();
        if len != 64 {
            return Err(StateMerkleError::InvalidNodeDataLength(len));
        }

        let bv = bytes_to_lsb_bits(node_data);
        let first_bit = bv.get(0).unwrap();

        // ensure the node data represents a branch node
        if first_bit {
            return Err(StateMerkleError::InvalidNodeType);
        }

        match child_type {
            ChildType::Left => Ok(slice_bitvec(&bv, 1..=511)?),
            ChildType::Right => Ok(slice_bitvec(&bv, 512..)?),
        }
    }

    /// Extracts state data or hash of the state data from a leaf node data, depending on the `leaf_type`.
    ///
    /// This function takes the raw data and type (embedded or regular) of a leaf node and returns the state data encoded with `JamCodec`.
    ///
    /// For regular leaf nodes, the leaf node data is the Blake2b-256 hash of the encoded state data.
    /// For embedded leaf nodes, the leaf node data is the encoded state data itself.
    pub(crate) fn get_leaf_value(
        state_key: &BitVec,
        node_data: &[u8],
        leaf_type: &LeafType,
    ) -> Result<Octets, StateMerkleError> {
        // check node data length
        let len = node_data.len();
        if len != 64 {
            return Err(StateMerkleError::InvalidNodeDataLength(len));
        }

        let bv = bytes_to_lsb_bits(node_data);
        let first_bit = bv.get(0).unwrap();

        // ensure the node data represents a leaf node
        if !first_bit {
            return Err(StateMerkleError::InvalidNodeType);
        }

        // compare the state key with the encoded state key
        Self::compare_state_keys(&bv, state_key)?;

        match leaf_type {
            LeafType::Embedded => {
                let value_len = slice_bitvec(&bv, 2..8)?.to_bytes();
                let value_len_in_bits = usize::decode_fixed(&mut &value_len[..], 1)? * 8;

                Ok(slice_bitvec(&bv, 256..value_len_in_bits)?.to_bytes())
            }
            LeafType::Regular => Ok(slice_bitvec(&bv, 256..)?.to_bytes()),
        }
    }

    //
    // Codec helper functions
    //

    /// Compare the provided state key with the encoded state key in the node data.
    pub(crate) fn compare_state_keys(
        node_data_bv: &BitVec,
        state_key: &BitVec,
    ) -> Result<(), StateMerkleError> {
        let key_without_last_byte = slice_bitvec(node_data_bv, 8..256)?;
        let state_key_without_last_byte = slice_bitvec(state_key, 0..248)?;

        if key_without_last_byte != state_key_without_last_byte {
            // reached to another leaf node with the same prefix
            Err(StateMerkleError::NodeNotFound)
        } else {
            Ok(())
        }
    }

    pub(crate) fn first_bit(data: &[u8]) -> Option<bool> {
        data.first().map(|&byte| (byte & 0b1000_0000) != 0)
    }

    pub(crate) fn second_bit(data: &[u8]) -> Option<bool> {
        data.first().map(|&byte| (byte & 0b0100_0000) != 0)
    }
}
