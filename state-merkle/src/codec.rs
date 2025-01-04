use crate::{
    error::StateMerkleError,
    types::*,
    utils::{bits_decode_msb, bits_encode_msb, slice_bitvec},
};
use bit_vec::BitVec;
use rjam_codec::{JamDecodeFixed, JamEncodeFixed};
use rjam_common::Hash32;
use rjam_crypto::{hash, Blake2b256};

pub struct NodeCodec;

impl NodeCodec {
    //
    // Node encoding functions
    //

    /// Encodes a branch node from its left and right child hashes.
    ///
    /// Drops the first bit of the left child hash to fit node data in 512 bits.
    /// Uses the first bit as a node type indicator (0 for branch).
    pub(crate) fn encode_branch(
        left: &Hash32,
        right: &Hash32,
    ) -> Result<Vec<u8>, StateMerkleError> {
        let mut node = BitVec::from_elem(1, false); // indicator for the branch node
        node.extend(slice_bitvec(&bits_encode_msb(left.as_slice()), 1..)?);
        node.extend(bits_encode_msb(right.as_slice()));

        Ok(bits_decode_msb(&node))
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
    ) -> Result<Vec<u8>, StateMerkleError> {
        let mut node = BitVec::new();
        if state_value.len() <= 32 {
            // indicator for the embedded leaf node
            node.extend(vec![true, false]);
            let length_bits = bits_encode_msb(&state_value.len().encode_fixed(1)?); // 8 bits

            node.extend(slice_bitvec(&length_bits, 2..)?);
            node.extend(slice_bitvec(&bits_encode_msb(state_key.as_slice()), ..248)?);
            node.extend(bits_encode_msb(state_value));

            while node.len() < NODE_SIZE_BITS {
                node.push(false); // zero padding for the remaining bits
            }
        } else {
            // indicator for the regular leaf node + zero padding
            node.extend(vec![true, true, false, false, false, false, false, false]);
            node.extend(slice_bitvec(&bits_encode_msb(state_key.as_slice()), ..248)?);
            let value_hash = hash::<Blake2b256>(state_value)?;
            node.extend(bits_encode_msb(value_hash.as_slice()));
        }

        Ok(bits_decode_msb(&node))
    }

    //
    // Node decoding functions
    //

    /// Extracts the hash identity of one of the two child nodes from a branch node data.
    ///
    /// This function takes the raw data of a branch node and returns the hash of the specified child
    /// (left or right) in `BitVec` type. For the left child, it returns 255 bits (missing the first bit),
    /// while for the right child, it returns the full 256 bits.
    ///
    /// The returned `BitVec` allows for efficient prediction and confirmation of the left child's full hash
    /// by trying both 0 and 1 for the missing first bit when retrieving the actual node.
    ///
    /// `get_node_from_hash_bits` method of `MerkleDB` handles the both cases and fetch node with the hash bits key.
    pub(crate) fn get_child_hash_bits(
        branch_node_data: &[u8],
        child_type: &ChildType,
    ) -> Result<BitVec, StateMerkleError> {
        // check node data length
        let len = branch_node_data.len();
        if len != 64 {
            return Err(StateMerkleError::InvalidNodeDataLength(len));
        }

        let bv = bits_encode_msb(branch_node_data);
        let first_bit = bv.get(0).unwrap();

        // ensure the node data represents a branch node
        if first_bit {
            return Err(StateMerkleError::InvalidNodeType);
        }

        match child_type {
            ChildType::Left => Ok(slice_bitvec(&bv, 1..=255)?),
            ChildType::Right => Ok(slice_bitvec(&bv, 256..)?),
        }
    }

    /// Extracts state data or hash of the state data from a leaf node data, depending on the `leaf_type`.
    ///
    /// This function takes encoded raw node data and type (embedded or regular) of a leaf node
    /// and returns the state data encoded with `JamCodec`.
    ///
    /// For regular leaf nodes, Blake2b-256 hash of the encoded state data is returned.
    /// For embedded leaf nodes,the encoded state data itself is returned.
    pub(crate) fn get_leaf_value(
        state_key: &BitVec,
        node: &MerkleNode,
    ) -> Result<Vec<u8>, StateMerkleError> {
        let bv = bits_encode_msb(&node.data);
        Self::validate_node_data(&bv, state_key)?;
        Self::decode_leaf(node)
    }

    fn validate_node_data(
        node_data_bv: &BitVec,
        state_key_bv: &BitVec,
    ) -> Result<(), StateMerkleError> {
        // check node data length
        if node_data_bv.len() != NODE_SIZE_BITS {
            return Err(StateMerkleError::InvalidNodeDataLength(node_data_bv.len()));
        }

        // ensure the node data represents a leaf node
        let first_bit = node_data_bv.get(0).unwrap();
        if !first_bit {
            return Err(StateMerkleError::InvalidNodeType);
        }

        // compare the state key with the encoded state key
        Self::compare_state_keys(node_data_bv, state_key_bv)?;

        Ok(())
    }

    pub(crate) fn decode_leaf(node: &MerkleNode) -> Result<Vec<u8>, StateMerkleError> {
        let node_data_bv = bits_encode_msb(&node.data);
        match node.check_node_type()? {
            NodeType::Leaf(LeafType::Embedded) => {
                // Pad the leading 2 bits with zeros (which were dropped while encoding)
                let mut length_bits_padded = BitVec::from_elem(2, false);
                length_bits_padded.extend(slice_bitvec(&node_data_bv, 2..8)?);
                let value_len_decoded =
                    u8::decode_fixed(&mut bits_decode_msb(&length_bits_padded).as_slice(), 1)?;
                let value_len_in_bits = (value_len_decoded as usize) * 8;
                let value_end_bit = 256 + value_len_in_bits;

                Ok(bits_decode_msb(&slice_bitvec(
                    &node_data_bv,
                    256..value_end_bit,
                )?))
            }
            NodeType::Leaf(LeafType::Regular) => {
                Ok(bits_decode_msb(&slice_bitvec(&node_data_bv, 256..)?))
            }
            _ => Err(StateMerkleError::InvalidNodeType),
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
        bits_encode_msb(data).get(0)
    }

    pub(crate) fn second_bit(data: &[u8]) -> Option<bool> {
        bits_encode_msb(data).get(1)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    //
    // Helper Functions
    //

    pub(crate) fn simple_hash(seed: &str) -> Hash32 {
        hash::<Blake2b256>(seed.as_bytes()).unwrap()
    }

    /// Returns 10-byte blob
    pub(crate) fn some_small_blob() -> Vec<u8> {
        hex::decode("00112233445566778899").unwrap()
    }

    /// Returns 100-byte blob
    pub(crate) fn some_large_blob() -> Vec<u8> {
        hex::decode(
            "00112233445566778899001122334455667788990011223344556677889900112233445566778899001122334455667788990011223344556677889900112233445566778899001122334455667788990011223344556677889900112233445566778899",
        )
            .unwrap()
    }

    pub(crate) fn generate_branch(left: Hash32, right: Hash32) -> MerkleNode {
        let node_data = NodeCodec::encode_branch(&left, &right).unwrap();
        let node_hash = hash::<Blake2b256>(&node_data).unwrap();
        // println!(
        //     "+++ Generated Branch: Hash({}), Left({}), Right({})",
        //     &node_hash, &left_hash, &right_hash,
        // );
        MerkleNode::new(node_hash, node_data)
    }

    pub(crate) fn generate_embedded_leaf(state_key: Hash32, state_value: &[u8]) -> MerkleNode {
        if state_value.len() > 32 {
            panic!("State data too large for embedded leaf")
        }
        let node_data = NodeCodec::encode_leaf(&state_key, state_value).unwrap();
        let node_hash = hash::<Blake2b256>(&node_data).unwrap();
        // println!(
        //     "+++ Generated Embedded: Hash({}), EmbeddedStateValue({})",
        //     &node_hash,
        //     hex::encode(&state_value)
        // );
        MerkleNode::new(node_hash, node_data)
    }

    pub(crate) fn generate_regular_leaf(state_key: Hash32, state_value: &[u8]) -> MerkleNode {
        if state_value.len() <= 32 {
            panic!("State data too small for regular leaf")
        }

        let node_data = NodeCodec::encode_leaf(&state_key, state_value).unwrap();
        let node_hash = hash::<Blake2b256>(&node_data).unwrap();
        // println!(
        //     "+++ Generated Regular: Hash({}), StateValueHash({})",
        //     &node_hash,
        //     hash::<Blake2b256>(&state_value).unwrap(),
        // );
        MerkleNode::new(node_hash, node_data)
    }

    pub(crate) fn print_node(node: &Option<MerkleNode>) {
        match node {
            Some(node) => {
                println!(">>> GET Node: {}", node.parse_node_data().unwrap());
            }
            None => println!(">>> None"),
        }
    }
}
