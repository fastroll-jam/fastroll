use crate::{
    error::StateMerkleError,
    merkle_db::MerkleDB,
    types::nodes::{
        BranchType, EmbeddedLeafParsed, LeafParsed, LeafType, MerkleNode, NodeType,
        RegularLeafParsed, NODE_SIZE_BITS,
    },
    utils::{bits_decode_msb, bits_encode_msb, bitvec_to_hash32, slice_bitvec},
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
        state_val: &[u8],
    ) -> Result<Vec<u8>, StateMerkleError> {
        let mut node = BitVec::new();
        if state_val.len() <= 32 {
            // indicator for the embedded leaf node
            node.extend(vec![true, false]);
            let length_bits = bits_encode_msb(&state_val.len().encode_fixed(1)?); // 8 bits

            node.extend(slice_bitvec(&length_bits, 2..)?);
            node.extend(slice_bitvec(&bits_encode_msb(state_key.as_slice()), ..248)?);
            node.extend(bits_encode_msb(state_val));

            while node.len() < NODE_SIZE_BITS {
                node.push(false); // zero padding for the remaining bits
            }
        } else {
            // indicator for the regular leaf node + zero padding
            node.extend(vec![true, true, false, false, false, false, false, false]);
            node.extend(slice_bitvec(&bits_encode_msb(state_key.as_slice()), ..248)?);
            let value_hash = hash::<Blake2b256>(state_val)?;
            node.extend(bits_encode_msb(value_hash.as_slice()));
        }

        Ok(bits_decode_msb(&node))
    }

    //
    // Node decoding functions
    //

    /// Extracts the `left` and `right` child node hashes from the data of a branch node.
    ///
    /// A branch node stores two child node hashes, but due to size constraints, the first bit of
    /// the `left` hash is omitted so that both child hashes and the node type bit can fit within
    /// 64 bytes.
    ///
    /// Consequently, this function internally calls [`MerkleDB::restore_hash_bit`] to attempt
    /// reconstructing the `left` hash by trying both `0` and `1` for the missing bit. It then
    /// verifies which hash corresponds to an actual entry in the `MerkleDB`.
    pub async fn decode_branch(
        node: &MerkleNode,
        merkle_db: &MerkleDB,
    ) -> Result<(Hash32, Hash32), StateMerkleError> {
        // check node data length
        let len = node.data.len();
        if len != 64 {
            return Err(StateMerkleError::InvalidNodeDataLength(len));
        }

        let bv = bits_encode_msb(&node.data);
        let first_bit = bv.get(0).unwrap();

        // ensure the node data represents a branch node
        if first_bit {
            return Err(StateMerkleError::InvalidNodeType);
        }

        let left_bv = slice_bitvec(&bv, 1..=255)?;
        let left_hash = merkle_db.restore_hash_bit(&left_bv).await?;

        let right_bv = slice_bitvec(&bv, 256..)?;
        let right_hash = bitvec_to_hash32(&right_bv)?;

        Ok((left_hash, right_hash))
    }

    /// Naively checks branch type. This is useful for checking if the branch node contains an empty
    /// hash or not. If the 255 bits of the left child hash identifier are all zeroes, assumes that
    /// is an empty hash.
    pub(crate) fn check_branch_type(node: &MerkleNode) -> Result<BranchType, StateMerkleError> {
        // check node data length
        let len = node.data.len();
        if len != 64 {
            return Err(StateMerkleError::InvalidNodeDataLength(len));
        }

        let bv = bits_encode_msb(&node.data);
        let first_bit = bv.get(0).unwrap();

        // ensure the node data represents a branch node
        if first_bit {
            return Err(StateMerkleError::InvalidNodeType);
        }

        let left_bv = slice_bitvec(&bv, 1..=255)?;
        let right_bv = slice_bitvec(&bv, 256..)?;

        match (left_bv.any(), right_bv.any()) {
            (true, true) => Ok(BranchType::Full),
            (true, false) => Ok(BranchType::LeftChildOnly),
            (false, true) => Ok(BranchType::RightChildOnly),
            _ => Err(StateMerkleError::InvalidNodeData),
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
        let node_data_bv = bits_encode_msb(&node.data);
        Self::validate_node_data(&node_data_bv, state_key)?;
        let leaf_parsed = Self::decode_leaf(node)?;

        let node_data_octets = match leaf_parsed {
            LeafParsed::EmbeddedLeaf(parsed) => parsed.value,
            LeafParsed::RegularLeaf(parsed) => parsed.val_hash.to_vec(),
        };
        Ok(node_data_octets)
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

        // Verify that the provided state key matches the encoded state key.
        // Because a leaf node on the path may have a different state key,
        // an explicit validation step is required here.
        Self::compare_state_keys(node_data_bv, state_key_bv)?;

        Ok(())
    }

    pub(crate) fn decode_leaf(node: &MerkleNode) -> Result<LeafParsed, StateMerkleError> {
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

                Ok(LeafParsed::EmbeddedLeaf(EmbeddedLeafParsed {
                    node_hash: node.hash.clone(),
                    value: bits_decode_msb(&slice_bitvec(&node_data_bv, 256..value_end_bit)?),
                    partial_state_key: slice_bitvec(&node_data_bv, 8..(8 + 248))?,
                }))
            }
            NodeType::Leaf(LeafType::Regular) => Ok(LeafParsed::RegularLeaf(RegularLeafParsed {
                node_hash: node.hash.clone(),
                val_hash: bitvec_to_hash32(&slice_bitvec(&node_data_bv, 256..)?)?,
                partial_state_key: slice_bitvec(&node_data_bv, 8..(8 + 248))?,
            })),
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
        let state_key_without_last_byte_extracted = slice_bitvec(node_data_bv, 8..256)?;
        let state_key_without_last_byte = slice_bitvec(state_key, 0..248)?;

        if state_key_without_last_byte_extracted != state_key_without_last_byte {
            // reached to another leaf node with the same prefix
            Err(StateMerkleError::StateKeyMismatch)
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
