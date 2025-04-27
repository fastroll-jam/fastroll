use crate::error::StateMerkleError;
use rjam_common::Hash32;
use rjam_crypto::{hash, Blake2b256};
use std::{
    collections::HashMap,
    fmt::{Display, Formatter},
    ops::{Deref, DerefMut},
};

/// Representation of merkle node write operation which will be added to `WriteBatch` of the `MerkleDB`.
#[derive(Clone, Debug)]
pub struct MerkleNodeWrite {
    /// Blake2b-256 hash of the `node_data` field.
    /// Used as a key to a new entry to be added in the `MerkleDB`.
    pub hash: Hash32,
    /// Encoded node data after state transition.
    /// Data of the new entry to be added in the `MerkleDB`.
    pub node_data: Vec<u8>,
}

impl Display for MerkleNodeWrite {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MerkleNodeWrite {{\n\
            \thash: {},\n\
            \tnode_data: {}\n\
            }}",
            self.hash,
            hex::encode(&self.node_data)
        )
    }
}

impl MerkleNodeWrite {
    pub fn new(hash: Hash32, node_data: Vec<u8>) -> Self {
        Self { hash, node_data }
    }
}

/// A collection of merkle node entries to be written into the `MerkleDB`. Also includes the
/// new merkle root that represents the posterior state of the merkle trie after committing them.
///
/// The `node_updates` is keyed by the node hash that previously existed at the position in the merkle trie
/// before the write operation represented by `MerkleNodeWrite`, so that parent nodes can look up
/// the map to get the "affected" value of their descendants.
#[derive(Debug, Default)]
pub struct MerkleDBWriteSet {
    new_root: Hash32,
    pub node_updates: HashMap<Hash32, MerkleNodeWrite>,
}

impl Deref for MerkleDBWriteSet {
    type Target = HashMap<Hash32, MerkleNodeWrite>;

    fn deref(&self) -> &Self::Target {
        &self.node_updates
    }
}

impl DerefMut for MerkleDBWriteSet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.node_updates
    }
}

impl Display for MerkleDBWriteSet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.node_updates.is_empty() {
            return writeln!(f, "MerkleDBWriteSet is empty");
        }

        for (key, node_write) in &self.node_updates {
            writeln!(f, "lookup_key: {key}")?;
            writeln!(f, "node_write: {node_write}")?;
        }
        Ok(())
    }
}

impl MerkleDBWriteSet {
    pub fn new(inner: HashMap<Hash32, MerkleNodeWrite>) -> Self {
        Self {
            new_root: Hash32::default(),
            node_updates: inner,
        }
    }

    pub fn get_new_root(&self) -> &Hash32 {
        &self.new_root
    }

    pub(crate) fn set_new_root(&mut self, new_root: Hash32) {
        self.new_root = new_root;
    }

    pub fn entries(&self) -> impl Iterator<Item = (&Hash32, &Vec<u8>)> {
        self.node_updates
            .values()
            .map(|node_write| (&node_write.hash, &node_write.node_data))
    }
}

/// A collection of raw state data entries for regular leaf nodes in `StateDB`.
/// Each entry is identified by a `Hash32` and contains the associated octets generated from
/// `Add` or `Update` operations.
#[derive(Debug, Default)]
pub struct StateDBWriteSet {
    inner: HashMap<Hash32, Vec<u8>>,
}

impl Deref for StateDBWriteSet {
    type Target = HashMap<Hash32, Vec<u8>>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for StateDBWriteSet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Display for StateDBWriteSet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.inner.is_empty() {
            return writeln!(f, "StateDBWriteSet is empty");
        }

        for (state_key, state_data) in &self.inner {
            writeln!(f, "State Key: {state_key}")?;
            writeln!(f, "Raw State Data: {}", hex::encode(state_data))?;
        }
        Ok(())
    }
}

impl StateDBWriteSet {
    pub fn new(inner: HashMap<Hash32, Vec<u8>>) -> Self {
        Self { inner }
    }

    pub fn entries(&self) -> impl Iterator<Item = (&Hash32, &Vec<u8>)> {
        self.inner.iter()
    }

    /// Inserts an entry if the state value is larger than 32 bytes, which
    /// implies that its corresponding leaf node is a regular leaf type.
    pub(crate) fn insert_if_regular_leaf(
        &mut self,
        state_val: &[u8],
    ) -> Result<(), StateMerkleError> {
        // regular leaf
        if state_val.len() > 32 {
            self.insert(hash::<Blake2b256>(state_val)?, state_val.to_vec());
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct DBWriteSet {
    pub merkle_db_write_set: MerkleDBWriteSet,
    pub state_db_write_set: StateDBWriteSet,
}

impl DBWriteSet {
    pub fn new(merkle_db_write_set: MerkleDBWriteSet, state_db_write_set: StateDBWriteSet) -> Self {
        Self {
            merkle_db_write_set,
            state_db_write_set,
        }
    }
}
