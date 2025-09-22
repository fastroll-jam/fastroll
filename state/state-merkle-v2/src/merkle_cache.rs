use crate::types::{MerkleNode, MerklePath};
use fr_common::StateKey;
use fr_state::cache::{CacheEntry, CacheEntryStatus, StateMut};
use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
};

type NodeWithPath = (MerklePath, MerkleNode);

struct MerkleCache {
    map: HashMap<MerklePath, MerkleNode>,
    affected_paths: HashSet<MerklePath>,
}

impl MerkleCache {
    fn affected_paths_as_sorted_vec(self) -> Vec<MerklePath> {
        let mut affected_paths_vec = self.affected_paths.into_iter().collect::<Vec<_>>();
        affected_paths_vec.sort_by(|a, b| {
            // First, sort by the path length (descending)
            match b.0.len().cmp(&a.0.len()) {
                Ordering::Equal => {
                    // For paths with the same length, sort by numerical value (descending)
                    for i in (0..a.0.len()).rev() {
                        match b.0.get(i).unwrap().cmp(&a.0.get(i).unwrap()) {
                            Ordering::Equal => continue,
                            other => return other,
                        }
                    }
                    // The exactly same path
                    Ordering::Equal
                }
                other => other,
            }
        });
        affected_paths_vec
    }
}

fn dirty_state_cache_entry_to_node_with_path(
    dirty_entries: &[(StateKey, CacheEntry)],
) -> NodeWithPath {
    for (_state_key, entry) in dirty_entries {
        if let CacheEntryStatus::Dirty(state_mut) = &entry.status {
            match state_mut {
                StateMut::Add => {}
                StateMut::Update => {}
                StateMut::Remove => {}
            }
        }
    }

    unimplemented!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitvec::prelude::*;

    #[test]
    fn test_affected_paths_sorting() {
        let paths = HashSet::from_iter(vec![
            MerklePath(bitvec![u8, Msb0; 1, 0, 1, 1]),
            MerklePath(bitvec![u8, Msb0; 1, 0, 1, 1, 1]),
            MerklePath(bitvec![u8, Msb0; 1]),
            MerklePath(bitvec![u8, Msb0; 1, 0, 1, 0, 1]),
            MerklePath(bitvec![u8, Msb0; 1, 0]),
        ]);

        let merkle_cache = MerkleCache {
            map: HashMap::new(),
            affected_paths: paths,
        };
        let paths_sorted = merkle_cache.affected_paths_as_sorted_vec();

        let paths_sorted_expected = vec![
            MerklePath(bitvec![u8, Msb0; 1, 0, 1, 1, 1]),
            MerklePath(bitvec![u8, Msb0; 1, 0, 1, 0, 1]),
            MerklePath(bitvec![u8, Msb0; 1, 0, 1, 1]),
            MerklePath(bitvec![u8, Msb0; 1, 0]),
            MerklePath(bitvec![u8, Msb0; 1]),
        ];
        assert_eq!(paths_sorted, paths_sorted_expected);
    }
}
