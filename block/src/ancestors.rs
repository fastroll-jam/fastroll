use fr_common::{BlockHeaderHash, TimeslotIndex, MAX_LOOKUP_ANCHOR_AGE};
use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashSet},
};

pub type AncestorEntry = (TimeslotIndex, BlockHeaderHash);

/// An in-memory block header ancestor set
/// maintaining min-heap of `(timeslot, header_hash)` tuple entries.
///
/// This struct holds up to `MAX_LOOKUP_ANCHOR_AGE` latest block ancestors' info.
pub struct AncestorSet {
    capacity: usize,
    /// The ancestor set min-heap
    heap: BinaryHeap<Reverse<AncestorEntry>>,
    /// A helper set for easier entry check
    set: HashSet<AncestorEntry>,
}

impl Default for AncestorSet {
    fn default() -> Self {
        Self {
            capacity: MAX_LOOKUP_ANCHOR_AGE,
            heap: BinaryHeap::with_capacity(MAX_LOOKUP_ANCHOR_AGE),
            set: HashSet::with_capacity(MAX_LOOKUP_ANCHOR_AGE),
        }
    }
}

impl AncestorSet {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            heap: BinaryHeap::with_capacity(capacity),
            set: HashSet::with_capacity(capacity),
        }
    }

    pub fn len(&self) -> usize {
        self.heap.len()
    }

    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.heap.len() == self.capacity
    }

    pub fn contains(&self, entry: &AncestorEntry) -> bool {
        self.set.contains(entry)
    }

    /// Adds an `AncestorEntry` to the `AncestorSet`. If the heap is full, removes the oldest
    /// ancestor entry.
    pub fn add(&mut self, entry: AncestorEntry) {
        if self.contains(&entry) {
            return;
        }

        if !self.is_full() {
            self.set.insert(entry.clone());
            self.heap.push(Reverse(entry));
        } else if let Some(min_entry) = self.heap.peek() {
            // Remove the oldest `AncestorEntry` (with the smallest timeslot value)
            if entry > min_entry.0 {
                if let Some(popped) = self.heap.pop() {
                    self.set.remove(&popped.0);
                }
                self.set.insert(entry.clone());
                self.heap.push(Reverse(entry));
            }
        }
    }

    pub fn add_multiple(&mut self, entries: Vec<AncestorEntry>) {
        for entry in entries {
            self.add(entry);
        }
    }

    pub fn remove(&mut self, entry: &AncestorEntry) -> bool {
        let existed = self.set.remove(entry);
        if existed {
            self.heap.retain(|e| e.0 .1 != entry.1);
        }
        existed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CAPACITY: usize = 3;

    fn create_test_entry(slot: TimeslotIndex, id: u8) -> AncestorEntry {
        let mut hash = BlockHeaderHash::default();
        hash[0] = id;
        (slot, hash)
    }

    #[test]
    fn test_ancestor_set_add_not_full() {
        let mut set = AncestorSet::with_capacity(TEST_CAPACITY);
        let entry1 = create_test_entry(10, 1);
        let entry2 = create_test_entry(20, 2);

        set.add(entry1.clone());
        set.add(entry2.clone());

        assert!(!set.is_full());
        assert_eq!(set.len(), 2);
        assert!(set.contains(&entry1));
        assert!(set.contains(&entry2));
    }

    #[test]
    fn test_ancestor_set_add_full() {
        let mut set = AncestorSet::with_capacity(TEST_CAPACITY);
        let entry1 = create_test_entry(10, 1);
        let entry2 = create_test_entry(20, 2);
        let entry3 = create_test_entry(30, 3);

        set.add(entry1.clone());
        set.add(entry2.clone());
        set.add(entry3.clone());

        assert!(set.is_full());

        // New entry
        let entry4 = create_test_entry(40, 4);
        set.add(entry4.clone());

        assert!(set.is_full());
        assert_eq!(set.len(), TEST_CAPACITY);
        assert!(set.contains(&entry2));
        assert!(set.contains(&entry3));
        assert!(set.contains(&entry4));
        // entry1 should be evicted
        assert!(!set.contains(&entry1));
    }

    #[test]
    fn test_ancestor_set_remove() {
        let mut set = AncestorSet::with_capacity(TEST_CAPACITY);
        let entry1 = create_test_entry(10, 1);
        let entry2 = create_test_entry(20, 2); // Remove this
        let entry3 = create_test_entry(30, 3);

        set.add(entry1.clone());
        set.add(entry2.clone());
        set.add(entry3.clone());

        assert!(set.is_full());
        assert!(set.contains(&entry2));

        let removed = set.remove(&entry2);
        assert!(removed);
        assert_eq!(set.len(), 2);

        assert!(set.contains(&entry1));
        assert!(!set.contains(&entry2));
        assert!(set.contains(&entry3));
    }

    #[test]
    fn test_ancestor_set_add_older_entry() {
        let mut set = AncestorSet::with_capacity(TEST_CAPACITY);
        let entry1 = create_test_entry(10, 1);
        let entry2 = create_test_entry(20, 2);
        let entry3 = create_test_entry(30, 3);

        set.add(entry1.clone());
        set.add(entry2.clone());
        set.add(entry3.clone());

        assert!(set.is_full());

        // New entry
        let entry4 = create_test_entry(5, 4);
        set.add(entry4.clone()); // Old entry; should be ignored

        assert!(set.is_full());
        assert_eq!(set.len(), TEST_CAPACITY);
        assert!(set.contains(&entry1));
        assert!(set.contains(&entry2));
        assert!(set.contains(&entry3));
        assert!(!set.contains(&entry4));
    }

    #[test]
    fn test_ancestor_set_add_supports_forking() {
        let mut set = AncestorSet::with_capacity(TEST_CAPACITY);
        let entry1 = create_test_entry(10, 1);
        set.add(entry1.clone());
        assert_eq!(set.len(), 1);

        // entry2 & entry3 implies a fork; same timeslot, different header hash
        let entry2 = create_test_entry(20, 2);
        let entry3 = create_test_entry(20, 3);
        set.add(entry2.clone());
        set.add(entry3.clone());
        assert_eq!(set.len(), 3);

        // A block is finalized (entry2); discard entry3
        set.remove(&entry3);
        assert_eq!(set.len(), 2);

        // Add the next block
        let entry4 = create_test_entry(40, 4);
        set.add(entry4.clone());
        assert_eq!(set.len(), 3);
        assert!(set.contains(&entry4));
    }
}
