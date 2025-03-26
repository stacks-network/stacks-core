// Copyright (C) 2025 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::fmt::Display;

use hashbrown::HashMap;

/// Node in the doubly linked list
struct Node<K, V> {
    key: K,
    value: V,
    dirty: bool,
    next: usize,
    prev: usize,
}

impl<K: Display, V: Display> Display for Node<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}={} ({}) [prev={}, next={}]",
            self.key,
            self.value,
            if self.dirty { "dirty" } else { "clean" },
            self.prev,
            self.next
        )
    }
}

/// LRU cache
pub struct LruCache<K, V> {
    capacity: usize,
    /// Map from address to an offset in the linked list
    cache: HashMap<K, usize>,
    /// Doubly linked list of values in order of most recently used
    order: Vec<Node<K, V>>,
    /// Index of the head of the linked list -- the most recently used element
    head: usize,
    /// Index of the tail of the linked list -- the least recently used element
    tail: usize,
}

impl<K: Display, V: Display> Display for LruCache<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "LruCache (capacity={}, head={}, tail={})",
            self.capacity, self.head, self.tail
        )?;
        let mut curr = self.head;
        while curr != self.capacity {
            writeln!(f, "  {}", self.order[curr])?;
            curr = self.order[curr].next;
        }
        Ok(())
    }
}

impl<K: Eq + std::hash::Hash + Clone, V: Copy> LruCache<K, V> {
    /// Create a new LRU cache with the given capacity
    pub fn new(capacity: usize) -> Self {
        LruCache {
            capacity,
            cache: HashMap::new(),
            order: Vec::with_capacity(capacity),
            head: capacity,
            tail: capacity,
        }
    }

    /// Get the value for the given key
    pub fn get(&mut self, key: &K) -> Option<V> {
        if let Some(&index) = self.cache.get(key) {
            self.move_to_head(index);
            Some(self.order[index].value)
        } else {
            None
        }
    }

    /// Insert a key-value pair into the cache, marking it as dirty.
    /// Returns `Some((K, V))` if a dirty value was evicted.
    pub fn insert(&mut self, key: K, value: V) -> Option<(K, V)> {
        self.insert_with_dirty(key, value, true)
    }

    /// Insert a key-value pair into the cache, marking it as clean.
    /// Returns `Some((K, V))` if a dirty value was evicted.
    pub fn insert_clean(&mut self, key: K, value: V) -> Option<(K, V)> {
        self.insert_with_dirty(key, value, false)
    }

    /// Insert a key-value pair into the cache
    /// Returns `Some((K, V))` if a dirty value was evicted.
    pub fn insert_with_dirty(&mut self, key: K, value: V, dirty: bool) -> Option<(K, V)> {
        if let Some(&index) = self.cache.get(&key) {
            // Update an existing node
            self.order[index].value = value;
            self.order[index].dirty = dirty;
            self.move_to_head(index);
            None
        } else {
            let mut evicted = None;
            // This is a new key
            let index = if self.cache.len() == self.capacity {
                // We've reached capacity. Evict the least-recently used value
                // and reuse its node
                let index = self.evict_lru();

                // Replace the key with the new key, saving the old key
                let replaced_key = std::mem::replace(&mut self.order[index].key, key.clone());

                // Save the evicted key-value pair, if it was dirty
                if self.order[index].dirty {
                    evicted = Some((replaced_key, self.order[index].value));
                };

                // Update the evicted node with the new key-value pair
                self.order[index].value = value;
                self.order[index].dirty = dirty;

                // Insert the new key-value pair into the cache
                self.cache.insert(key.clone(), index);

                index
            } else {
                // Create a new node, add it to the cache
                let index = self.order.len();
                let node = Node {
                    key: key.clone(),
                    value,
                    dirty,
                    next: self.capacity,
                    prev: self.capacity,
                };
                self.order.push(node);
                self.cache.insert(key, index);
                index
            };

            // Put the new or reused node at the head of the LRU list
            self.attach_as_head(index);

            evicted
        }
    }

    /// Flush all dirty values in the cache, calling the given function, `f`,
    /// for each dirty value.
    pub fn flush<E>(&mut self, mut f: impl FnMut(&K, V) -> Result<(), E>) -> Result<(), E> {
        let mut index = self.head;
        while index != self.capacity {
            let next = self.order[index].next;
            if self.order[index].dirty {
                let value = self.order[index].value;
                f(&self.order[index].key, value)?;
                self.order[index].dirty = false;
            }
            index = next;
        }
        Ok(())
    }

    /// Helper function to remove a node from the linked list (by index)
    fn detach_node(&mut self, index: usize) {
        if index >= self.order.len() {
            return;
        }

        let prev = self.order[index].prev;
        let next = self.order[index].next;

        if index == self.tail {
            // If this is the last node, update the tail to point to its previous node
            self.tail = prev;
        } else {
            // Else, update the next node to point to the previous node
            self.order[next].prev = prev;
        }

        if index == self.head {
            // If this is the first node, update the head to point to the next node
            self.head = next;
        } else {
            // Else, update the previous node to point to the next node
            self.order[prev].next = next;
        }
    }

    /// Helper function to attach a node as the head of the linked list
    fn attach_as_head(&mut self, index: usize) {
        self.order[index].prev = self.capacity;
        self.order[index].next = self.head;

        if self.head != self.capacity {
            // If there is a head, update its previous pointer to this one
            self.order[self.head].prev = index;
        } else {
            // Else, the list was empty, so update the tail
            self.tail = index;
        }
        self.head = index;
    }

    /// Helper function to move a node to the head of the linked list
    fn move_to_head(&mut self, index: usize) {
        if index == self.head {
            // If the node is already the head, do nothing
            return;
        }

        self.detach_node(index);
        self.attach_as_head(index);
    }

    /// Helper function to evict the least-recently used node, which is the
    /// tail of the linked list
    /// Returns the index of the evicted node
    fn evict_lru(&mut self) -> usize {
        let index = self.tail;
        if index == self.capacity {
            // If the list is empty, do nothing
            return self.capacity;
        }
        self.detach_node(index);
        self.cache.remove(&self.order[index].key);
        index
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lru_cache() {
        let mut cache = LruCache::new(2);

        cache.insert(1, 1);
        cache.insert(2, 2);
        assert_eq!(cache.get(&1), Some(1));
        cache.insert(3, 3);
        assert_eq!(cache.get(&2), None);
        cache.insert(4, 4);
        assert_eq!(cache.get(&1), None);
        assert_eq!(cache.get(&3), Some(3));
        assert_eq!(cache.get(&4), Some(4));
    }

    #[test]
    fn test_lru_cache_update() {
        let mut cache = LruCache::new(2);

        cache.insert(1, 1);
        cache.insert(2, 2);
        cache.insert(1, 10);
        assert_eq!(cache.get(&1), Some(10));
        cache.insert(3, 3);
        assert_eq!(cache.get(&2), None);
        cache.insert(2, 4);
        assert_eq!(cache.get(&2), Some(4));
        assert_eq!(cache.get(&3), Some(3));
    }

    #[test]
    fn test_lru_cache_evicted() {
        let mut cache = LruCache::new(2);

        assert!(cache.insert(1, 1).is_none());
        assert!(cache.insert(2, 2).is_none());
        let evicted = cache.insert(3, 3).expect("expected an eviction");
        assert_eq!(evicted, (1, 1));
    }

    #[test]
    fn test_lru_cache_flush() {
        let mut cache = LruCache::new(2);

        cache.insert(1, 1);

        let mut flushed = Vec::new();
        cache
            .flush(|k, v| {
                flushed.push((*k, v));
                Ok::<(), ()>(())
            })
            .unwrap();

        assert_eq!(flushed, vec![(1, 1)]);

        cache.insert(1, 3);
        cache.insert(2, 2);

        let mut flushed = Vec::new();
        cache
            .flush(|k, v| {
                flushed.push((*k, v));
                Ok::<(), ()>(())
            })
            .unwrap();

        assert_eq!(flushed, vec![(2, 2), (1, 3)]);
    }

    #[test]
    fn test_lru_cache_evict_clean() {
        let mut cache = LruCache::new(2);

        assert!(cache.insert_with_dirty(0, 0, false).is_none());
        assert!(cache.insert_with_dirty(1, 1, false).is_none());
        assert!(cache.insert_with_dirty(2, 2, true).is_none());
        assert!(cache.insert_with_dirty(3, 3, true).is_none());

        let mut flushed = Vec::new();
        cache
            .flush(|k, v| {
                flushed.push((*k, v));
                Ok::<(), ()>(())
            })
            .unwrap();

        assert_eq!(flushed, [(3, 3), (2, 2)]);
    }

    /// Simple LRU implementation for testing
    pub struct SimpleLRU {
        pub cache: Vec<Node<u32, u32>>,
        capacity: usize,
    }

    impl SimpleLRU {
        pub fn new(capacity: usize) -> Self {
            SimpleLRU {
                cache: Vec::with_capacity(capacity),
                capacity,
            }
        }

        pub fn insert(&mut self, key: u32, value: u32, dirty: bool) {
            if let Some(pos) = self.cache.iter().position(|x| x.key == key) {
                self.cache.remove(pos);
            } else if self.cache.len() == self.capacity {
                self.cache.remove(0);
            }
            self.cache.push(Node {
                key,
                value,
                dirty,
                next: 0,
                prev: 0,
            });
        }

        pub fn get(&mut self, key: u32) -> Option<u32> {
            if let Some(pos) = self.cache.iter().position(|x| x.key == key) {
                let node = self.cache.remove(pos);
                let value = node.value;
                self.cache.push(node);
                Some(value)
            } else {
                None
            }
        }

        pub fn flush<E>(&mut self, mut f: impl FnMut(&u32, u32) -> Result<(), E>) -> Result<(), E> {
            for node in self.cache.iter_mut().rev() {
                if node.dirty {
                    f(&node.key, node.value)?;
                }
                node.dirty = false;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod property_tests {
    use proptest::prelude::*;

    use super::tests::SimpleLRU;
    use super::*;

    #[derive(Debug, Clone)]
    enum CacheOp {
        Insert(u32, u32),
        Get(u32),
        InsertClean(u32, u32),
        Flush,
    }

    prop_compose! {
        fn arbitrary_op()(op_type in 0..4, key in 0..100u32, value in 0..1000u32) -> CacheOp {
            match op_type {
                0 => CacheOp::Insert(key, value),
                1 => CacheOp::Get(key),
                2 => CacheOp::InsertClean(key, value),
                _ => CacheOp::Flush,
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1_000_000))]

        #[test]
        fn doesnt_crash_with_random_operations(ops in prop::collection::vec(arbitrary_op(), 1..1000)) {
            let mut cache = LruCache::new(10);
            for op in ops {
                match op {
                    CacheOp::Insert(k, v) => { cache.insert(k, v); }
                    CacheOp::Get(k) => { cache.get(&k); }
                    CacheOp::InsertClean(k, v) => { cache.insert_clean(k, v); }
                    CacheOp::Flush => { cache.flush(|_, _| Ok::<(), ()>(())).unwrap(); }
                }
            }
        }

        #[test]
        fn maintains_size_invariant(ops in prop::collection::vec(0..100u32, 1..1000)) {
            let capacity = 10;
            let mut cache = LruCache::new(capacity);
            for op in ops {
                cache.insert(op, op);
                prop_assert!(cache.cache.len() <= capacity);
                prop_assert!(cache.order.len() <= capacity);
            }
        }

        #[test]
        fn maintains_linked_list_integrity(ops in prop::collection::vec(arbitrary_op(), 1..1000)) {
            let mut cache = LruCache::new(10);
            for op in ops {
                match op {
                    CacheOp::Insert(k, v) => { cache.insert(k, v); }
                    CacheOp::Get(k) => { cache.get(&k); }
                    CacheOp::InsertClean(k, v) => { cache.insert_clean(k, v); }
                    CacheOp::Flush => { cache.flush(|_, _| Ok::<(), ()>(())).unwrap(); }
                }
                // Verify linked list integrity
                if !cache.order.is_empty() {
                    let mut curr = cache.head;
                    let mut count = 0;
                    while curr != cache.capacity {
                        if count >= cache.order.len() {
                            prop_assert!(false, "Linked list cycle detected");
                        }
                        if cache.order[curr].next != cache.capacity {
                            prop_assert_eq!(cache.order[cache.order[curr].next].prev, curr);
                        }
                        curr = cache.order[curr].next;
                        count += 1;
                    }
                }
            }
        }

        #[test]
        fn maintains_lru_correctness(ops in prop::collection::vec(arbitrary_op(), 1..1000)) {
            let mut cache = LruCache::new(5);
            let mut simple = SimpleLRU::new(5);
            for op in ops {
                match op {
                    CacheOp::Insert(k, v) => {
                        cache.insert(k, v);
                        simple.insert(k, v, true);
                    }
                    CacheOp::Get(k) => {
                        let actual = cache.get(&k);
                        let expected = simple.get(k);
                        prop_assert_eq!(actual, expected);
                    }
                    CacheOp::InsertClean(k, v) => {
                        cache.insert_clean(k, v);
                        simple.insert(k, v, false);
                    }
                    CacheOp::Flush => {
                        let mut flushed = vec![];
                        let mut simple_flushed = vec![];
                        cache.flush(|k, v| {
                            flushed.push((*k, v));
                            Ok::<(), ()>(())
                        }).unwrap();
                        simple.flush(|k, v| {
                            simple_flushed.push((*k, v));
                            Ok::<(), ()>(())
                        }).unwrap();
                        prop_assert_eq!(flushed, simple_flushed);
                    }
                };

                // The cache should have the same order as the simple LRU
                let mut curr = cache.head;
                let mut count = 0;
                while curr != cache.capacity {
                    if count >= cache.order.len() {
                        prop_assert!(false, "Linked list cycle detected");
                    }
                    let idx = simple.cache.len() - count - 1;
                    prop_assert_eq!(cache.order[curr].key, simple.cache[idx].key);
                    prop_assert_eq!(cache.order[curr].value, simple.cache[idx].value);
                    curr = cache.order[curr].next;
                    count += 1;
                }
            }
        }
    }
}
