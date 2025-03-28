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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LruCacheCorrupted;

impl std::fmt::Display for LruCacheCorrupted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LRU cache is in a corrupted state")
    }
}

impl std::error::Error for LruCacheCorrupted {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushError<E> {
    LruCacheCorrupted,
    FlushError(E),
}

impl<E> From<E> for FlushError<E> {
    fn from(e: E) -> Self {
        FlushError::FlushError(e)
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
            let Some(node) = self.order.get(curr) else {
                writeln!(f, "  <invalid>")?;
                break;
            };
            writeln!(f, "  {}", node)?;
            curr = node.next;
        }
        Ok(())
    }
}

impl<K: Eq + std::hash::Hash + Clone, V: Copy> LruCache<K, V> {
    /// Create a new LRU cache with the given capacity (> 0)
    pub fn new(mut capacity: usize) -> Self {
        if capacity == 0 {
            error!("Capacity must be greater than 0. Defaulting to 1024.");
            capacity = 1024;
        }

        LruCache {
            capacity,
            cache: HashMap::new(),
            order: Vec::with_capacity(capacity),
            head: capacity,
            tail: capacity,
        }
    }

    /// Get the value for the given key
    /// Returns an error iff the cache is corrupted and should be discarded
    pub fn get(&mut self, key: &K) -> Result<Option<V>, LruCacheCorrupted> {
        if let Some(&index) = self.cache.get(key) {
            self.move_to_head(index)?;
            let node = self.order.get(index).ok_or(LruCacheCorrupted)?;
            Ok(Some(node.value))
        } else {
            Ok(None)
        }
    }

    /// Insert a key-value pair into the cache, marking it as dirty.
    /// Returns an error iff the cache is corrupted and should be discarded
    /// Returns `Ok(Some((K, V)))` if a dirty value was evicted.
    pub fn insert(&mut self, key: K, value: V) -> Result<Option<(K, V)>, LruCacheCorrupted> {
        self.insert_with_dirty(key, value, true)
    }

    /// Insert a key-value pair into the cache, marking it as clean.
    /// Returns an error iff the cache is corrupted and should be discarded
    /// Returns `Ok(Some((K, V)))` if a dirty value was evicted.
    pub fn insert_clean(&mut self, key: K, value: V) -> Result<Option<(K, V)>, LruCacheCorrupted> {
        self.insert_with_dirty(key, value, false)
    }

    /// Insert a key-value pair into the cache
    /// Returns an error iff the cache is corrupted and should be discarded
    /// Returns `Ok(Some((K, V)))` if a dirty value was evicted.
    pub fn insert_with_dirty(
        &mut self,
        key: K,
        value: V,
        dirty: bool,
    ) -> Result<Option<(K, V)>, LruCacheCorrupted> {
        if let Some(&index) = self.cache.get(&key) {
            // Update an existing node
            let node = self.order.get_mut(index).ok_or(LruCacheCorrupted)?;
            node.value = value;
            node.dirty = dirty;
            self.move_to_head(index)?;
            Ok(None)
        } else {
            let mut evicted = None;
            // This is a new key
            let index = if self.cache.len() == self.capacity {
                // We've reached capacity. Evict the least-recently used value
                // and reuse its node
                let index = self.evict_lru()?;
                let tail_node = self.order.get_mut(index).ok_or(LruCacheCorrupted)?;

                // Replace the key with the new key, saving the old key
                let replaced_key = std::mem::replace(&mut tail_node.key, key.clone());

                // Save the evicted key-value pair, if it was dirty
                if tail_node.dirty {
                    evicted = Some((replaced_key, tail_node.value));
                };

                // Update the evicted node with the new key-value pair
                tail_node.value = value;
                tail_node.dirty = dirty;

                // Insert the new key-value pair into the cache
                self.cache.insert(key, index);

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
            self.attach_as_head(index)?;

            Ok(evicted)
        }
    }

    /// Flush all dirty values in the cache, calling the given function, `f`,
    /// for each dirty value.
    /// Outer result is an error iff the cache is corrupted and should be discarded.
    /// Inner result is an error iff the function, `f`, returns an error.
    pub fn flush<E>(
        &mut self,
        mut f: impl FnMut(&K, V) -> Result<(), E>,
    ) -> Result<(), FlushError<E>> {
        for node in self.order.iter_mut().filter(|n| n.dirty) {
            f(&node.key, node.value)?;
            node.dirty = false;
        }
        Ok(())
    }

    /// Helper function to remove a node from the linked list (by index)
    fn detach_node(&mut self, index: usize) -> Result<(), LruCacheCorrupted> {
        let node = self.order.get(index).ok_or(LruCacheCorrupted)?;
        let prev = node.prev;
        let next = node.next;

        if index == self.tail {
            // If this is the last node, update the tail to point to its previous node
            self.tail = prev;
        } else {
            // Else, update the next node to point to the previous node
            let next_node = self.order.get_mut(next).ok_or(LruCacheCorrupted)?;
            next_node.prev = prev;
        }

        if index == self.head {
            // If this is the first node, update the head to point to the next node
            self.head = next;
        } else {
            // Else, update the previous node to point to the next node
            let prev_node = self.order.get_mut(prev).ok_or(LruCacheCorrupted)?;
            prev_node.next = next;
        }

        Ok(())
    }

    /// Helper function to attach a node as the head of the linked list
    fn attach_as_head(&mut self, index: usize) -> Result<(), LruCacheCorrupted> {
        let node = self.order.get_mut(index).ok_or(LruCacheCorrupted)?;
        node.prev = self.capacity;
        node.next = self.head;

        if self.head != self.capacity {
            // If there is a head, update its previous pointer to this one
            let head_node = self.order.get_mut(self.head).ok_or(LruCacheCorrupted)?;
            head_node.prev = index;
        } else {
            // Else, the list was empty, so update the tail
            self.tail = index;
        }
        self.head = index;
        Ok(())
    }

    /// Helper function to move a node to the head of the linked list
    fn move_to_head(&mut self, index: usize) -> Result<(), LruCacheCorrupted> {
        if index == self.head {
            // If the node is already the head, do nothing
            return Ok(());
        }

        self.detach_node(index)?;
        self.attach_as_head(index)
    }

    /// Helper function to evict the least-recently used node, which is the
    /// tail of the linked list
    /// Returns the index of the evicted node
    fn evict_lru(&mut self) -> Result<usize, LruCacheCorrupted> {
        let index = self.tail;
        if index == self.capacity {
            // If the list is empty, do nothing
            return Ok(self.capacity);
        }
        self.detach_node(index)?;
        let node = self.order.get(index).ok_or(LruCacheCorrupted)?;
        self.cache.remove(&node.key);
        Ok(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lru_cache() {
        let mut cache = LruCache::new(2);

        cache.insert(1, 1).expect("cache corrupted");
        cache.insert(2, 2).expect("cache corrupted");
        assert_eq!(cache.get(&1).expect("cache corrupted"), Some(1));
        cache.insert(3, 3).expect("cache corrupted");
        assert_eq!(cache.get(&2).expect("cache corrupted"), None);
        cache.insert(4, 4).expect("cache corrupted");
        assert_eq!(cache.get(&1).expect("cache corrupted"), None);
        assert_eq!(cache.get(&3).expect("cache corrupted"), Some(3));
        assert_eq!(cache.get(&4).expect("cache corrupted"), Some(4));
    }

    #[test]
    fn test_lru_cache_update() {
        let mut cache = LruCache::new(2);

        cache.insert(1, 1).expect("cache corrupted");
        cache.insert(2, 2).expect("cache corrupted");
        cache.insert(1, 10).expect("cache corrupted");
        assert_eq!(cache.get(&1).expect("cache corrupted"), Some(10));
        cache.insert(3, 3).expect("cache corrupted");
        assert_eq!(cache.get(&2).expect("cache corrupted"), None);
        cache.insert(2, 4).expect("cache corrupted");
        assert_eq!(cache.get(&2).expect("cache corrupted"), Some(4));
        assert_eq!(cache.get(&3).expect("cache corrupted"), Some(3));
    }

    #[test]
    fn test_lru_cache_evicted() {
        let mut cache = LruCache::new(2);

        assert!(cache.insert(1, 1).expect("cache corrupted").is_none());
        assert!(cache.insert(2, 2).expect("cache corrupted").is_none());
        let evicted = cache
            .insert(3, 3)
            .expect("cache corrupted")
            .expect("expected an eviction");
        assert_eq!(evicted, (1, 1));
    }

    #[test]
    fn test_lru_cache_flush() {
        let mut cache = LruCache::new(2);

        cache.insert(1, 1).expect("cache corrupted");

        let mut flushed = Vec::new();
        cache
            .flush(|k, v| {
                flushed.push((*k, v));
                Ok::<(), ()>(())
            })
            .expect("cache corrupted or flush failed");

        assert_eq!(flushed, vec![(1, 1)]);

        cache.insert(1, 3).expect("cache corrupted");
        cache.insert(2, 2).expect("cache corrupted");

        let mut flushed = Vec::new();
        cache
            .flush(|k, v| {
                flushed.push((*k, v));
                Ok::<(), ()>(())
            })
            .expect("cache corrupted or flush failed");

        flushed.sort();
        assert_eq!(flushed, vec![(1, 3), (2, 2)]);
    }

    #[test]
    fn test_lru_cache_evict_clean() {
        let mut cache = LruCache::new(2);

        assert!(cache
            .insert_with_dirty(0, 0, false)
            .expect("cache corrupted")
            .is_none());
        assert!(cache
            .insert_with_dirty(1, 1, false)
            .expect("cache corrupted")
            .is_none());
        assert!(cache
            .insert_with_dirty(2, 2, true)
            .expect("cache corrupted")
            .is_none());
        assert!(cache
            .insert_with_dirty(3, 3, true)
            .expect("cache corrupted")
            .is_none());

        let mut flushed = Vec::new();
        cache
            .flush(|k, v| {
                flushed.push((*k, v));
                Ok::<(), ()>(())
            })
            .expect("cache corrupted or flush failed");

        flushed.sort();
        assert_eq!(flushed, [(2, 2), (3, 3)]);
    }

    #[test]
    fn test_lru_cache_capacity_one() {
        let mut cache = LruCache::new(1);

        cache.insert(1, 1).expect("cache corrupted");
        assert_eq!(cache.get(&1).expect("cache corrupted"), Some(1));

        cache.insert(2, 2).expect("cache corrupted");
        assert_eq!(cache.get(&1).expect("cache corrupted"), None);
        assert_eq!(cache.get(&2).expect("cache corrupted"), Some(2));
    }

    #[test]
    fn test_lru_cache_capacity_one_update() {
        let mut cache = LruCache::new(1);

        cache.insert(1, 1).expect("cache corrupted");
        cache.insert(1, 2).expect("cache corrupted");
        assert_eq!(cache.get(&1).expect("cache corrupted"), Some(2));

        cache.insert(2, 3).expect("cache corrupted");
        assert_eq!(cache.get(&1).expect("cache corrupted"), None);
        assert_eq!(cache.get(&2).expect("cache corrupted"), Some(3));
    }

    #[test]
    fn test_lru_cache_capacity_one_eviction() {
        let mut cache = LruCache::new(1);

        assert!(cache.insert(1, 1).expect("cache corrupted").is_none());
        let evicted = cache
            .insert(2, 2)
            .expect("cache corrupted")
            .expect("expected eviction");
        assert_eq!(evicted, (1, 1));
    }

    #[test]
    fn test_lru_cache_capacity_one_flush() {
        let mut cache = LruCache::new(1);

        cache.insert(1, 1).expect("cache corrupted");

        let mut flushed = Vec::new();
        cache
            .flush(|k, v| {
                flushed.push((*k, v));
                Ok::<(), ()>(())
            })
            .expect("cache corrupted or flush failed");

        assert_eq!(flushed, vec![(1, 1)]);

        cache.insert(2, 2).expect("cache corrupted");

        let mut flushed = Vec::new();
        cache
            .flush(|k, v| {
                flushed.push((*k, v));
                Ok::<(), ()>(())
            })
            .expect("cache corrupted or flush failed");

        assert_eq!(flushed, vec![(2, 2)]);
    }

    /// Simple LRU implementation for property testing
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
        #[test]
        fn doesnt_crash_with_random_operations(ops in prop::collection::vec(arbitrary_op(), 1..1000)) {
            let mut cache = LruCache::new(10);
            for op in ops {
                match op {
                    CacheOp::Insert(k, v) => { cache.insert(k, v).expect("cache corrupted"); }
                    CacheOp::Get(k) => { cache.get(&k).expect("cache corrupted"); }
                    CacheOp::InsertClean(k, v) => { cache.insert_clean(k, v).expect("cache corrupted"); }
                    CacheOp::Flush => { cache.flush(|_, _| Ok::<(), ()>(())).expect("cache corrupted or flush failed"); }
                }
            }
        }

        #[test]
        fn maintains_size_invariant(ops in prop::collection::vec(0..100u32, 1..1000)) {
            let capacity = 10;
            let mut cache = LruCache::new(capacity);
            for op in ops {
                cache.insert(op, op).expect("cache corrupted");
                prop_assert!(cache.cache.len() <= capacity);
                prop_assert!(cache.order.len() <= capacity);
            }
        }

        #[test]
        fn maintains_linked_list_integrity(ops in prop::collection::vec(arbitrary_op(), 1..1000)) {
            let mut cache = LruCache::new(10);
            for op in ops {
                match op {
                    CacheOp::Insert(k, v) => { cache.insert(k, v).expect("cache corrupted"); }
                    CacheOp::Get(k) => { cache.get(&k).expect("cache corrupted"); }
                    CacheOp::InsertClean(k, v) => { cache.insert_clean(k, v).expect("cache corrupted"); }
                    CacheOp::Flush => { cache.flush(|_, _| Ok::<(), ()>(())).expect("cache corrupted or flush failed"); }
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
                        cache.insert(k, v).expect("cache corrupted");
                        simple.insert(k, v, true);
                    }
                    CacheOp::Get(k) => {
                        let actual = cache.get(&k).expect("cache corrupted");
                        let expected = simple.get(k);
                        prop_assert_eq!(actual, expected);
                    }
                    CacheOp::InsertClean(k, v) => {
                        cache.insert_clean(k, v).expect("cache corrupted");
                        simple.insert(k, v, false);
                    }
                    CacheOp::Flush => {
                        let mut flushed = vec![];
                        let mut simple_flushed = vec![];
                        cache.flush(|k, v| {
                            flushed.push((*k, v));
                            Ok::<(), ()>(())
                        }).expect("cache corrupted or flush failed");
                        simple.flush(|k, v| {
                            simple_flushed.push((*k, v));
                            Ok::<(), ()>(())
                        }).unwrap();
                        flushed.sort();
                        simple_flushed.sort();
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
