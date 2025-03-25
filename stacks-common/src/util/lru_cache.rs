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

use hashbrown::{HashMap, HashSet};

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

/// LRU cache for account nonces
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
    /// Create a new LRU cache with the given capacity
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
    pub fn get(&mut self, key: &K) -> Result<Option<V>, ()> {
        if let Some(order_idx) = self.cache.get(key) {
            // Move the node to the head of the LRU list
            if *order_idx != self.head {
                let node = self.order.get_mut(*order_idx).ok_or(())?;
                let prev = node.prev;
                let next = node.next;
                node.prev = self.capacity;
                node.next = self.head;

                if *order_idx == self.tail {
                    // If this is the tail, update the tail
                    self.tail = prev;
                } else {
                    // Else, update the next node's prev pointer
                    let next_node = self.order.get_mut(next).ok_or(())?;
                    next_node.prev = prev;
                }

                let prev_node = self.order.get_mut(prev).ok_or(())?;
                prev_node.next = next;

                let head_node = self.order.get_mut(self.head).ok_or(())?;
                head_node.prev = *order_idx;
                self.head = *order_idx;
            }

            let node = self.order.get(*order_idx).ok_or(())?;
            // Safety check: if the key doesn't match, the cache is corrupted
            if node.key != *key {
                return Err(());
            }

            Ok(Some(node.value))
        } else {
            Ok(None)
        }
    }

    /// Insert a key-value pair into the cache, marking it as dirty.
    /// Returns an error iff the cache is corrupted and should be discarded
    /// Returns `Ok(Some((K, V)))` if a dirty value was evicted.
    pub fn insert(&mut self, key: K, value: V) -> Result<Option<(K, V)>, ()> {
        self.insert_with_dirty(key, value, true)
    }

    /// Insert a key-value pair into the cache, marking it as clean.
    /// Returns an error iff the cache is corrupted and should be discarded
    /// Returns `Ok(Some((K, V)))` if a dirty value was evicted.
    pub fn insert_clean(&mut self, key: K, value: V) -> Result<Option<(K, V)>, ()> {
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
    ) -> Result<Option<(K, V)>, ()> {
        let mut evicted = None;
        if let Some(order_idx) = self.cache.get(&key) {
            // Update the value for the key
            let node = self.order.get_mut(*order_idx).ok_or(())?;
            node.value = value;
            node.dirty = dirty;

            // Just call get to handle updating the LRU list
            self.get(&key)?;
        } else {
            let index = if self.cache.len() == self.capacity {
                // Take the place of the least recently used element.
                // First, remove it from the tail of the LRU list
                let index = self.tail;
                let tail_node = self.order.get_mut(index).ok_or(())?;
                let prev = tail_node.prev;

                // Remove it from the cache
                self.cache.remove(&tail_node.key);

                // Replace the key with the new key, saving the old key
                let replaced_key = std::mem::replace(&mut tail_node.key, key.clone());

                // If it is dirty, save the key-value pair to return
                if tail_node.dirty {
                    evicted = Some((replaced_key, tail_node.value));
                }

                // Insert this new value into the cache
                self.cache.insert(key, index);

                // Update the node with the new key-value pair, inserting it at
                // the head of the LRU list
                tail_node.value = value;
                tail_node.dirty = dirty;
                tail_node.next = self.head;
                tail_node.prev = self.capacity;

                let tail_prev_node = self.order.get_mut(prev).ok_or(())?;
                tail_prev_node.next = self.capacity;
                self.tail = prev;

                index
            } else {
                // Insert a new key-value pair
                let node = Node {
                    key: key.clone(),
                    value,
                    dirty,
                    next: self.head,
                    prev: self.capacity,
                };

                let index = self.order.len();
                self.order.push(node);
                self.cache.insert(key, index);

                index
            };

            // Put it at the head of the LRU list
            if self.head != self.capacity {
                self.order[self.head].prev = index;
            } else {
                self.tail = index;
            }

            self.head = index;
        }
        Ok(evicted)
    }

    /// Flush all dirty values in the cache, calling the given function, `f`,
    /// for each dirty value.
    /// Outer result is an error iff the cache is corrupted and should be discarded.
    /// Inner result is an error iff the function, `f`, returns an error.
    pub fn flush<E>(
        &mut self,
        mut f: impl FnMut(&K, V) -> Result<(), E>,
    ) -> Result<Result<(), E>, ()> {
        let mut current = self.head;

        // Keep track of visited nodes to detect cycles
        let mut visited = HashSet::new();

        while current != self.capacity {
            // Detect cycles
            if !visited.insert(current) {
                return Err(());
            }

            let node = self.order.get_mut(current).ok_or(())?;
            let next = node.next;
            if node.dirty {
                let value = node.value;

                // Call the flush function
                match f(&node.key, value) {
                    Ok(()) => node.dirty = false,
                    Err(e) => return Ok(Err(e)),
                }
            }
            current = next;
        }
        Ok(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lru_cache() {
        let mut cache = LruCache::new(2);

        cache.insert(1, 1).unwrap();
        cache.insert(2, 2).unwrap();
        assert_eq!(cache.get(&1).unwrap(), Some(1));
        cache.insert(3, 3).unwrap();
        assert_eq!(cache.get(&2).unwrap(), None);
        cache.insert(4, 4).unwrap();
        assert_eq!(cache.get(&1).unwrap(), None);
        assert_eq!(cache.get(&3).unwrap(), Some(3));
        assert_eq!(cache.get(&4).unwrap(), Some(4));
    }

    #[test]
    fn test_lru_cache_update() {
        let mut cache = LruCache::new(2);

        cache.insert(1, 1).unwrap();
        cache.insert(2, 2).unwrap();
        cache.insert(1, 10).unwrap();
        assert_eq!(cache.get(&1).unwrap(), Some(10));
        cache.insert(3, 3).unwrap();
        assert_eq!(cache.get(&2).unwrap(), None);
        cache.insert(2, 4).unwrap();
        assert_eq!(cache.get(&2).unwrap(), Some(4));
        assert_eq!(cache.get(&3).unwrap(), Some(3));
    }

    #[test]
    fn test_lru_cache_evicted() {
        let mut cache = LruCache::new(2);

        assert!(cache.insert(1, 1).unwrap().is_none());
        assert!(cache.insert(2, 2).unwrap().is_none());
        let evicted = cache.insert(3, 3).unwrap().expect("expected an eviction");
        assert_eq!(evicted, (1, 1));
    }

    #[test]
    fn test_lru_cache_flush() {
        let mut cache = LruCache::new(2);

        cache.insert(1, 1).unwrap();

        let mut flushed = Vec::new();
        cache
            .flush(|k, v| {
                flushed.push((*k, v));
                Ok::<(), ()>(())
            })
            .unwrap();

        assert_eq!(flushed, vec![(1, 1)]);

        cache.insert(1, 3).unwrap();
        cache.insert(2, 2).unwrap();

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

        assert!(cache.insert_with_dirty(0, 0, false).unwrap().is_none());
        assert!(cache.insert_with_dirty(1, 1, false).unwrap().is_none());
        assert!(cache.insert_with_dirty(2, 2, true).unwrap().is_none());
        assert!(cache.insert_with_dirty(3, 3, true).unwrap().is_none());

        let mut flushed = Vec::new();
        cache
            .flush(|k, v| {
                flushed.push((*k, v));
                Ok::<(), ()>(())
            })
            .unwrap();

        assert_eq!(flushed, [(3, 3), (2, 2)]);
    }
}

#[cfg(test)]
mod property_tests {
    use proptest::prelude::*;

    use super::*;

    #[derive(Debug, Clone)]
    enum CacheOp {
        Insert(u32),
        Get(u32),
        InsertClean(u32),
        Flush,
    }

    prop_compose! {
        fn arbitrary_op()(op_type in 0..4, value in 0..100u32) -> CacheOp {
            match op_type {
                0 => CacheOp::Insert(value),
                1 => CacheOp::Get(value),
                2 => CacheOp::InsertClean(value),
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
                    CacheOp::Insert(v) => { cache.insert(v, v); }
                    CacheOp::Get(v) => { cache.get(&v); }
                    CacheOp::InsertClean(v) => { cache.insert_clean(v, v); }
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
        fn maintains_lru_order(ops in prop::collection::vec(arbitrary_op(), 1..1000)) {
            let mut cache = LruCache::new(10);
            for op in ops {
                match op {
                    CacheOp::Insert(v) => { cache.insert(v, v); }
                    CacheOp::Get(v) => { cache.get(&v); }
                    CacheOp::InsertClean(v) => { cache.insert_clean(v, v); }
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
    }
}
