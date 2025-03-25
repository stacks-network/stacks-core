// Copyright (C) 2024 Stacks Open Internet Foundation
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
        if let Some(node) = self.cache.get(key) {
            // Move the node to the head of the LRU list
            let node = *node;

            if node != self.head {
                let prev = self.order[node].prev;
                let next = self.order[node].next;

                if node == self.tail {
                    // If this is the tail, update the tail
                    self.tail = prev;
                } else {
                    // Else, update the next node's prev pointer
                    self.order[next].prev = prev;
                }

                self.order[prev].next = next;
                self.order[node].prev = self.capacity;
                self.order[node].next = self.head;
                self.order[self.head].prev = node;
                self.head = node;
            }

            Some(self.order[node].value)
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
        let mut evicted = None;
        if let Some(node) = self.cache.get(&key) {
            // Update the value for the key
            let node = *node;
            self.order[node].value = value;
            self.order[node].dirty = dirty;

            // Just call get to handle updating the LRU list
            self.get(&key);
        } else {
            let index = if self.cache.len() == self.capacity {
                // Take the place of the least recently used element.
                // First, remove it from the tail of the LRU list
                let index = self.tail;
                let prev = self.order[index].prev;
                self.order[prev].next = self.capacity;
                self.tail = prev;

                // Remove it from the cache
                self.cache.remove(&self.order[index].key);

                // Replace the key with the new key, saving the old key
                let replaced_key = std::mem::replace(&mut self.order[index].key, key.clone());

                // If it is dirty, save the key-value pair to return
                if self.order[index].dirty {
                    evicted = Some((replaced_key, self.order[index].value));
                }

                // Insert this new value into the cache
                self.cache.insert(key, index);

                // Update the node with the new key-value pair, inserting it at
                // the head of the LRU list
                self.order[index].value = value;
                self.order[index].dirty = dirty;
                self.order[index].next = self.head;
                self.order[index].prev = self.capacity;

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
        evicted
    }

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

    pub struct SimpleLRU {
        pub cache: Vec<u32>,
        capacity: usize,
    }

    impl SimpleLRU {
        pub fn new(capacity: usize) -> Self {
            SimpleLRU {
                cache: Vec::with_capacity(capacity),
                capacity,
            }
        }

        pub fn insert(&mut self, key: u32) {
            if let Some(pos) = self.cache.iter().position(|&x| x == key) {
                self.cache.remove(pos);
            } else if self.cache.len() == self.capacity {
                self.cache.remove(0);
            }
            self.cache.push(key);
        }

        pub fn get(&mut self, key: u32) -> Option<u32> {
            if let Some(pos) = self.cache.iter().position(|&x| x == key) {
                self.cache.remove(pos);
                self.cache.push(key);
                Some(key)
            } else {
                None
            }
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
        fn maintains_linked_list_integrity(ops in prop::collection::vec(arbitrary_op(), 1..1000)) {
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

        #[test]
        fn maintains_lru_correctness(ops in prop::collection::vec(arbitrary_op(), 1..1000)) {
            let mut cache = LruCache::new(5);
            let mut simple = SimpleLRU::new(5);
            for op in ops {
                match op {
                    CacheOp::Insert(v) => {
                        cache.insert(v, v);
                        simple.insert(v);
                    }
                    CacheOp::Get(v) => {
                        let actual = cache.get(&v);
                        let expected = simple.get(v);
                        prop_assert_eq!(actual, expected);
                    }
                    CacheOp::InsertClean(v) => {
                        cache.insert_clean(v, v);
                        simple.insert(v);
                    }
                    CacheOp::Flush => cache.flush(|_, _| Ok::<(), ()>(())).unwrap(),
                };

                // The cache should have the same order as the simple LRU
                let mut curr = cache.head;
                let mut count = 0;
                while curr != cache.capacity {
                    if count >= cache.order.len() {
                        prop_assert!(false, "Linked list cycle detected");
                    }
                    let idx = simple.cache.len() - count - 1;
                    prop_assert_eq!(cache.order[curr].key, simple.cache[idx]);
                    prop_assert_eq!(cache.order[curr].value, simple.cache[idx]);
                    curr = cache.order[curr].next;
                    count += 1;
                }
            }
        }
    }
}
