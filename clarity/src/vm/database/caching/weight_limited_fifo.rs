// Copyright (C) 2026 Stacks Open Internet Foundation
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

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;

/// Entry in the `WeightLimitedFifo` cache, storing the value and its weight.
struct Entry<V> {
    value: V,
    weight: u64,
}

/// FIFO cache bounded by the sum of per-entry weights.
pub struct WeightLimitedFifo<K, V> {
    /// Source of truth for membership.
    entries: HashMap<K, Entry<V>>,
    /// Insertion order, front = oldest. Each key appears exactly once.
    order: VecDeque<K>,
    total_weight: u64,
    weight_limit: u64,
    hits: u64,
    misses: u64,
}

impl<K, V> WeightLimitedFifo<K, V>
where
    K: Eq + Hash + Clone,
{
    pub fn new(weight_limit: u64) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            total_weight: 0,
            weight_limit,
            hits: 0,
            misses: 0,
        }
    }

    pub fn weight_limit(&self) -> u64 {
        self.weight_limit
    }

    pub fn total_weight(&self) -> u64 {
        self.total_weight
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn hits(&self) -> u64 {
        self.hits
    }

    pub fn misses(&self) -> u64 {
        self.misses
    }

    /// Look up `key`. Updates hit/miss counters. Does not change insertion order.
    pub fn get(&mut self, key: &K) -> Option<&V> {
        match self.entries.get(key) {
            Some(entry) => {
                self.hits = self.hits.saturating_add(1);
                Some(&entry.value)
            }
            None => {
                self.misses = self.misses.saturating_add(1);
                None
            }
        }
    }

    /// Look up `key` without touching counters.
    pub fn peek(&self, key: &K) -> Option<&V> {
        self.entries.get(key).map(|e| &e.value)
    }

    /// Insert `(key, value)` with the given `weight`. Re-insert moves the key to the back.
    /// Returns `false` only when `weight > weight_limit`; rejection leaves the cache untouched.
    ///
    /// `weight == 0` is normalized to `1` so distinct zero-weight entries can't grow the cache
    /// without bound.
    pub fn insert(&mut self, key: K, value: V, weight: u64) -> bool {
        let weight = weight.max(1);
        if weight > self.weight_limit {
            return false;
        }

        // Re-insert: drop the old entry (debit weight + remove from queue) before inserting fresh.
        if let Some(old) = self.entries.remove(&key) {
            self.total_weight = self.total_weight.saturating_sub(old.weight);
            // O(n) scan; acceptable at expected cache sizes (tens of entries).
            if let Some(pos) = self.order.iter().position(|k| k == &key) {
                self.order.remove(pos);
            }
        }

        // Evict from the front until the new entry fits.
        while self.total_weight.saturating_add(weight) > self.weight_limit {
            let Some(front_key) = self.order.pop_front() else {
                debug_assert!(false, "non-empty queue expected: weight ≤ limit");
                break;
            };
            if let Some(evicted) = self.entries.remove(&front_key) {
                self.total_weight = self.total_weight.saturating_sub(evicted.weight);
            }
        }

        self.order.push_back(key.clone());
        self.entries.insert(key, Entry { value, weight });
        self.total_weight = self.total_weight.saturating_add(weight);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_cache() {
        let cache: WeightLimitedFifo<u32, u32> = WeightLimitedFifo::new(100);
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.total_weight(), 0);
        assert_eq!(cache.weight_limit(), 100);
    }

    #[test]
    fn miss_returns_none() {
        let mut cache: WeightLimitedFifo<u32, u32> = WeightLimitedFifo::new(100);
        assert_eq!(cache.get(&42), None);
    }

    #[test]
    fn insert_then_get_hits() {
        let mut cache = WeightLimitedFifo::new(100);
        assert!(cache.insert(1u32, 'a', 10));
        assert_eq!(cache.get(&1), Some(&'a'));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.total_weight(), 10);
    }

    #[test]
    fn fifo_eviction_in_insertion_order() {
        // Budget fits exactly 3 entries of weight 10; the 4th evicts the oldest-inserted.
        let mut cache = WeightLimitedFifo::new(30);
        cache.insert(1u32, 'a', 10);
        cache.insert(2, 'b', 10);
        cache.insert(3, 'c', 10);
        cache.insert(4, 'd', 10);

        assert_eq!(cache.get(&1), None, "oldest-inserted evicted");
        assert_eq!(cache.get(&2), Some(&'b'));
        assert_eq!(cache.get(&3), Some(&'c'));
        assert_eq!(cache.get(&4), Some(&'d'));
        assert_eq!(cache.total_weight(), 30);
    }

    #[test]
    fn get_does_not_promote() {
        // Getting the oldest entry does not save it from the next eviction.
        let mut cache = WeightLimitedFifo::new(30);
        cache.insert(1u32, 'a', 10);
        cache.insert(2, 'b', 10);
        cache.insert(3, 'c', 10);

        let _ = cache.get(&1); // no-op for ordering
        cache.insert(4, 'd', 10); // still evicts the oldest-inserted: `1`

        assert_eq!(cache.get(&1), None, "get did not promote");
        assert_eq!(cache.get(&2), Some(&'b'));
        assert_eq!(cache.get(&3), Some(&'c'));
        assert_eq!(cache.get(&4), Some(&'d'));
    }

    #[test]
    fn variable_weight_evicts_multiple_to_fit() {
        let mut cache = WeightLimitedFifo::new(100);
        cache.insert(1u32, 'a', 30);
        cache.insert(2, 'b', 30);
        cache.insert(3, 'c', 30);
        // total = 90. Insert weight-50 entry:
        //   90 + 50 > 100 → evict `1`, total = 60.
        //   60 + 50 > 100 → evict `2`, total = 30.
        //   30 + 50 ≤ 100 → stop.
        cache.insert(4, 'd', 50);
        assert_eq!(cache.get(&1), None);
        assert_eq!(cache.get(&2), None);
        assert_eq!(cache.get(&3), Some(&'c'));
        assert_eq!(cache.get(&4), Some(&'d'));
        assert_eq!(cache.total_weight(), 80);
    }

    #[test]
    fn oversized_entry_rejected() {
        let mut cache = WeightLimitedFifo::new(50);
        assert!(!cache.insert(1u32, 'a', 100), "weight > limit rejected");
        assert!(cache.is_empty());

        cache.insert(2, 'b', 30);
        assert!(!cache.insert(3, 'c', 100));
        assert_eq!(
            cache.get(&2),
            Some(&'b'),
            "rejection preserves existing entries"
        );
        assert_eq!(cache.total_weight(), 30);
    }

    #[test]
    fn reinsert_same_key_moves_to_back() {
        // After re-insert, the key is at the tail of the queue, so a subsequent eviction takes the
        // next-oldest instead.
        let mut cache = WeightLimitedFifo::new(30);
        cache.insert(1u32, 'a', 10);
        cache.insert(2, 'b', 10);
        cache.insert(3, 'c', 10);
        cache.insert(1, 'A', 10); // re-insert moves 1 to back; order: 2, 3, 1

        cache.insert(4, 'd', 10); // evicts 2 (now the oldest), not 1
        assert_eq!(cache.get(&2), None);
        assert_eq!(cache.get(&1), Some(&'A'));
        assert_eq!(cache.get(&3), Some(&'c'));
        assert_eq!(cache.get(&4), Some(&'d'));
    }

    #[test]
    fn reinsert_with_heavier_weight_evicts_others() {
        // Replacing `1` (10 → 30) overflows the 40-budget; `2` (next oldest) gets evicted.
        let mut cache = WeightLimitedFifo::new(40);
        cache.insert(1u32, 'a', 10);
        cache.insert(2, 'b', 10);
        cache.insert(3, 'c', 10);
        cache.insert(1, 'A', 30);

        assert_eq!(cache.get(&2), None);
        assert_eq!(cache.get(&1), Some(&'A'));
        assert_eq!(cache.get(&3), Some(&'c'));
        assert!(cache.total_weight() <= 40);
    }

    #[test]
    fn peek_returns_value_without_changing_order() {
        let mut cache = WeightLimitedFifo::new(30);
        cache.insert(1u32, 'a', 10);
        cache.insert(2, 'b', 10);
        cache.insert(3, 'c', 10);

        assert_eq!(cache.peek(&1), Some(&'a'));

        cache.insert(4, 'd', 10);
        assert_eq!(cache.get(&1), None, "peek did not move 1 in the queue");
        assert_eq!(cache.get(&2), Some(&'b'));
        assert_eq!(cache.get(&3), Some(&'c'));
        assert_eq!(cache.get(&4), Some(&'d'));
    }

    #[test]
    fn get_updates_hit_and_miss_counters() {
        let mut cache = WeightLimitedFifo::new(100);
        cache.insert(1u32, 'a', 10);

        let _ = cache.get(&1); // hit
        let _ = cache.get(&1); // hit
        let _ = cache.get(&2); // miss
        let _ = cache.get(&3); // miss
        let _ = cache.get(&3); // miss

        assert_eq!(cache.hits(), 2);
        assert_eq!(cache.misses(), 3);
    }

    #[test]
    fn peek_does_not_touch_counters() {
        let mut cache = WeightLimitedFifo::new(100);
        cache.insert(1u32, 'a', 10);

        let _ = cache.peek(&1);
        let _ = cache.peek(&2);
        let _ = cache.peek(&1);

        assert_eq!(cache.hits(), 0);
        assert_eq!(cache.misses(), 0);
    }

    #[test]
    fn peek_miss_returns_none() {
        let cache: WeightLimitedFifo<u32, char> = WeightLimitedFifo::new(10);
        assert_eq!(cache.peek(&42), None);
    }

    #[test]
    fn eviction_drops_payload_immediately() {
        use std::sync::Arc;

        let mut cache = WeightLimitedFifo::new(10);
        let payload = Arc::new(vec![0u8; 1024]);
        let weak = Arc::downgrade(&payload);

        cache.insert(1u32, payload, 10);
        assert_eq!(weak.strong_count(), 1);

        cache.insert(2u32, Arc::new(vec![]), 10);

        assert_eq!(
            weak.strong_count(),
            0,
            "evicted payload must drop immediately",
        );
    }

    #[test]
    fn single_capacity_entry() {
        let mut cache = WeightLimitedFifo::new(10);
        cache.insert(1u32, 'a', 10);
        assert_eq!(cache.get(&1), Some(&'a'));
        cache.insert(2, 'b', 10);
        assert_eq!(cache.get(&1), None);
        assert_eq!(cache.get(&2), Some(&'b'));
    }

    #[test]
    fn zero_capacity_rejects_everything() {
        let mut cache: WeightLimitedFifo<u32, char> = WeightLimitedFifo::new(0);
        assert!(!cache.insert(1, 'a', 1));
        assert!(!cache.insert(2, 'b', 0));
        assert!(cache.is_empty());
    }

    #[test]
    fn zero_weight_is_normalized_to_one() {
        let mut cache = WeightLimitedFifo::new(3);
        cache.insert(1u32, 'a', 0);
        cache.insert(2, 'b', 0);
        cache.insert(3, 'c', 0);
        assert_eq!(cache.total_weight(), 3, "weight-0 entries count as 1");

        cache.insert(4, 'd', 0);
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.get(&1), None, "weight-0 entries FIFO-evict normally");
        assert_eq!(cache.get(&4), Some(&'d'));
    }

    #[test]
    fn queue_stays_in_sync_with_entries_after_reinserts() {
        // Repeatedly re-inserting the same key must not leave stale queue positions.
        let mut cache = WeightLimitedFifo::new(100);
        for _ in 0..50 {
            cache.insert(1u32, 'a', 10);
        }
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.order.len(), 1);
        assert_eq!(cache.total_weight(), 10);
    }
}

#[cfg(test)]
mod property_tests {
    use pinny::tag;
    use proptest::prelude::*;

    use super::*;

    /// Naive Vec-based FIFO oracle: `entries[0]` is oldest, `entries[len-1]` is newest; `get` does
    /// not move; `insert` removes prior position (if any), appends, then trims from the front until
    /// total weight fits.
    #[derive(Default)]
    struct OracleFifo {
        entries: Vec<(u32, u32, u64)>,
        weight_limit: u64,
    }

    impl OracleFifo {
        fn new(weight_limit: u64) -> Self {
            Self {
                entries: Vec::new(),
                weight_limit,
            }
        }

        fn total_weight(&self) -> u64 {
            self.entries.iter().map(|(_, _, w)| *w).sum()
        }

        fn get(&self, key: u32) -> Option<u32> {
            self.entries
                .iter()
                .find(|(k, _, _)| *k == key)
                .map(|(_, v, _)| *v)
        }

        fn insert(&mut self, key: u32, value: u32, weight: u64) -> bool {
            let weight = weight.max(1);
            if weight > self.weight_limit {
                return false;
            }
            if let Some(pos) = self.entries.iter().position(|(k, _, _)| *k == key) {
                self.entries.remove(pos);
            }
            self.entries.push((key, value, weight));
            while self.total_weight() > self.weight_limit {
                self.entries.remove(0);
            }
            true
        }
    }

    #[derive(Debug, Clone)]
    enum Op {
        Get(u32),
        Insert(u32, u32, u64),
    }

    fn arbitrary_op() -> impl Strategy<Value = Op> {
        prop_oneof![
            (0..15u32).prop_map(Op::Get),
            (0..15u32, 0..1000u32, 1..=12u64).prop_map(|(k, v, w)| Op::Insert(k, v, w)),
        ]
    }

    #[tag(t_prop)]
    #[test]
    fn matches_oracle_under_random_ops() {
        let weight_limit = 50;
        proptest!(|(ops in prop::collection::vec(arbitrary_op(), 1..200))| {
            let mut cache = WeightLimitedFifo::new(weight_limit);
            let mut oracle = OracleFifo::new(weight_limit);

            for op in ops {
                match op {
                    Op::Get(k) => {
                        let actual = cache.get(&k).copied();
                        let expected = oracle.get(k);
                        prop_assert_eq!(actual, expected);
                    }
                    Op::Insert(k, v, w) => {
                        let actual = cache.insert(k, v, w);
                        let expected = oracle.insert(k, v, w);
                        prop_assert_eq!(actual, expected);
                    }
                }
                prop_assert_eq!(cache.total_weight(), oracle.total_weight());
                prop_assert_eq!(cache.len(), oracle.entries.len());
                prop_assert!(cache.total_weight() <= weight_limit);
            }
        });
    }

    #[tag(t_prop)]
    #[test]
    fn fifo_order_matches_oracle() {
        let weight_limit = 30;
        proptest!(|(ops in prop::collection::vec(arbitrary_op(), 1..150))| {
            let mut cache = WeightLimitedFifo::new(weight_limit);
            let mut oracle = OracleFifo::new(weight_limit);

            for op in ops {
                match op {
                    Op::Get(k) => { let _ = cache.get(&k); let _ = oracle.get(k); }
                    Op::Insert(k, v, w) => { cache.insert(k, v, w); oracle.insert(k, v, w); }
                }
            }

            let oracle_keys: std::collections::HashSet<u32> =
                oracle.entries.iter().map(|(k, _, _)| *k).collect();
            for k in 0u32..15 {
                let in_cache = cache.peek(&k).is_some();
                let in_oracle = oracle_keys.contains(&k);
                prop_assert_eq!(in_cache, in_oracle, "membership disagrees on key {}", k);
            }
        });
    }
}
