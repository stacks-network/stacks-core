use std::borrow::Borrow;
use std::collections::VecDeque;
use std::fmt::Formatter;
use std::marker::PhantomData;
use std::mem;

use serde::de::{Deserialize, MapAccess, Visitor};
use serde::{Serialize, Serializer};

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct VecMap<K: Ord, V> {
    data: VecDeque<(K, V)>,
}

pub struct Iter<'a, K, V>
where
    K: 'a + Ord,
    V: 'a,
{
    data: &'a VecMap<K, V>,
    next_index: usize,
}

pub struct ConsumingIter<K, V>
where
    K: Ord,
{
    data: std::vec::IntoIter<(K, V)>,
}

impl<K, V> Iterator for ConsumingIter<K, V>
where
    K: Ord,
{
    type Item = (K, V);

    fn next(&mut self) -> Option<Self::Item> {
        self.data.next()
    }
}

impl<'a, K, V> Iterator for Iter<'a, K, V>
where
    K: Ord,
{
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_index >= self.data.data.len() {
            return None;
        }
        let (ref k, ref v) = self.data.data.get(self.next_index)?;
        self.next_index = self.next_index.saturating_add(1);
        Some((k, v))
    }
}

impl<'a, K, V> IntoIterator for &'a VecMap<K, V>
where
    K: Ord,
{
    type Item = (&'a K, &'a V);
    type IntoIter = Iter<'a, K, V>;

    fn into_iter(self) -> Self::IntoIter {
        VecMap::iter(self)
    }
}

impl<K, V> IntoIterator for VecMap<K, V>
where
    K: Ord,
{
    type Item = (K, V);
    type IntoIter = std::collections::vec_deque::IntoIter<(K, V)>;

    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

impl<K: Ord, V> VecMap<K, V> {
    pub fn new() -> Self {
        Self {
            data: VecDeque::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: VecDeque::with_capacity(capacity),
        }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn iter(&self) -> Iter<K, V> {
        Iter {
            data: self,
            next_index: 0,
        }
    }

    fn get_index<Q>(&self, key: &Q) -> Result<usize, usize>
    where
        K: Borrow<Q> + Ord,
        Q: Ord + ?Sized,
    {
        self.data.binary_search_by_key(&key, |(k, _v)| k.borrow())
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        match self.get_index(&key) {
            Ok(replacement_ix) => {
                let replaced = mem::replace(&mut self.data[replacement_ix], (key, value));
                return Some(replaced.1);
            }
            Err(insertion_ix) => {
                self.data.insert(insertion_ix, (key, value));
                return None;
            }
        }
    }

    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q> + Ord,
        Q: Ord + ?Sized,
    {
        let index = self.get_index(key).ok()?;
        self.data.get(index).map(|(_, ref v)| v)
    }

    pub fn destructive_remove<Q>(mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q> + Ord,
        Q: Ord + ?Sized,
    {
        let index = self.get_index(key).ok()?;
        self.data.swap_remove_front(index).map(|(_k, v)| v)
    }

    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q> + Ord,
        Q: Ord + ?Sized,
    {
        let index = self.get_index(key).ok()?;
        self.data.remove(index).map(|(_k, v)| v)
    }

    pub fn checked_from_vec(mut value: Vec<(K, V)>) -> Result<Self, K> {
        value.sort_by(|(k_a, _v_a), (k_b, _v_b)| k_a.cmp(k_b));
        for i in 1..value.len() {
            let cur = &value[i];
            let prior = &value[i - 1];
            if cur.0 == prior.0 {
                return Err(value.remove(i).0);
            }
        }
        Ok(Self {
            data: VecDeque::from(value),
        })
    }
}

pub struct VecMapDeserVisitor<K, V> {
    marker: PhantomData<(K, V)>,
}

impl<'de, K, V> Visitor<'de> for VecMapDeserVisitor<K, V>
where
    K: Deserialize<'de> + Ord,
    V: Deserialize<'de>,
{
    type Value = VecMap<K, V>;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        write!(formatter, "a map")
    }

    #[inline]
    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut values = VecMap::with_capacity(map.size_hint().unwrap_or(0));

        while let Some((key, value)) = map.next_entry()? {
            values.insert(key, value);
        }

        Ok(values)
    }
}

impl<'de, K, V> Deserialize<'de> for VecMap<K, V>
where
    K: Deserialize<'de> + Ord,
    V: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let visitor = VecMapDeserVisitor {
            marker: PhantomData,
        };
        deserializer.deserialize_map(visitor)
    }
}

impl<K, V> Serialize for VecMap<K, V>
where
    K: Serialize + Ord,
    V: Serialize,
{
    #[inline]
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(self.iter())
    }
}

impl<K: Ord, V> From<Vec<(K, V)>> for VecMap<K, V> {
    fn from(mut value: Vec<(K, V)>) -> Self {
        value.sort_by(|(k_a, _v_a), (k_b, _v_b)| k_a.cmp(k_b));
        // reverse the entries so that dedup_by will retain the last inserted
        // entries
        value.reverse();
        value.dedup_by(|(k_a, _v_a), (k_b, _v_b)| k_a == k_b);
        value.reverse();
        let data = VecDeque::from(value);
        Self { data }
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    use super::VecMap;

    // doesn't test the remove methods...
    fn assert_coherence(input: Vec<(u8, u8)>) {
        let mut bt_map_control: BTreeMap<u8, u8> = input.iter().copied().collect();
        let mut map_by_from = VecMap::from(input.clone());
        assert_eq!(map_by_from.len(), bt_map_control.len());
        assert_eq!(map_by_from.is_empty(), bt_map_control.is_empty());
        for (vm_item, bt_item) in bt_map_control.iter().zip(&map_by_from) {
            assert_eq!(vm_item, bt_item);
            assert_eq!(vm_item.1, map_by_from.get(&vm_item.0).unwrap());
            // check non-responses too!
            assert_eq!(
                bt_map_control.get(&(vm_item.0.saturating_add(1))),
                map_by_from.get(&(vm_item.0.saturating_add(1))),
            );
        }
        let serialized_bt = serde_json::to_string(&bt_map_control).unwrap();
        let serialized_vm = serde_json::to_string(&map_by_from).unwrap();
        assert_eq!(serialized_bt, serialized_vm);
        let bt_from_vm: BTreeMap<u8, u8> = serde_json::from_str(&serialized_vm).unwrap();
        let vm_from_bt: VecMap<u8, u8> = serde_json::from_str(&serialized_bt).unwrap();
        assert_eq!(bt_from_vm, bt_map_control);
        assert_eq!(vm_from_bt, map_by_from);

        let mut map_by_insert = VecMap::with_capacity(bt_map_control.len());
        for (key, value) in input.iter() {
            map_by_insert.insert(*key, *value);
        }

        assert_eq!(map_by_from, map_by_insert);

        let mut map_by_insert = VecMap::new();
        for (key, value) in input.iter() {
            map_by_insert.insert(*key, *value);
        }

        assert_eq!(map_by_from, map_by_insert);

        for (key, value) in input.iter() {
            let control_result = bt_map_control.remove(key);
            let vm_destroyer_result = map_by_from.clone().destructive_remove(key);
            let vm_result = map_by_from.remove(key);
            assert_eq!(control_result, vm_result);
            assert_eq!(control_result, vm_destroyer_result);

            let control_result = bt_map_control.remove(key);
            let vm_destroyer_result = map_by_from.clone().destructive_remove(key);
            let vm_result = map_by_from.remove(key);
            assert_eq!(control_result, vm_result);
            assert_eq!(control_result, vm_destroyer_result);
            assert_eq!(control_result, None);
        }
    }

    #[test]
    fn test_vectors() {
        let test_vectors = vec![
            vec![
                (4, 7),
                (128, 4),
                (3, 7),
                (0, 1),
                (1, 80),
                (6, 8),
                (1, 2),
                (1, 3),
            ],
            vec![],
        ];

        for test in test_vectors {
            assert_coherence(test);
        }
    }

    #[test]
    fn test_randos() {
        let rng_seeds = 0..100;
        let vec_size = 10_000;
        for rng_seed in rng_seeds {
            let mut std_rng = StdRng::seed_from_u64(rng_seed);
            let test_vec: Vec<(u8, u8)> = (0..vec_size)
                .map(|_| (std_rng.gen(), std_rng.gen()))
                .collect();
            assert_coherence(test_vec);
        }
    }
}
