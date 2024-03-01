use std::hash::Hash;
use std::iter::{FromIterator, IntoIterator};
use std::ops::{Deref, DerefMut};

use hashbrown::HashMap;
use rand::Rng;

#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct StacksHashMap<K, V>(pub HashMap<K, V>)
where
    K: Eq + Hash;

impl<K, V> StacksHashMap<K, V>
where
    K: Eq + Hash,
{
    pub fn new() -> Self {
        StacksHashMap(HashMap::new())
    }
}

impl<'a, K, V> Deref for StacksHashMap<K, V>
where
    K: Eq + Hash,
{
    type Target = HashMap<K, V>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<K, V> DerefMut for StacksHashMap<K, V>
where
    K: Eq + Hash,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<K, V> FromIterator<(K, V)> for StacksHashMap<K, V>
where
    K: Eq + Hash,
{
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut map = StacksHashMap::new();
        for (key, value) in iter {
            map.insert(key, value);
        }
        map
    }
}

impl<K, V> IntoIterator for StacksHashMap<K, V>
where
    K: Eq + Hash,
{
    type Item = (K, V);
    type IntoIter = hashbrown::hash_map::IntoIter<K, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}