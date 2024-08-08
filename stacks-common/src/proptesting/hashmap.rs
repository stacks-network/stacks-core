// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use std::hash::Hash;

use hashbrown::HashMap as StacksHashMap;
use proptest::collection::{SizeRange, VecStrategy, VecValueTree};
use proptest::strategy::{statics, NewTree, Strategy, ValueTree};
use proptest::test_runner::TestRunner;
use proptest::tuple::TupleValueTree;

#[derive(Debug, Clone, Copy)]
struct MinSize(usize);

#[derive(Clone, Debug)]
pub struct StacksHashMapStrategy<K, V>(
    statics::Filter<statics::Map<VecStrategy<(K, V)>, VecToStacksHashMap>, MinSize>,
)
where
    K: Strategy,
    V: Strategy,
    K::Value: Hash + Eq;

#[derive(Clone, Debug)]
pub struct StacksHashMapValueTree<K, V>(
    statics::Filter<
        statics::Map<VecValueTree<TupleValueTree<(K, V)>>, VecToStacksHashMap>,
        MinSize,
    >,
)
where
    K: ValueTree,
    V: ValueTree,
    K::Value: Hash + Eq;

impl<K, V> Strategy for StacksHashMapStrategy<K, V>
where
    K: Strategy,
    V: Strategy,
    K::Value: Hash + Eq,
{
    type Tree = StacksHashMapValueTree<K::Tree, V::Tree>;
    type Value = StacksHashMap<K::Value, V::Value>;
    fn new_tree(&self, runner: &mut TestRunner) -> NewTree<Self> {
        self.0.new_tree(runner).map(StacksHashMapValueTree)
    }
}

impl<K, V> ValueTree for StacksHashMapValueTree<K, V>
where
    K: ValueTree,
    V: ValueTree,
    K::Value: Hash + Eq,
{
    type Value = StacksHashMap<K::Value, V::Value>;
    fn current(&self) -> Self::Value {
        self.0.current()
    }
    fn simplify(&mut self) -> bool {
        self.0.simplify()
    }
    fn complicate(&mut self) -> bool {
        self.0.complicate()
    }
}

#[derive(Clone, Copy, Debug)]
struct VecToStacksHashMap;

impl<K: std::fmt::Debug + Hash + Eq, V: std::fmt::Debug> statics::MapFn<Vec<(K, V)>>
    for VecToStacksHashMap
{
    type Output = StacksHashMap<K, V>;
    fn apply(&self, vec: Vec<(K, V)>) -> StacksHashMap<K, V> {
        vec.into_iter().collect()
    }
}

pub fn stacks_hash_map<K: Strategy, V: Strategy>(
    key: K,
    value: V,
    size: impl Into<SizeRange>,
) -> StacksHashMapStrategy<K, V>
where
    K::Value: Hash + Eq,
{
    let size = size.into();
    StacksHashMapStrategy(statics::Filter::new(
        statics::Map::new(
            proptest::collection::vec((key, value), size.clone()),
            VecToStacksHashMap,
        ),
        "HashMap minimum size".into(),
        MinSize(size.start()),
    ))
}

impl<K: Hash + Eq, V> statics::FilterFn<StacksHashMap<K, V>> for MinSize {
    fn apply(&self, map: &StacksHashMap<K, V>) -> bool {
        map.len() >= self.0
    }
}
