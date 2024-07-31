use std::hash::Hash;

use proptest::collection::{SizeRange, VecStrategy, VecValueTree};
use proptest::prelude::*;
use proptest::strategy::{statics, NewTree, ValueTree};
use proptest::test_runner::TestRunner;

use crate::types::StacksHashSet;

#[derive(Clone, Copy, Debug)]
struct MinSize(usize);

#[derive(Clone, Copy, Debug)]
struct VecToStacksHashSet;

impl<T: std::fmt::Debug + Hash + Eq> statics::MapFn<Vec<T>> for VecToStacksHashSet {
    type Output = StacksHashSet<T>;
    fn apply(&self, vec: Vec<T>) -> StacksHashSet<T> {
        vec.into_iter().collect()
    }
}

#[derive(Clone, Debug)]
pub struct StacksHashSetStrategy<T>(
    statics::Filter<statics::Map<VecStrategy<T>, VecToStacksHashSet>, MinSize>,
)
where
    T: Strategy,
    T::Value: Hash + Eq;

#[derive(Clone, Debug)]
pub struct StacksHashSetValueTree<T>(
    statics::Filter<statics::Map<VecValueTree<T>, VecToStacksHashSet>, MinSize>,
)
where
    T: ValueTree,
    T::Value: Hash + Eq;

impl<T> Strategy for StacksHashSetStrategy<T>
where
    T: Strategy,
    T::Value: Hash + Eq,
{
    type Tree = StacksHashSetValueTree<T::Tree>;
    type Value = StacksHashSet<T::Value>;
    fn new_tree(&self, runner: &mut TestRunner) -> NewTree<Self> {
        self.0.new_tree(runner).map(StacksHashSetValueTree)
    }
}

impl<T> ValueTree for StacksHashSetValueTree<T>
where
    T: ValueTree,
    T::Value: Hash + Eq,
{
    type Value = StacksHashSet<T::Value>;
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

impl<T: Eq + Hash> statics::FilterFn<StacksHashSet<T>> for MinSize {
    fn apply(&self, set: &StacksHashSet<T>) -> bool {
        set.len() >= self.0
    }
}

pub fn stacks_hash_set<T: Strategy>(
    element: T,
    size: impl Into<SizeRange>,
) -> StacksHashSetStrategy<T>
where
    T::Value: Hash + Eq,
{
    let size = size.into();
    StacksHashSetStrategy(statics::Filter::new(
        statics::Map::new(
            proptest::collection::vec(element, size.clone()),
            VecToStacksHashSet,
        ),
        "HashSet minimum size".into(),
        MinSize(size.start()),
    ))
}
