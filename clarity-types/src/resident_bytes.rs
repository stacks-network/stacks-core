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

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::mem::size_of;
use std::sync::Arc;

#[cfg(feature = "developer-mode")]
use crate::representations::Span;
use crate::representations::{
    ClarityName, ContractName, SymbolicExpression, SymbolicExpressionType, TraitDefinition,
};
use crate::types::signatures::{
    BufferLength, CallableSubtype, ListTypeData, SequenceSubtype, StringSubtype, StringUTF8Length,
    TupleTypeSignature, TypeSignature,
};
use crate::types::{
    ASCIIData, BuffData, CallableData, CharType, FunctionIdentifier, ListData, OptionalData,
    PrincipalData, QualifiedContractIdentifier, ResponseData, SequenceData, StandardPrincipalData,
    TraitIdentifier, TupleData, UTF8Data, Value,
};

/// Estimated overhead for `Arc<T>`: `strong + weak counts + allocation header`.
const ARC_OVERHEAD: usize = 16;

// The `btree` and `hashmap` modules below contain heuristic constants derived from std's internal
// implementations (as of Rust 1.94 / hashbrown 0.15). They provide reasonable estimates of
// structural overhead, not exact byte counts.

/// Layout constants for `std::collections::BTreeMap` / `BTreeSet`.
///
/// BTreeMap uses `B=6`, so nodes hold up to `2*B-1 = 11` entries. Leaf nodes store keys+values;
/// internal nodes add 12 edge pointers. ~32 bytes overhead per node (metadata + allocator header),
/// ~2/3 average fill (~7 entries/node, ~8 children for internal nodes).
mod btree {
    use std::mem::size_of;

    /// Maximum entries per node (`B=6` → `2*B-1 = 11`).
    pub const NODE_CAPACITY: usize = 11;
    /// Estimated average entries per node in a steady-state B-tree (~2/3 fill).
    pub const AVERAGE_FILL: usize = 7;
    /// Average children per internal node at ~2/3 fill.
    pub const AVG_FANOUT: usize = AVERAGE_FILL + 1;
    /// Per-node overhead: `(parent ptr + idx + len + padding) + allocator header`.
    pub const NODE_OVERHEAD: usize = 32;
    /// Additional per-node size for internal nodes: `[MaybeUninit<NonNull<LeafNode>>; CAPACITY + 1]`.
    pub const EDGE_ARRAY_SIZE: usize = (NODE_CAPACITY + 1) * size_of::<usize>();

    /// Estimate total BTree node count (leaves + internal) and how many are internal.
    pub fn node_counts(len: usize) -> (usize, usize) {
        let leaves = len.div_ceil(AVERAGE_FILL);
        let mut internal = 0;
        let mut children_at_level = leaves;
        while children_at_level > 1 {
            let parents = children_at_level.div_ceil(AVG_FANOUT);
            internal += parents;
            children_at_level = parents;
        }
        (leaves + internal, internal)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn btree_node_counts() {
            // 7 entries: 1 leaf, 0 internal
            assert_eq!(node_counts(7), (1, 0));
            // 12 entries: 2 leaves + 1 internal root
            let (total, internal) = node_counts(12);
            assert_eq!(total, 3);
            assert_eq!(internal, 1);
            // 0 entries edge case
            assert_eq!(node_counts(0), (0, 0));
        }
    }
}

/// Layout constants for [`HashMap`] / [`HashSet`] (hashbrown-backed since Rust 1.36).
///
/// `hashbrown` uses a 7/8 max load factor and 1-byte control tags per bucket.
///
/// The control array is padded by `Group::WIDTH` (4/8/16 depending on SIMD support); we use 16 as
/// an upper bound.
mod hashmap {
    /// Inverse of `hashbrown`'s max load factor (7/8), as a fraction: `buckets ~= (capacity * 8/7)`.
    pub const LOAD_FACTOR_INV_NUM: usize = 8;
    pub const LOAD_FACTOR_INV_DEN: usize = 7;
    /// Upper bound for SIMD group-width padding. In hashbrown 0.15, Group::WIDTH varies by target
    /// and implementation (4/8/16 bytes), so we use 16 as a conservative upper bound for
    /// control-byte padding overhead.
    pub const CONTROL_GROUP_PADDING: usize = 16;

    /// Calculate the number of buckets for a given `HashMap` capacity, based on hashbrown's growth
    /// strategy and load factor.
    pub fn buckets_for_capacity(cap: usize) -> usize {
        (cap * LOAD_FACTOR_INV_NUM).div_ceil(LOAD_FACTOR_INV_DEN)
    }
}

/// Approximate in-memory footprint, in bytes.
///
/// Split into [`heap_bytes()`](Self::heap_bytes) (children only) and
/// [`resident_bytes()`](Self::resident_bytes) (inline + heap) to avoid double-counting in nested
/// types — containers call `heap_bytes()` on children, only the outermost caller should use
/// `resident_bytes()`.
pub trait ResidentBytes: Sized {
    /// Total approximate memory footprint of this instance.
    ///
    /// Default implementation: [`size_of::<Self>()`](size_of) (inline size) +
    /// [`heap_bytes()`](Self::heap_bytes) (additional heap allocations).
    fn resident_bytes(&self) -> usize {
        // Note: if we ever need to support unsized types, we should switch to size_of_val(self)
        // here instead of size_of::<Self>() and remove the Sized trait bound.
        std::mem::size_of::<Self>() + self.heap_bytes()
    }

    /// Heap allocations only, beyond the inline size reported by [`size_of::<Self>()`](size_of).
    fn heap_bytes(&self) -> usize;
}

impl ResidentBytes for String {
    fn heap_bytes(&self) -> usize {
        self.capacity()
    }
}

impl<T: ResidentBytes> ResidentBytes for Vec<T> {
    fn heap_bytes(&self) -> usize {
        // Backing array: capacity slots (inline size per slot)
        let backing = self.capacity() * size_of::<T>();

        // Children's heap allocations
        let children: usize = self.iter().map(|v| v.heap_bytes()).sum();

        // Total heap
        backing + children
    }
}

impl<T: ResidentBytes> ResidentBytes for Box<T> {
    fn heap_bytes(&self) -> usize {
        // Box heap-allocates the pointee: its inline size + its own heap
        size_of::<T>() + (**self).heap_bytes()
    }
}

impl<T: ResidentBytes> ResidentBytes for Option<T> {
    fn heap_bytes(&self) -> usize {
        match self {
            // For Some, the T is inline in the Option; only count T's heap
            Some(v) => v.heap_bytes(),
            None => 0,
        }
    }
}

impl<T: ResidentBytes> ResidentBytes for Arc<T> {
    fn heap_bytes(&self) -> usize {
        // Counts the Arc allocation (header + pointee). Shared backing may be overcounted if
        // multiple Arc handles to the same allocation are reachable in one measured graph.
        ARC_OVERHEAD + size_of::<T>() + (**self).heap_bytes()
    }
}

impl<K: ResidentBytes, V: ResidentBytes> ResidentBytes for HashMap<K, V> {
    fn heap_bytes(&self) -> usize {
        let cap = self.capacity();
        if cap == 0 {
            // HashMap::new() does not allocate until first insert.
            return 0;
        }

        let buckets = hashmap::buckets_for_capacity(cap);
        let backing = buckets * size_of::<(K, V)>() + buckets + hashmap::CONTROL_GROUP_PADDING;

        // Children's heap allocations (only for occupied entries)
        let children: usize = self
            .iter()
            .map(|(k, v)| k.heap_bytes() + v.heap_bytes())
            .sum();

        backing + children
    }
}

impl<K: ResidentBytes, V: ResidentBytes> ResidentBytes for BTreeMap<K, V> {
    fn heap_bytes(&self) -> usize {
        if self.is_empty() {
            return 0; // Empty BTreeMaps do not allocate on the heap.
        }

        let (total_nodes, internal_nodes) = btree::node_counts(self.len());

        // Base node size (shared by leaf and internal): overhead + key/value arrays
        let leaf_size = btree::NODE_OVERHEAD
            + (btree::NODE_CAPACITY * size_of::<K>())
            + (btree::NODE_CAPACITY * size_of::<V>());
        // Internal nodes additionally carry an edge pointer array
        let structural = total_nodes * leaf_size + internal_nodes * btree::EDGE_ARRAY_SIZE;

        // Children's heap allocations (only for occupied entries)
        let children: usize = self
            .iter()
            .map(|(k, v)| k.heap_bytes() + v.heap_bytes())
            .sum();

        structural + children
    }
}

impl<T: ResidentBytes> ResidentBytes for BTreeSet<T> {
    fn heap_bytes(&self) -> usize {
        if self.is_empty() {
            return 0;
        }

        let (total_nodes, internal_nodes) = btree::node_counts(self.len());

        // BTreeSet is backed by BTreeMap<T, ()> — vals array is zero-size
        let leaf_size = btree::NODE_OVERHEAD + (btree::NODE_CAPACITY * size_of::<T>());
        let structural = total_nodes * leaf_size + internal_nodes * btree::EDGE_ARRAY_SIZE;
        let children: usize = self.iter().map(|v| v.heap_bytes()).sum();
        structural + children
    }
}

impl<T: ResidentBytes> ResidentBytes for HashSet<T> {
    fn heap_bytes(&self) -> usize {
        let cap = self.capacity();
        if cap == 0 {
            return 0;
        }

        let buckets = hashmap::buckets_for_capacity(cap);
        let backing = buckets * size_of::<T>() + buckets + hashmap::CONTROL_GROUP_PADDING;
        let children: usize = self.iter().map(|v| v.heap_bytes()).sum();
        backing + children
    }
}

impl<A: ResidentBytes, B: ResidentBytes> ResidentBytes for (A, B) {
    fn heap_bytes(&self) -> usize {
        self.0.heap_bytes() + self.1.heap_bytes()
    }
}

// Primitive types: no heap allocation (stack-only)

impl ResidentBytes for bool {
    fn heap_bytes(&self) -> usize {
        0
    }
}
impl ResidentBytes for u8 {
    fn heap_bytes(&self) -> usize {
        0
    }
}
impl ResidentBytes for u32 {
    fn heap_bytes(&self) -> usize {
        0
    }
}
impl ResidentBytes for u64 {
    fn heap_bytes(&self) -> usize {
        0
    }
}
impl ResidentBytes for u128 {
    fn heap_bytes(&self) -> usize {
        0
    }
}
impl ResidentBytes for i128 {
    fn heap_bytes(&self) -> usize {
        0
    }
}

impl ResidentBytes for Value {
    fn heap_bytes(&self) -> usize {
        match self {
            Value::Int(_) | Value::UInt(_) | Value::Bool(_) => 0,
            Value::Sequence(data) => data.heap_bytes(),
            Value::Principal(data) => data.heap_bytes(),
            Value::Tuple(data) => data.heap_bytes(),
            Value::Optional(data) => data.heap_bytes(),
            Value::Response(data) => data.heap_bytes(),
            Value::CallableContract(data) => data.heap_bytes(),
        }
    }
}

impl ResidentBytes for SequenceData {
    fn heap_bytes(&self) -> usize {
        match self {
            SequenceData::Buffer(buf) => buf.heap_bytes(),
            SequenceData::List(list) => list.heap_bytes(),
            SequenceData::String(char_type) => char_type.heap_bytes(),
        }
    }
}

impl ResidentBytes for BuffData {
    fn heap_bytes(&self) -> usize {
        self.data.heap_bytes()
    }
}

impl ResidentBytes for ListData {
    fn heap_bytes(&self) -> usize {
        self.data.heap_bytes() + self.type_signature.heap_bytes()
    }
}

impl ResidentBytes for CharType {
    fn heap_bytes(&self) -> usize {
        match self {
            CharType::ASCII(data) => data.heap_bytes(),
            CharType::UTF8(data) => data.heap_bytes(),
        }
    }
}

impl ResidentBytes for ASCIIData {
    fn heap_bytes(&self) -> usize {
        self.data.heap_bytes()
    }
}

impl ResidentBytes for UTF8Data {
    fn heap_bytes(&self) -> usize {
        // Vec<Vec<u8>>: outer vec backing + each inner vec's backing
        let outer = self.data.capacity() * size_of::<Vec<u8>>();
        let inner: usize = self.data.iter().map(|v| v.capacity()).sum();
        outer + inner
    }
}

impl ResidentBytes for TupleData {
    fn heap_bytes(&self) -> usize {
        self.type_signature.heap_bytes() + self.data_map.heap_bytes()
    }
}

impl ResidentBytes for OptionalData {
    fn heap_bytes(&self) -> usize {
        self.data.heap_bytes()
    }
}

impl ResidentBytes for ResponseData {
    fn heap_bytes(&self) -> usize {
        self.data.heap_bytes()
    }
}

impl ResidentBytes for CallableData {
    fn heap_bytes(&self) -> usize {
        self.contract_identifier.heap_bytes() + self.trait_identifier.heap_bytes()
    }
}

impl ResidentBytes for PrincipalData {
    fn heap_bytes(&self) -> usize {
        match self {
            PrincipalData::Standard(data) => data.heap_bytes(),
            PrincipalData::Contract(data) => data.heap_bytes(),
        }
    }
}

impl ResidentBytes for StandardPrincipalData {
    fn heap_bytes(&self) -> usize {
        0 // Fixed-size: u8 + [u8; 20], no heap allocation
    }
}

impl ResidentBytes for QualifiedContractIdentifier {
    fn heap_bytes(&self) -> usize {
        self.issuer.heap_bytes() + self.name.heap_bytes()
    }
}

impl ResidentBytes for ClarityName {
    fn heap_bytes(&self) -> usize {
        self.heap_capacity()
    }
}

impl ResidentBytes for ContractName {
    fn heap_bytes(&self) -> usize {
        self.heap_capacity()
    }
}

impl ResidentBytes for TraitIdentifier {
    fn heap_bytes(&self) -> usize {
        self.name.heap_bytes() + self.contract_identifier.heap_bytes()
    }
}

impl ResidentBytes for FunctionIdentifier {
    fn heap_bytes(&self) -> usize {
        self.heap_capacity()
    }
}

impl ResidentBytes for TypeSignature {
    fn heap_bytes(&self) -> usize {
        match self {
            TypeSignature::NoType
            | TypeSignature::IntType
            | TypeSignature::UIntType
            | TypeSignature::BoolType
            | TypeSignature::PrincipalType => 0,
            TypeSignature::SequenceType(subtype) => subtype.heap_bytes(),
            TypeSignature::TupleType(tuple_sig) => tuple_sig.heap_bytes(),
            TypeSignature::OptionalType(inner) => inner.heap_bytes(),
            TypeSignature::ResponseType(inner) => inner.heap_bytes(),
            TypeSignature::CallableType(subtype) => subtype.heap_bytes(),
            TypeSignature::ListUnionType(set) => set.heap_bytes(),
            TypeSignature::TraitReferenceType(trait_id) => trait_id.heap_bytes(),
        }
    }
}

impl ResidentBytes for TupleTypeSignature {
    fn heap_bytes(&self) -> usize {
        // TupleTypeSignature wraps Arc<BTreeMap<ClarityName, TypeSignature>>. get_type_map()
        // returns &BTreeMap — count Arc overhead + map header + contents.
        let map_header = size_of::<BTreeMap<ClarityName, TypeSignature>>();
        ARC_OVERHEAD + map_header + self.get_type_map().heap_bytes()
    }
}

impl ResidentBytes for SequenceSubtype {
    fn heap_bytes(&self) -> usize {
        match self {
            SequenceSubtype::BufferType(len) => len.heap_bytes(),
            SequenceSubtype::ListType(list) => list.heap_bytes(),
            SequenceSubtype::StringType(string) => string.heap_bytes(),
        }
    }
}

impl ResidentBytes for ListTypeData {
    fn heap_bytes(&self) -> usize {
        // max_len: u32 (no heap), entry_type: Box<TypeSignature>
        size_of::<TypeSignature>() + self.get_list_item_type().heap_bytes()
    }
}

impl ResidentBytes for StringSubtype {
    fn heap_bytes(&self) -> usize {
        0 // Both variants (ASCII, UTF8) contain only u32 newtypes
    }
}

impl ResidentBytes for BufferLength {
    fn heap_bytes(&self) -> usize {
        0 // u32 newtype
    }
}

impl ResidentBytes for StringUTF8Length {
    fn heap_bytes(&self) -> usize {
        0 // u32 newtype
    }
}

impl ResidentBytes for CallableSubtype {
    fn heap_bytes(&self) -> usize {
        match self {
            CallableSubtype::Principal(id) => id.heap_bytes(),
            CallableSubtype::Trait(trait_id) => trait_id.heap_bytes(),
        }
    }
}

#[cfg(feature = "developer-mode")]
impl ResidentBytes for Span {
    fn heap_bytes(&self) -> usize {
        0 // 4 × u32, all inline
    }
}

impl ResidentBytes for SymbolicExpression {
    fn heap_bytes(&self) -> usize {
        #[allow(unused_mut)]
        let mut total = self.expr.heap_bytes();
        // id is u64 — no heap allocation

        #[cfg(feature = "developer-mode")]
        {
            // span is inline (no heap), but pre_comments, end_line_comment, and
            // post_comments have heap allocations via Vec/String.
            total += self.pre_comments.heap_bytes();
            total += self.end_line_comment.heap_bytes();
            total += self.post_comments.heap_bytes();
        }

        total
    }
}

impl ResidentBytes for SymbolicExpressionType {
    fn heap_bytes(&self) -> usize {
        match self {
            SymbolicExpressionType::AtomValue(value)
            | SymbolicExpressionType::LiteralValue(value) => value.heap_bytes(),
            SymbolicExpressionType::Atom(name) => name.heap_bytes(),
            SymbolicExpressionType::List(exprs) => exprs.heap_bytes(),
            SymbolicExpressionType::Field(trait_id) => trait_id.heap_bytes(),
            SymbolicExpressionType::TraitReference(name, defn) => {
                name.heap_bytes() + defn.heap_bytes()
            }
        }
    }
}

impl ResidentBytes for TraitDefinition {
    fn heap_bytes(&self) -> usize {
        match self {
            TraitDefinition::Defined(id) | TraitDefinition::Imported(id) => id.heap_bytes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod primitives {
        use super::*;

        #[test]
        fn primitive_heap_bytes_zero() {
            assert_eq!(true.heap_bytes(), 0);
            assert_eq!(0u8.heap_bytes(), 0);
            assert_eq!(0u32.heap_bytes(), 0);
            assert_eq!(0u64.heap_bytes(), 0);
            assert_eq!(0u128.heap_bytes(), 0);
            assert_eq!(0i128.heap_bytes(), 0);
        }

        #[test]
        fn u64_resident_bytes() {
            let v: u64 = 42;
            assert_eq!(v.resident_bytes(), 8);
            assert_eq!(v.heap_bytes(), 0);
        }
    }

    mod std_containers {
        use super::*;

        const HASHMAP_CAPACITY_TRANSITIONS: &[(usize, usize, usize)] = &[
            (0, 0, 0),
            (1, 3, 4),
            (4, 7, 8),
            (8, 14, 16),
            (15, 28, 32),
            (29, 56, 64),
            (57, 112, 128),
            (113, 224, 256),
            (225, 448, 512),
        ];

        #[test]
        fn string() {
            let s = String::from("hello world");
            assert!(s.resident_bytes() >= size_of::<String>() + 11);
            assert!(s.heap_bytes() >= 11);
        }

        #[test]
        fn vec() {
            let v: Vec<u64> = vec![1, 2, 3, 4, 5];
            assert!(v.heap_bytes() >= 40);
            assert!(v.resident_bytes() >= size_of::<Vec<u64>>() + 40);
        }

        #[test]
        fn boxed() {
            let b = Box::new(String::from("boxed"));
            assert!(b.heap_bytes() >= size_of::<String>() + 5);
        }

        #[test]
        fn option_none() {
            let opt: Option<Box<Value>> = None;
            assert_eq!(opt.heap_bytes(), 0);
            assert!(opt.resident_bytes() >= size_of::<Option<Box<Value>>>());
        }

        #[test]
        fn option_some() {
            let opt: Option<Box<Value>> = Some(Box::new(Value::Int(42)));
            assert!(opt.heap_bytes() >= size_of::<Value>());
        }

        #[test]
        fn arc() {
            let a = Arc::new(String::from("hello"));
            assert!(a.heap_bytes() >= ARC_OVERHEAD + size_of::<String>() + 5);
        }

        #[test]
        fn tuple_pair() {
            let t = ("hello".to_string(), 42u64);
            assert!(t.heap_bytes() >= 5);
            assert_eq!(42u64.heap_bytes(), 0);
        }

        #[test]
        fn hashmap() {
            let mut m: HashMap<String, u64> = HashMap::new();
            m.insert("key1".into(), 1);
            m.insert("key2".into(), 2);

            let cap = m.capacity();
            let buckets = hashmap::buckets_for_capacity(cap);
            // Structural lower bound: buckets * entry_size + control bytes
            let min_structural = buckets * size_of::<(String, u64)>() + buckets;
            // Child heap: each key String has at least 4 bytes of heap
            let min_child_heap = 2 * 4;
            assert!(
                m.heap_bytes() >= min_structural + min_child_heap,
                "heap_bytes {} < expected minimum {}",
                m.heap_bytes(),
                min_structural + min_child_heap,
            );
        }

        #[test]
        fn hashmap_empty() {
            let m: HashMap<String, u64> = HashMap::new();
            assert_eq!(m.heap_bytes(), 0);
        }

        #[test]
        fn hashmap_with_capacity_progression_matches_expected_boundaries() {
            let mut observed = Vec::new();
            let mut previous = None;

            for requested in 0usize..=256 {
                let map = HashMap::<u64, u64>::with_capacity(requested);
                let cap = map.capacity();
                let buckets = if cap == 0 {
                    0
                } else {
                    hashmap::buckets_for_capacity(cap)
                };

                if previous != Some((cap, buckets)) {
                    observed.push((requested, cap, buckets));
                    previous = Some((cap, buckets));
                }
            }

            assert_eq!(observed.as_slice(), HASHMAP_CAPACITY_TRANSITIONS);
        }

        #[test]
        fn hashmap_capacity_boundaries_match_bucket_accounting() {
            for (_, expected_cap, _) in HASHMAP_CAPACITY_TRANSITIONS.iter().copied().skip(1) {
                let mut map = HashMap::with_capacity(expected_cap);

                assert_eq!(
                    map.capacity(),
                    expected_cap,
                    "HashMap::with_capacity({expected_cap}) returned capacity {cap}",
                    cap = map.capacity(),
                );

                for entry in 0..expected_cap {
                    map.insert(entry as u64, entry as u64);
                    assert_eq!(
                        map.capacity(),
                        expected_cap,
                        "HashMap grew before reaching capacity {expected_cap}; capacity is {cap} after {inserts} inserts",
                        cap = map.capacity(),
                        inserts = entry + 1,
                    );
                }

                map.insert(expected_cap as u64, expected_cap as u64);
                assert!(
                    map.capacity() > expected_cap,
                    "HashMap did not grow after exceeding capacity {expected_cap}; capacity remained {cap}",
                    cap = map.capacity(),
                );
            }
        }

        #[test]
        fn hashset() {
            let mut s: HashSet<u64> = HashSet::new();
            for i in 0..10 {
                s.insert(i);
            }

            let cap = s.capacity();
            let buckets = hashmap::buckets_for_capacity(cap);
            let min_structural = buckets * size_of::<u64>() + buckets;
            assert!(
                s.heap_bytes() >= min_structural,
                "heap_bytes {} < expected minimum {}",
                s.heap_bytes(),
                min_structural,
            );
        }

        #[test]
        fn hashset_empty() {
            let s: HashSet<String> = HashSet::new();
            assert_eq!(s.heap_bytes(), 0);
        }

        #[test]
        fn btreemap() {
            let mut m = BTreeMap::new();
            for i in 0..20u64 {
                m.insert(i, i);
            }

            let (total_nodes, internal_nodes) = btree::node_counts(20);
            let leaf_size = btree::NODE_OVERHEAD
                + btree::NODE_CAPACITY * size_of::<u64>()
                + btree::NODE_CAPACITY * size_of::<u64>();
            let min_structural = total_nodes * leaf_size + internal_nodes * btree::EDGE_ARRAY_SIZE;
            assert!(
                m.heap_bytes() >= min_structural,
                "heap_bytes {} < expected minimum {}",
                m.heap_bytes(),
                min_structural,
            );
            // Must account for internal nodes (20 entries > single-leaf capacity of 11)
            assert!(internal_nodes >= 1);
        }

        #[test]
        fn btreemap_empty() {
            let m: BTreeMap<String, u64> = BTreeMap::new();
            assert_eq!(m.heap_bytes(), 0);
        }

        #[test]
        fn btreeset() {
            let s: BTreeSet<u64> = (0..15).collect();

            let (total_nodes, _) = btree::node_counts(15);
            let leaf_size = btree::NODE_OVERHEAD + btree::NODE_CAPACITY * size_of::<u64>();
            assert!(
                s.heap_bytes() >= total_nodes * leaf_size,
                "heap_bytes {} < expected minimum {}",
                s.heap_bytes(),
                total_nodes * leaf_size,
            );
        }

        #[test]
        fn btreeset_empty() {
            let s: BTreeSet<u64> = BTreeSet::new();
            assert_eq!(s.heap_bytes(), 0);
        }
    }

    mod clarity_values {
        use super::*;

        #[test]
        fn int_uint_bool_no_heap() {
            assert_eq!(Value::Int(42).heap_bytes(), 0);
            assert_eq!(Value::UInt(42).heap_bytes(), 0);
            assert_eq!(Value::Bool(true).heap_bytes(), 0);
            let int_size = Value::Int(42).resident_bytes();
            assert!(
                int_size >= size_of::<Value>(),
                "Int resident_bytes ({int_size}) should be >= size_of::<Value>()"
            );
        }

        #[test]
        fn sequence_buffer() {
            let buf = BuffData {
                data: vec![0u8; 100],
            };
            assert!(buf.heap_bytes() >= 100);
        }

        #[test]
        fn sequence_ascii() {
            let v = Value::Sequence(SequenceData::String(CharType::ASCII(ASCIIData {
                data: vec![b'a', b'b', b'c'],
            })));
            assert!(v.heap_bytes() >= 3);
        }

        #[test]
        fn sequence_utf8() {
            let v = Value::Sequence(SequenceData::String(CharType::UTF8(UTF8Data {
                data: vec![vec![0xC3, 0xA9], vec![0xC3, 0xB1]],
            })));
            assert!(v.heap_bytes() > 0);
        }

        #[test]
        fn list_data() {
            let list = ListData {
                data: vec![Value::Int(1), Value::Int(2), Value::Int(3)],
                type_signature: ListTypeData::new_list(TypeSignature::IntType, 10).unwrap(),
            };
            assert!(list.heap_bytes() > 0);
        }

        #[test]
        fn principal_standard() {
            let v = Value::Principal(PrincipalData::Standard(StandardPrincipalData::transient()));
            assert_eq!(v.heap_bytes(), 0);
        }

        #[test]
        fn principal_contract() {
            let v = Value::Principal(PrincipalData::Contract(
                QualifiedContractIdentifier::transient(),
            ));
            assert!(v.heap_bytes() > 0);
        }

        #[test]
        fn tuple() {
            let tuple = TupleData::from_data(vec![
                (
                    ClarityName::try_from("a".to_string()).unwrap(),
                    Value::Int(1),
                ),
                (
                    ClarityName::try_from("b".to_string()).unwrap(),
                    Value::Bool(true),
                ),
            ])
            .unwrap();
            assert!(Value::Tuple(tuple).heap_bytes() > 0);
        }

        #[test]
        fn optional() {
            let opt = OptionalData {
                data: Some(Box::new(Value::Int(42))),
            };
            assert!(opt.heap_bytes() > 0);
        }

        #[test]
        fn response() {
            let ok = Value::Response(ResponseData {
                committed: true,
                data: Box::new(Value::Int(42)),
            });
            let err = Value::Response(ResponseData {
                committed: false,
                data: Box::new(Value::Bool(false)),
            });
            assert!(ok.heap_bytes() >= size_of::<Value>());
            assert!(err.heap_bytes() >= size_of::<Value>());
        }

        #[test]
        fn callable_contract() {
            let v = Value::CallableContract(CallableData {
                contract_identifier: QualifiedContractIdentifier::transient(),
                trait_identifier: None,
            });
            assert!(v.heap_bytes() > 0);
        }
    }

    mod clarity_identifiers {
        use super::*;

        #[test]
        fn clarity_name() {
            let name = ClarityName::try_from("my-variable".to_string()).unwrap();
            assert!(name.heap_bytes() >= 11);
            assert!(name.resident_bytes() > name.heap_bytes());
        }

        #[test]
        fn contract_name() {
            let name = ContractName::try_from("my-contract".to_string()).unwrap();
            assert!(name.heap_bytes() >= 11);
        }

        #[test]
        fn standard_principal_data() {
            let p = StandardPrincipalData::transient();
            assert_eq!(p.heap_bytes(), 0);
        }

        #[test]
        fn qualified_contract_identifier() {
            let id = QualifiedContractIdentifier::transient();
            assert!(id.heap_bytes() > 0);
        }

        #[test]
        fn trait_identifier() {
            let id = TraitIdentifier::new(
                StandardPrincipalData::transient(),
                ContractName::try_from("contract".to_string()).unwrap(),
                ClarityName::try_from("my-trait".to_string()).unwrap(),
            );
            assert!(id.heap_bytes() > 0);
        }

        #[test]
        fn function_identifier() {
            let fid = FunctionIdentifier::new_native_function("map");
            assert!(fid.heap_bytes() > 0);
        }
    }

    mod type_signatures {
        use super::*;

        #[test]
        fn scalar_no_heap() {
            assert_eq!(TypeSignature::IntType.heap_bytes(), 0);
            assert_eq!(TypeSignature::UIntType.heap_bytes(), 0);
            assert_eq!(TypeSignature::BoolType.heap_bytes(), 0);
            assert_eq!(TypeSignature::PrincipalType.heap_bytes(), 0);
            assert_eq!(TypeSignature::NoType.heap_bytes(), 0);
            assert!(TypeSignature::IntType.resident_bytes() > 0);
        }

        #[test]
        fn optional() {
            let sig = TypeSignature::OptionalType(Box::new(TypeSignature::IntType));
            assert!(sig.heap_bytes() > 0);
            assert!(sig.resident_bytes() > sig.heap_bytes());
        }

        #[test]
        fn response() {
            let sig = TypeSignature::ResponseType(Box::new((
                TypeSignature::IntType,
                TypeSignature::BoolType,
            )));
            assert!(sig.heap_bytes() > 0);
        }

        #[test]
        fn sequence() {
            let sig = TypeSignature::SequenceType(SequenceSubtype::BufferType(
                BufferLength::try_from(64u32).unwrap(),
            ));
            assert_eq!(sig.heap_bytes(), 0);
        }

        #[test]
        fn tuple() {
            let sig = TypeSignature::TupleType(
                TupleTypeSignature::try_from(vec![(
                    ClarityName::try_from("f".to_string()).unwrap(),
                    TypeSignature::IntType,
                )])
                .unwrap(),
            );
            assert!(sig.heap_bytes() > 0);
        }

        #[test]
        fn callable() {
            let sig = TypeSignature::CallableType(CallableSubtype::Principal(
                QualifiedContractIdentifier::transient(),
            ));
            assert!(sig.heap_bytes() > 0);
        }

        #[test]
        fn list_union() {
            let mut set = BTreeSet::new();
            set.insert(CallableSubtype::Principal(
                QualifiedContractIdentifier::transient(),
            ));
            let sig = TypeSignature::ListUnionType(set);
            assert!(sig.heap_bytes() > 0);
        }

        #[test]
        fn trait_reference() {
            let id = TraitIdentifier::new(
                StandardPrincipalData::transient(),
                ContractName::try_from("c".to_string()).unwrap(),
                ClarityName::try_from("t".to_string()).unwrap(),
            );
            let sig = TypeSignature::TraitReferenceType(id);
            assert!(sig.heap_bytes() > 0);
        }

        #[test]
        fn tuple_type_signature() {
            let sig = TupleTypeSignature::try_from(vec![
                (
                    ClarityName::try_from("x".to_string()).unwrap(),
                    TypeSignature::IntType,
                ),
                (
                    ClarityName::try_from("y".to_string()).unwrap(),
                    TypeSignature::BoolType,
                ),
            ])
            .unwrap();
            assert!(sig.heap_bytes() > ARC_OVERHEAD);
        }

        #[test]
        fn sequence_subtype() {
            assert_eq!(
                SequenceSubtype::BufferType(BufferLength::try_from(32u32).unwrap()).heap_bytes(),
                0,
            );
            let list = SequenceSubtype::ListType(
                ListTypeData::new_list(TypeSignature::IntType, 5).unwrap(),
            );
            assert!(list.heap_bytes() > 0);
            assert_eq!(
                SequenceSubtype::StringType(StringSubtype::ASCII(
                    BufferLength::try_from(10u32).unwrap()
                ))
                .heap_bytes(),
                0,
            );
        }

        #[test]
        fn string_subtype_no_heap() {
            assert_eq!(
                StringSubtype::ASCII(BufferLength::try_from(10u32).unwrap()).heap_bytes(),
                0
            );
            assert_eq!(
                StringSubtype::UTF8(StringUTF8Length::try_from(10u32).unwrap()).heap_bytes(),
                0
            );
        }

        #[test]
        fn buffer_length_no_heap() {
            assert_eq!(BufferLength::try_from(100u32).unwrap().heap_bytes(), 0);
        }

        #[test]
        fn string_utf8_length_no_heap() {
            assert_eq!(StringUTF8Length::try_from(100u32).unwrap().heap_bytes(), 0);
        }

        #[test]
        fn callable_subtype_principal() {
            let sub = CallableSubtype::Principal(QualifiedContractIdentifier::transient());
            assert!(sub.heap_bytes() > 0);
        }

        #[test]
        fn callable_subtype_trait() {
            let id = TraitIdentifier::new(
                StandardPrincipalData::transient(),
                ContractName::try_from("c".to_string()).unwrap(),
                ClarityName::try_from("t".to_string()).unwrap(),
            );
            assert!(CallableSubtype::Trait(id).heap_bytes() > 0);
        }
    }

    mod symbolic_expressions {
        use super::*;

        #[test]
        fn atom() {
            let inner = SymbolicExpression::atom(ClarityName::try_from("x".to_string()).unwrap());
            let list = SymbolicExpression::list(vec![inner.clone(), inner.clone(), inner]);
            assert!(list.heap_bytes() > 0);
            assert!(list.resident_bytes() > list.heap_bytes());
        }

        #[test]
        fn atom_value() {
            let expr = SymbolicExpression::atom_value(Value::Int(1));
            assert_eq!(expr.heap_bytes(), 0);
        }

        #[test]
        fn literal_value() {
            let expr = SymbolicExpression::literal_value(Value::Bool(true));
            assert_eq!(expr.heap_bytes(), 0);
        }

        #[test]
        fn field() {
            let id = TraitIdentifier::new(
                StandardPrincipalData::transient(),
                ContractName::try_from("c".to_string()).unwrap(),
                ClarityName::try_from("f".to_string()).unwrap(),
            );
            let expr = SymbolicExpression::field(id);
            assert!(expr.heap_bytes() > 0);
        }

        #[test]
        fn trait_reference() {
            let id = TraitIdentifier::new(
                StandardPrincipalData::transient(),
                ContractName::try_from("c".to_string()).unwrap(),
                ClarityName::try_from("t".to_string()).unwrap(),
            );
            let expr = SymbolicExpression::trait_reference(
                ClarityName::try_from("name".to_string()).unwrap(),
                TraitDefinition::Defined(id),
            );
            assert!(expr.heap_bytes() > 0);
        }

        #[test]
        fn trait_definition() {
            let id = TraitIdentifier::new(
                StandardPrincipalData::transient(),
                ContractName::try_from("c".to_string()).unwrap(),
                ClarityName::try_from("t".to_string()).unwrap(),
            );
            let defined = TraitDefinition::Defined(id.clone());
            let imported = TraitDefinition::Imported(id);
            assert!(defined.heap_bytes() > 0);
            assert_eq!(defined.heap_bytes(), imported.heap_bytes());
        }
    }

    #[cfg(feature = "developer-mode")]
    mod developer_mode {
        use super::*;

        #[test]
        fn symbolic_expression_comment_fields() {
            let mut expr =
                SymbolicExpression::atom(ClarityName::try_from("x".to_string()).unwrap());
            expr.pre_comments = vec![
                ("comment1".to_string(), Span::zero()),
                ("comment2".to_string(), Span::zero()),
            ];
            expr.end_line_comment = Some("end comment".to_string());
            expr.post_comments = vec![("post".to_string(), Span::zero())];

            let with_comments = expr.heap_bytes();
            let plain = SymbolicExpression::atom(ClarityName::try_from("x".to_string()).unwrap());
            assert!(with_comments > plain.heap_bytes());
        }

        #[test]
        fn span_no_heap() {
            let s = Span::zero();
            assert_eq!(s.heap_bytes(), 0);
        }
    }
}
