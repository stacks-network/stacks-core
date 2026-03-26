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
/// Rust's BTreeMap uses `B=6` (hardcoded). Each node holds up to `CAPACITY = 2*B-1 = 11` entries:
/// * **LeafNode** layout: parent ptr (8) + parent_idx (2) + len (2) + padding (~4) + keys:
///   `[MaybeUninit<K>; 11]` + vals: `[MaybeUninit<V>; 11]`.
/// * **InternalNode** layout: LeafNode fields + edges: `[MaybeUninit<NonNull<LeafNode>>; 12]`.
/// * Allocator header adds ~16 bytes per node.
/// * Total per-node overhead (metadata + allocator): ~32 bytes. Average fill factor ~2/3 → ~7
///   entries per node. Internal nodes at average fill have ~8 children.
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
}

/// Layout constants for `std::collections::HashMap` / `HashSet`.
///
/// std's HashMap has been backed by hashbrown since Rust 1.36. These constants reflect hashbrown
/// internals that are not exposed through any std API.
///
/// * `hashbrown` targets a 7/8 max load factor: it allocates more buckets than `capacity()`
///   reports. `capacity()` returns the number of insertions before reallocation, not the bucket
///   count. Actual buckets ~= `ceil(capacity * LOAD_FACTOR_INV_NUM / LOAD_FACTOR_INV_DEN)`.
/// * Each bucket has a 1-byte control tag. The control array is padded by `Group::WIDTH` bytes (16
///   on platforms with 128-bit SIMD, 8 otherwise) for SIMD probing at the end of the table.
/// * `hashbrown` also aligns `buckets * entry_size` up to `ctrl_align` (max of entry alignment and
///   Group alignment) before placing control bytes. We don't model this padding — for the types
///   used in Clarity, bucket counts are powers of 2 and entry alignments are <=8, so the gap is
///   typically zero.
mod hashmap {
    /// Inverse of hashbrown's max load factor (7/8), as a fraction: `buckets ~= (capacity * 8/7)`.
    pub const LOAD_FACTOR_INV_NUM: usize = 8;
    pub const LOAD_FACTOR_INV_DEN: usize = 7;
    /// Conservative upper bound for SIMD group width padding appended to the control byte array.
    /// hashbrown's actual `Group::WIDTH` varies by target (4, 8, or 16 bytes); 16 is the max
    /// (SSE2 path on x86_64) and overestimates by at most 12 bytes on other platforms.
    pub const CONTROL_GROUP_PADDING: usize = 16;

    // NOTE:
}

/// Reports the approximate in-memory footprint of an instance, in bytes.
///
/// See module-level documentation for the two-method design.
pub trait ResidentBytes {
    /// Total in-memory footprint: inline [`size_of()`](size_of) + heap allocations.
    ///
    /// This is the method callers should use. It has a provided default implementation;
    /// implementors only need to implement [`heap_bytes()`](Self::heap_bytes).
    fn resident_bytes(&self) -> usize {
        std::mem::size_of_val(self) + self.heap_bytes()
    }

    /// Heap allocations only, beyond the inline [`size_of()`](size_of).
    ///
    /// Container types call this on their children to avoid double-counting inline sizes that are
    /// already part of the container's backing allocation.
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
            // For Some, the T is inline in the Option — only count T's heap
            Some(v) => v.heap_bytes(),
            None => 0,
        }
    }
}

impl<T: ResidentBytes> ResidentBytes for Arc<T> {
    fn heap_bytes(&self) -> usize {
        // Arc heap-allocates: header (strong + weak counts, ~16 bytes) + T inline + T's heap
        16 + size_of::<T>() + (**self).heap_bytes()
    }
}

impl<K: ResidentBytes, V: ResidentBytes> ResidentBytes for HashMap<K, V> {
    fn heap_bytes(&self) -> usize {
        let cap = self.capacity();
        if cap == 0 {
            // HashMap::new() does not allocate until first insert.
            return 0;
        }

        let buckets =
            (cap * hashmap::LOAD_FACTOR_INV_NUM).div_ceil(hashmap::LOAD_FACTOR_INV_DEN);
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

        let buckets =
            (cap * hashmap::LOAD_FACTOR_INV_NUM).div_ceil(hashmap::LOAD_FACTOR_INV_DEN);
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

    #[test]
    fn test_primitive_values_include_inline_size() {
        // resident_bytes() includes size_of::<Value>() even for scalar variants
        let int_size = Value::Int(42).resident_bytes();
        assert!(
            int_size >= size_of::<Value>(),
            "Int resident_bytes ({int_size}) should be >= size_of::<Value>()"
        );
        assert_eq!(Value::Int(42).heap_bytes(), 0);
    }

    #[test]
    fn test_u64_resident_bytes() {
        let v: u64 = 42;
        assert_eq!(v.resident_bytes(), 8);
        assert_eq!(v.heap_bytes(), 0);
    }

    #[test]
    fn test_string_resident_bytes() {
        let s = String::from("hello world");
        assert!(s.resident_bytes() >= size_of::<String>() + 11);
        assert!(s.heap_bytes() >= 11);
    }

    #[test]
    fn test_vec_resident_bytes() {
        let v: Vec<u64> = vec![1, 2, 3, 4, 5];
        // heap: capacity * size_of::<u64>() = 5 * 8 = 40 bytes (no child heap)
        assert!(v.heap_bytes() >= 40);
        // total: size_of::<Vec<u64>>() + heap
        assert!(v.resident_bytes() >= size_of::<Vec<u64>>() + 40);
    }

    #[test]
    fn test_hashmap_resident_bytes() {
        let mut m: HashMap<String, u64> = HashMap::new();
        m.insert("key1".into(), 1);
        m.insert("key2".into(), 2);
        // Should include: HashMap header + backing array + key string heaps
        assert!(m.resident_bytes() > size_of::<HashMap<String, u64>>());
    }

    #[test]
    fn test_optional_none() {
        let opt: Option<Box<Value>> = None;
        assert_eq!(opt.heap_bytes(), 0);
        // resident_bytes includes size_of::<Option<Box<Value>>>()
        assert!(opt.resident_bytes() >= size_of::<Option<Box<Value>>>());
    }

    #[test]
    fn test_optional_some_counts_content() {
        let opt = OptionalData {
            data: Some(Box::new(Value::Int(42))),
        };
        // heap: Box (size_of::<Value>() + 0 heap)
        assert!(opt.heap_bytes() > 0);
    }

    #[test]
    fn test_clarity_name_includes_inline_and_heap() {
        let name = ClarityName::try_from("my-variable".to_string()).unwrap();
        // heap: String buffer capacity
        assert!(name.heap_bytes() >= 11);
        // total: size_of::<ClarityName>() + heap
        assert!(name.resident_bytes() > name.heap_bytes());
    }

    #[test]
    fn test_sequence_buffer_counts_vec() {
        let buf = BuffData {
            data: vec![0u8; 100],
        };
        assert!(buf.heap_bytes() >= 100);
    }

    #[test]
    fn test_list_data_recursive() {
        let list = ListData {
            data: vec![Value::Int(1), Value::Int(2), Value::Int(3)],
            type_signature: ListTypeData::new_list(TypeSignature::IntType, 10).unwrap(),
        };
        // heap: Vec backing (3 * size_of::<Value>()) + ListTypeData (Box<TypeSignature>)
        assert!(list.heap_bytes() > 0);
    }

    #[test]
    fn test_symbolic_expression_list_recursive() {
        let inner = SymbolicExpression::atom(ClarityName::try_from("x".to_string()).unwrap());
        let list = SymbolicExpression::list(vec![inner.clone(), inner.clone(), inner]);
        // Should recursively count the Vec backing + each child's ClarityName heap
        assert!(list.heap_bytes() > 0);
        assert!(list.resident_bytes() > list.heap_bytes());
    }

    #[test]
    fn test_type_signature_scalar_heap_is_zero() {
        // Heap bytes for scalar types should be zero
        assert_eq!(TypeSignature::IntType.heap_bytes(), 0);
        assert_eq!(TypeSignature::BoolType.heap_bytes(), 0);
        // But resident_bytes includes size_of::<TypeSignature>()
        assert!(TypeSignature::IntType.resident_bytes() > 0);
    }

    #[test]
    fn test_type_signature_optional_recursive() {
        let sig = TypeSignature::OptionalType(Box::new(TypeSignature::IntType));
        // heap: Box (size_of::<TypeSignature>() + 0)
        assert!(sig.heap_bytes() > 0);
        assert!(sig.resident_bytes() > sig.heap_bytes());
    }
}
