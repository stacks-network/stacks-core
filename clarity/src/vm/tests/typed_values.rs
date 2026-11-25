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

//! Property tests over generated types and values of those types: consensus serialization
//! round-trips and size bounds, type admission, and least-supertype laws.

use clarity_types::Value;
use clarity_types::types::TypeSignature;
use pinny::tag;
use proptest::prelude::*;
use stacks_common::types::StacksEpochId;

use crate::vm::tests::proptesting::strategies::types::type_signature_strategy;
use crate::vm::tests::proptesting::strategies::values::{
    typed_value_strategy, value_of_type_strategy,
};

const EPOCH: StacksEpochId = StacksEpochId::latest();

fn typed_value_pair() -> impl Strategy<Value = (TypeSignature, Value, Value)> {
    type_signature_strategy().prop_flat_map(|ty| {
        (
            Just(ty.clone()),
            value_of_type_strategy(ty.clone()),
            value_of_type_strategy(ty),
        )
    })
}

proptest! {
    #[tag(t_prop)]
    #[test]
    fn typed_value_round_trips_with_expected_type((ty, value) in typed_value_strategy()) {
        let bytes = value.serialize_to_vec().unwrap();
        prop_assert_eq!(
            Value::try_deserialize_bytes_at_epoch(&bytes, &ty, &EPOCH).unwrap(),
            value.clone()
        );
        prop_assert_eq!(Value::try_deserialize_bytes(&bytes, &ty, false).unwrap(), value);
    }

    #[tag(t_prop)]
    #[test]
    fn untyped_round_trip_reserializes_identically((_ty, value) in typed_value_strategy()) {
        let bytes = value.serialize_to_vec().unwrap();
        let decoded = Value::deserialize_read(&mut bytes.as_slice(), None, false).unwrap();
        prop_assert_eq!(&decoded, &value);
        prop_assert_eq!(decoded.serialize_to_vec().unwrap(), bytes);
    }

    #[tag(t_prop)]
    #[test]
    fn serialized_size_is_exact_and_within_type_bound((ty, value) in typed_value_strategy()) {
        let len = u32::try_from(value.serialize_to_vec().unwrap().len()).unwrap();
        prop_assert_eq!(value.serialized_size().unwrap(), len);
        prop_assert!(len <= ty.max_serialized_size().unwrap());
    }

    #[tag(t_prop)]
    #[test]
    fn type_admits_its_values((ty, value) in typed_value_strategy()) {
        prop_assert!(ty.admits(&EPOCH, &value).unwrap());
        let value_type = TypeSignature::type_of(&value).unwrap();
        prop_assert!(ty.admits_type(&EPOCH, &value_type).unwrap());
    }

    #[tag(t_prop)]
    #[test]
    fn least_supertype_of_two_values_admits_both((ty, a, b) in typed_value_pair()) {
        let a_type = TypeSignature::type_of(&a).unwrap();
        let b_type = TypeSignature::type_of(&b).unwrap();
        let supertype = TypeSignature::least_supertype(&EPOCH, &a_type, &b_type).unwrap();
        prop_assert!(supertype.admits(&EPOCH, &a).unwrap());
        prop_assert!(supertype.admits(&EPOCH, &b).unwrap());
        // Two values of `ty` never need a type wider than `ty`.
        prop_assert!(ty.admits_type(&EPOCH, &supertype).unwrap());
    }

    #[tag(t_prop)]
    #[test]
    fn least_supertype_is_commutative((_ty, a, b) in typed_value_pair()) {
        let a = TypeSignature::type_of(&a).unwrap();
        let b = TypeSignature::type_of(&b).unwrap();
        prop_assert_eq!(
            TypeSignature::least_supertype(&EPOCH, &a, &b).unwrap(),
            TypeSignature::least_supertype(&EPOCH, &b, &a).unwrap()
        );
    }

    /// From Epoch 4.1, type analysis requires matching tuple field sets, so whether two types have
    /// a supertype does not depend on their order. The runtime `least_supertype` is deliberately
    /// asymmetric: it drops the second tuple's extra fields (see the tuple epoch-gate test in
    /// `clarity-types`). The supertype itself can still depend on order: for two `max_len` 0
    /// lists, it takes the second list's entry type.
    #[tag(t_prop)]
    #[test]
    fn analysis_supertype_success_is_symmetric(
        a in type_signature_strategy(),
        b in type_signature_strategy(),
    ) {
        prop_assert_eq!(
            TypeSignature::least_supertype_for_analysis(&EPOCH, &a, &b).is_ok(),
            TypeSignature::least_supertype_for_analysis(&EPOCH, &b, &a).is_ok()
        );
    }

    #[tag(t_prop)]
    #[test]
    fn least_supertype_is_idempotent(ty in type_signature_strategy()) {
        prop_assert_eq!(TypeSignature::least_supertype(&EPOCH, &ty, &ty).unwrap(), ty);
    }
}

/// List types that only admit the empty list: no capacity, or an entry type with no values,
/// such as `(list 1 UnknownType)` inferred for `(as-max-len? (list) u1)`.
#[test]
fn value_of_list_type_without_entries_is_the_empty_list() {
    use clarity_types::types::ListTypeData;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;

    for list_type in [
        TypeSignature::empty_list(),
        ListTypeData::new_list(TypeSignature::NoType, 1).unwrap(),
    ] {
        let ty = TypeSignature::from(list_type);
        let value = value_of_type_strategy(ty.clone())
            .new_tree(&mut TestRunner::deterministic())
            .unwrap()
            .current();
        assert_eq!(value, Value::list_from(vec![]).unwrap());
        assert!(
            ty.admits(&EPOCH, &value).unwrap(),
            "{ty} must admit {value}"
        );
    }
}
