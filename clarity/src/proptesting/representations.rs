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

use proptest::prelude::*;

use super::*;
use crate::vm::representations::{Span, TraitDefinition};
use crate::vm::{ClarityName, ContractName, SymbolicExpression, SymbolicExpressionType};

/// Returns a [`Strategy`] for randomly generating a [`ClarityName`].
pub fn clarity_name() -> impl Strategy<Value = ClarityName> {
    "[a-z]{40}".prop_map(|s| s.try_into().unwrap())
}

/// Returns a [`Strategy`] for randomly generating a [`ContractName`].
pub fn contract_name() -> impl Strategy<Value = ContractName> {
    "[a-zA-Z]{1,40}".prop_map(|s| s.try_into().unwrap())
}

/// Returns a [`Strategy`] for randomly generating a [`TraitDefinition`].
pub fn trait_definition() -> impl Strategy<Value = TraitDefinition> {
    prop_oneof![
        trait_identifier().prop_map(TraitDefinition::Defined),
        trait_identifier().prop_map(TraitDefinition::Imported)
    ]
}

/// Returns a [`Strategy`] for randomly generating a [`SymbolicExpression`].
pub fn symbolic_expression() -> impl Strategy<Value = SymbolicExpression> {
    let leaf = prop_oneof![
        clarity_name().prop_map(|name| SymbolicExpression::atom(name)),
        PropValue::any().prop_map(|val| SymbolicExpression::atom_value(val.into())),
        PropValue::any().prop_map(|val| SymbolicExpression::literal_value(val.into())),
        trait_identifier().prop_map(|name| SymbolicExpression::field(name)),
        (clarity_name(), trait_definition())
            .prop_map(|(n, t)| SymbolicExpression::trait_reference(n, t)),
    ];

    leaf.prop_recursive(3, 64, 5, |inner| {
        prop::collection::vec(inner, 1..3).prop_map(|list| SymbolicExpression::list(list))
    })
}
