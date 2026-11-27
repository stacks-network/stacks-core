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

//! Upper-bound estimate of the serialized size of a contract's analysis.
//!
//! The estimate covers `ContractAnalysis::serialize()` once the contract interface
//! built by [`super::build_contract_interface`] has been attached, so it can be
//! computed before either of them is produced. The per-node constants bound the
//! larger of the two JSON encodings of a type: the `serde` encoding of
//! [`TypeSignature`] used by the analysis, and the [`super::ContractInterfaceAtomType`]
//! encoding used by the interface.
//!
//! Tuple type maps can be shared between types, so they are memoized by address to
//! keep the walk linear in the in-memory size of the analysis.
//!
//! The estimate is a pure function of the analysis: it never charges costs, never
//! consults the resource limiter, and never changes the analysis.

use std::collections::{BTreeMap, HashMap};

use crate::vm::ClarityName;
use crate::vm::analysis::types::ContractAnalysis;
use crate::vm::types::signatures::{
    CallableSubtype, FunctionArgSignature, FunctionReturnsSignature,
};
use crate::vm::types::{
    FunctionType, QualifiedContractIdentifier, SequenceSubtype, TraitIdentifier,
    TupleTypeSignature, TypeSignature,
};

/// Bound for a type with no children and no length, e.g. `"PrincipalType"` / `"principal"`.
const SIMPLE_LEAF_BOUND: u64 = 16;
/// Bound for a type with a length and no children, e.g.
/// `{"SequenceType":{"StringType":{"UTF8":4294967295}}}`, and for the fixed part of
/// callable and trait types.
const LEAF_BOUND: u64 = 64;
/// Wrapper bound for `{"OptionalType":<inner>}` / `{"optional":<inner>}`.
const OPTIONAL_OVERHEAD: u64 = 32;
/// Wrapper bound for `{"ResponseType":[<ok>,<err>]}` / `{"response":{"ok":<ok>,"error":<err>}}`.
const RESPONSE_OVERHEAD: u64 = 48;
/// Wrapper bound for `{"SequenceType":{"ListType":{"max_len":4294967295,"entry_type":<inner>}}}`.
const LIST_OVERHEAD: u64 = 96;
/// Wrapper bound for `{"TupleType":{"type_map":{...}}}` / `{"tuple":[...]}`.
const TUPLE_OVERHEAD: u64 = 48;
/// Per-field bound, excluding the name: `{"name":"","type":<inner>},`.
const TUPLE_FIELD_OVERHEAD: u64 = 32;
/// Per-member separator bound for a `ListUnionType`.
const UNION_MEMBER_OVERHEAD: u64 = 32;
/// Bound for a contract identifier, excluding its name: the issuer serializes as
/// `[version,[20 bytes as numbers]]`, i.e. at most 88 bytes, plus the field names.
const CONTRACT_ID_OVERHEAD: u64 = 128;
/// Bound for a trait identifier, excluding the trait name and contract identifier.
const TRAIT_ID_OVERHEAD: u64 = 64;
/// Bound for a top-level entry (function, variable, map, token or trait) in either
/// the analysis or the ABI, excluding its name and types.
const ENTRY_OVERHEAD: u64 = 256;
/// Bound for a function argument, excluding its name and type.
const ARG_OVERHEAD: u64 = 64;
/// Bound for the fixed parts of the analysis and the ABI: the contract identifier,
/// epoch, Clarity version and all of the top-level field names.
const BASE_OVERHEAD: u64 = 2048;

/// Returns an upper bound on the length of `ContractAnalysis::serialize()` for
/// `analysis`, once the contract interface built from it has been attached.
///
/// The result saturates at `u64::MAX`.
pub fn estimate_serialized_analysis_size(analysis: &ContractAnalysis) -> u64 {
    SizeEstimator::default().analysis_size(analysis)
}

#[derive(Default)]
struct SizeEstimator {
    /// Estimated size of each tuple map visited so far, keyed by its address.
    /// The analysis is borrowed for the whole walk, so no address can be reused.
    tuple_sizes: HashMap<*const BTreeMap<ClarityName, TypeSignature>, u64>,
}

fn name_size(name: &ClarityName) -> u64 {
    u64::from(name.len())
}

fn contract_id_size(id: &QualifiedContractIdentifier) -> u64 {
    CONTRACT_ID_OVERHEAD.saturating_add(u64::from(id.name.len()))
}

fn trait_id_size(id: &TraitIdentifier) -> u64 {
    TRAIT_ID_OVERHEAD
        .saturating_add(name_size(&id.name))
        .saturating_add(contract_id_size(&id.contract_identifier))
}

fn callable_size(callable: &CallableSubtype) -> u64 {
    match callable {
        CallableSubtype::Principal(id) => contract_id_size(id),
        CallableSubtype::Trait(id) => trait_id_size(id),
    }
}

impl SizeEstimator {
    fn type_size(&mut self, sig: &TypeSignature) -> u64 {
        match sig {
            TypeSignature::NoType
            | TypeSignature::IntType
            | TypeSignature::UIntType
            | TypeSignature::BoolType
            | TypeSignature::PrincipalType => SIMPLE_LEAF_BOUND,
            TypeSignature::SequenceType(SequenceSubtype::BufferType(_))
            | TypeSignature::SequenceType(SequenceSubtype::StringType(_)) => LEAF_BOUND,
            TypeSignature::SequenceType(SequenceSubtype::ListType(list)) => {
                LIST_OVERHEAD.saturating_add(self.type_size(list.get_list_item_type()))
            }
            TypeSignature::OptionalType(inner) => {
                OPTIONAL_OVERHEAD.saturating_add(self.type_size(inner))
            }
            TypeSignature::ResponseType(inner) => {
                let (ok, err) = inner.as_ref();
                RESPONSE_OVERHEAD
                    .saturating_add(self.type_size(ok))
                    .saturating_add(self.type_size(err))
            }
            TypeSignature::TupleType(tuple) => self.tuple_size(tuple),
            TypeSignature::CallableType(callable) => {
                LEAF_BOUND.saturating_add(callable_size(callable))
            }
            TypeSignature::ListUnionType(members) => {
                members.iter().fold(LEAF_BOUND, |acc, member| {
                    acc.saturating_add(UNION_MEMBER_OVERHEAD)
                        .saturating_add(callable_size(member))
                })
            }
            TypeSignature::TraitReferenceType(id) => LEAF_BOUND.saturating_add(trait_id_size(id)),
        }
    }

    fn tuple_size(&mut self, tuple: &TupleTypeSignature) -> u64 {
        let type_map = tuple.get_type_map();
        let key: *const _ = type_map;
        if let Some(size) = self.tuple_sizes.get(&key) {
            return *size;
        }
        let size = type_map.iter().fold(TUPLE_OVERHEAD, |acc, (name, field)| {
            acc.saturating_add(TUPLE_FIELD_OVERHEAD)
                .saturating_add(name_size(name))
                .saturating_add(self.type_size(field))
        });
        self.tuple_sizes.insert(key, size);
        size
    }

    fn arg_size(&mut self, name: Option<&ClarityName>, sig: &TypeSignature) -> u64 {
        ARG_OVERHEAD
            .saturating_add(name.map(name_size).unwrap_or(0))
            .saturating_add(self.type_size(sig))
    }

    /// Size of the types and argument names in a function signature. User-defined
    /// functions are always `Fixed`; the other variants are covered for completeness.
    fn function_type_size(&mut self, function_type: &FunctionType) -> u64 {
        match function_type {
            FunctionType::Fixed(fixed) => fixed
                .args
                .iter()
                .fold(self.type_size(&fixed.returns), |acc, arg| {
                    acc.saturating_add(self.arg_size(Some(&arg.name), &arg.signature))
                }),
            FunctionType::Variadic(arg, returns) => self
                .arg_size(None, arg)
                .saturating_add(self.type_size(returns)),
            FunctionType::UnionArgs(args, returns) => {
                args.iter().fold(self.type_size(returns), |acc, arg| {
                    acc.saturating_add(self.arg_size(None, arg))
                })
            }
            FunctionType::Binary(first, second, returns) => {
                let returns = match returns {
                    FunctionReturnsSignature::TypeOfArgAtPosition(_) => LEAF_BOUND,
                    FunctionReturnsSignature::Fixed(sig) => self.type_size(sig),
                };
                [first, second].into_iter().fold(returns, |acc, arg| {
                    let arg = match arg {
                        FunctionArgSignature::Single(sig) => self.arg_size(None, sig),
                        FunctionArgSignature::Union(sigs) => {
                            sigs.iter().fold(ARG_OVERHEAD, |acc, sig| {
                                acc.saturating_add(self.arg_size(None, sig))
                            })
                        }
                    };
                    acc.saturating_add(arg)
                })
            }
            FunctionType::ArithmeticVariadic
            | FunctionType::ArithmeticUnary
            | FunctionType::ArithmeticBinary
            | FunctionType::ArithmeticComparison => LEAF_BOUND,
        }
    }

    fn analysis_size(&mut self, analysis: &ContractAnalysis) -> u64 {
        let ContractAnalysis {
            contract_identifier,
            private_function_types,
            variable_types,
            public_function_types,
            read_only_function_types,
            map_types,
            persisted_variable_types,
            fungible_tokens,
            non_fungible_tokens,
            defined_traits,
            implemented_traits,
            // Covered below: the estimate always accounts for the interface built
            // from the other fields, whether or not it has been attached yet.
            contract_interface: _,
            epoch: _,
            clarity_version: _,
            // Not serialized.
            expressions: _,
            type_map: _,
            cost_track: _,
        } = analysis;

        let mut total = BASE_OVERHEAD.saturating_add(contract_id_size(contract_identifier));

        // Everything that appears in the ABI appears twice: once in the analysis
        // itself and once in the attached `contract_interface`.
        let entry = |name: &ClarityName, types: u64| {
            ENTRY_OVERHEAD
                .saturating_add(name_size(name).saturating_mul(2))
                .saturating_add(types.saturating_mul(2))
        };

        for functions in [
            private_function_types,
            public_function_types,
            read_only_function_types,
        ] {
            for (name, function_type) in functions {
                let types = self.function_type_size(function_type);
                total = total.saturating_add(entry(name, types));
            }
        }
        for variables in [
            variable_types,
            persisted_variable_types,
            non_fungible_tokens,
        ] {
            for (name, sig) in variables {
                let types = self.type_size(sig);
                total = total.saturating_add(entry(name, types));
            }
        }
        for (name, (key, value)) in map_types {
            let types = self.type_size(key).saturating_add(self.type_size(value));
            total = total.saturating_add(entry(name, types));
        }
        for name in fungible_tokens {
            total = total.saturating_add(entry(name, 0));
        }

        // Trait definitions and implementations are only in the analysis, not the ABI.
        for (trait_name, functions) in defined_traits {
            total = total
                .saturating_add(ENTRY_OVERHEAD)
                .saturating_add(name_size(trait_name));
            for (name, signature) in functions {
                let types = signature
                    .args
                    .iter()
                    .fold(self.type_size(&signature.returns), |acc, arg| {
                        acc.saturating_add(self.arg_size(None, arg))
                    });
                total = total
                    .saturating_add(ENTRY_OVERHEAD)
                    .saturating_add(name_size(name))
                    .saturating_add(types);
            }
        }
        for trait_id in implemented_traits {
            total = total
                .saturating_add(ARG_OVERHEAD)
                .saturating_add(trait_id_size(trait_id));
        }

        total
    }
}

#[cfg(test)]
mod tests {
    use stacks_common::types::StacksEpochId;

    use super::*;
    use crate::vm::ClarityVersion;
    use crate::vm::analysis::mem_type_check;
    use crate::vm::database::ClaritySerializable as _;

    /// Type-check `src` (which also attaches the contract interface) and check that the
    /// estimate bounds the real serialized size without being uselessly loose.
    fn assert_bounds(src: &str) {
        let (_, analysis) =
            mem_type_check(src, ClarityVersion::latest(), StacksEpochId::latest()).unwrap();
        assert!(analysis.contract_interface.is_some());
        let actual = analysis.serialize().len() as u64;
        let estimate = estimate_serialized_analysis_size(&analysis);
        assert!(
            estimate >= actual,
            "estimate {estimate} < actual {actual} for:\n{src}"
        );
        // Loose enough to tolerate the fixed overheads on tiny contracts.
        assert!(
            estimate <= actual.saturating_mul(8).max(BASE_OVERHEAD * 2),
            "estimate {estimate} is too loose for actual {actual} for:\n{src}"
        );
    }

    #[test]
    fn bounds_minimal_contract() {
        assert_bounds("(define-data-var x int 0)");
    }

    #[test]
    fn bounds_every_type_shape() {
        assert_bounds(
            "(define-data-var counter int 0)
             (define-data-var owner principal tx-sender)
             (define-data-var flag bool true)
             (define-data-var buf (buff 4294) 0x00)
             (define-data-var ascii (string-ascii 128) \"a\")
             (define-data-var utf8 (string-utf8 128) u\"a\")
             (define-data-var opt (optional uint) none)
             (define-data-var lst (list 10 (list 3 { a: int, b: (optional (buff 2)) })) (list))
             (define-map ledger { owner: principal, id: uint } { amount: uint, memo: (optional (string-ascii 34)) })
             (define-fungible-token ft)
             (define-non-fungible-token nft { id: uint, tag: (buff 32) })
             (define-constant tup { x: 1, y: { z: u2, w: (some true) } })
             (define-constant principals (list 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.a 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.b))
             (define-private (priv (a int) (b (response uint int))) (ok a))
             (define-read-only (ro (k { owner: principal, id: uint })) (map-get? ledger k))
             (define-public (pub (amount uint)) (if (> amount u0) (ok amount) (err u1)))",
        );
    }

    #[test]
    fn bounds_traits() {
        assert_bounds(
            "(define-trait token-trait
                ((transfer? (principal principal uint) (response uint uint))
                 (get-balance (principal) (response { balance: uint, locked: (optional uint) } uint))))
             (define-public (call-it (t <token-trait>) (who principal))
                (contract-call? t get-balance who))",
        );
    }

    #[test]
    fn bounds_nested_constants() {
        assert_bounds(
            "(define-constant base { a: 1, b: u2, c: (some true) })
             (define-constant nested { x: base, y: (list base base), z: (ok base) })
             (define-constant outer { first: nested, second: nested })
             (define-read-only (get-outer) outer)",
        );
    }
}
