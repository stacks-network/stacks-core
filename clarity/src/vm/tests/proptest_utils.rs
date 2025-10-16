// Copyright (C) 2025 Stacks Open Internet Foundation
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

//! This module contains utility functions and strategies for property-based
//! testing of the Clarity VM.

use std::result::Result;

use clarity_types::errors::InterpreterResult;
use clarity_types::types::{
    CharType, PrincipalData, QualifiedContractIdentifier, SequenceData, StandardPrincipalData,
    TypeSignature, UTF8Data,
};
use clarity_types::{ContractName, Value};
use proptest::array::uniform20;
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::strategy::BoxedStrategy;
use proptest::string::string_regex;
use stacks_common::types::StacksEpochId;

use crate::vm::contexts::{AssetMap, GlobalContext};
use crate::vm::database::STXBalance;
use crate::vm::errors::Error as VmError;
use crate::vm::{
    execute_call_in_global_context_and_return_asset_map,
    execute_with_parameters_and_call_in_global_context, ClarityVersion,
};

const DEFAULT_EPOCH: StacksEpochId = StacksEpochId::Epoch33;
const DEFAULT_CLARITY_VERSION: ClarityVersion = ClarityVersion::Clarity4;
const INITIAL_BALANCE: u128 = 1_000_000;

fn initialize_balances(g: &mut GlobalContext) -> Result<(), VmError> {
    let sender_principal = PrincipalData::Standard(StandardPrincipalData::transient());
    let contract_id = QualifiedContractIdentifier::transient();
    let contract_principal = PrincipalData::Contract(contract_id);
    let balance = STXBalance::initial(INITIAL_BALANCE);

    let mut sender_snapshot = g
        .database
        .get_stx_balance_snapshot_genesis(&sender_principal)
        .unwrap();
    sender_snapshot.set_balance(balance.clone());
    sender_snapshot.save().unwrap();

    let mut contract_snapshot = g
        .database
        .get_stx_balance_snapshot_genesis(&contract_principal)
        .unwrap();
    contract_snapshot.set_balance(balance);
    contract_snapshot.save().unwrap();

    g.database
        .increment_ustx_liquid_supply(INITIAL_BALANCE * 2)
        .unwrap();
    Ok(())
}

/// Execute a Clarity code snippet in a fresh global context with default
/// parameters, setting up initial balances.
pub fn execute(snippet: &str) -> InterpreterResult<Option<Value>> {
    execute_versioned(snippet, DEFAULT_CLARITY_VERSION)
}

/// Execute a Clarity code snippet with the specified Clarity version in a
/// fresh global context with default parameters, setting up initial balances.
pub fn execute_versioned(
    snippet: &str,
    version: ClarityVersion,
) -> InterpreterResult<Option<Value>> {
    execute_with_parameters_and_call_in_global_context(
        snippet,
        version,
        DEFAULT_EPOCH,
        false,
        initialize_balances,
    )
}

/// Execute a Clarity code snippet in a fresh global context with default
/// parameters, setting up initial balances, returning the resulting value
/// along with the final asset map.
pub fn execute_and_return_asset_map(snippet: &str) -> InterpreterResult<(Option<Value>, AssetMap)> {
    execute_and_return_asset_map_versioned(snippet, DEFAULT_CLARITY_VERSION)
}

/// Execute a Clarity code snippet with the specified Clarity version in a
/// fresh global context with default parameters, setting up initial balances,
/// returning the resulting value along with the final asset map.
pub fn execute_and_return_asset_map_versioned(
    snippet: &str,
    version: ClarityVersion,
) -> InterpreterResult<(Option<Value>, AssetMap)> {
    execute_call_in_global_context_and_return_asset_map(
        snippet,
        version,
        DEFAULT_EPOCH,
        false,
        initialize_balances,
    )
}

/// A strategy that generates Clarity values.
pub fn clarity_values() -> BoxedStrategy<Value> {
    clarity_values_inner(true)
}

/// A strategy that generates Clarity values, excluding Response types.
pub fn clarity_values_no_response() -> BoxedStrategy<Value> {
    clarity_values_inner(false)
}

/// Internal function to generate Clarity values, with an option to include
/// or exclude Response types.
fn clarity_values_inner(include_responses: bool) -> BoxedStrategy<Value> {
    let ascii_strings = string_regex("[A-Za-z0-9 \\-_=+*/?!]{0,1024}")
        .unwrap()
        .prop_map(|s| {
            Value::string_ascii_from_bytes(s.into_bytes())
                .expect("ASCII literal within allowed character set")
        });

    let utf8_strings =
        string_regex(r#"[\u{00A1}-\u{024F}\u{0370}-\u{03FF}\u{1F300}-\u{1F64F}]{0,1024}"#)
            .unwrap()
            .prop_map(|s| {
                Value::string_utf8_from_bytes(s.into_bytes())
                    .expect("UTF-8 literal within allowed character set")
            });

    let standard_principal_data = (any::<u8>(), uniform20(any::<u8>()))
        .prop_filter_map("Invalid standard principal", |(version, bytes)| {
            let version = version % 32;
            StandardPrincipalData::new(version, bytes).ok()
        })
        .boxed();

    let standard_principals = standard_principal_data
        .clone()
        .prop_map(|principal| Value::Principal(PrincipalData::Standard(principal)))
        .boxed();

    let contract_name_strings = prop_oneof![
        string_regex("[a-tv-z][a-z0-9-?!]{0,39}").unwrap(),
        string_regex("u[a-z-?!][a-z0-9-?!]{0,38}").unwrap(),
    ]
    .boxed();

    let contract_names = contract_name_strings
        .prop_filter_map("Invalid contract name", |name| {
            ContractName::try_from(name).ok()
        })
        .boxed();

    let contract_principals = (standard_principal_data, contract_names)
        .prop_map(|(issuer, name)| {
            Value::Principal(PrincipalData::Contract(QualifiedContractIdentifier::new(
                issuer, name,
            )))
        })
        .boxed();

    let principal_values = prop_oneof![standard_principals, contract_principals];

    let buffer_values = vec(any::<u8>(), 0..1024).prop_map(|bytes| {
        Value::buff_from(bytes).expect("Buffer construction should succeed with any byte data")
    });

    let base_values = prop_oneof![
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|v| Value::Int(v as i128)),
        any::<u64>().prop_map(|v| Value::UInt(v as u128)),
        ascii_strings,
        utf8_strings,
        Just(Value::none()),
        principal_values,
        buffer_values,
    ];

    base_values
        .prop_recursive(
            3,  // max nesting depth
            64, // total size budget
            6,  // branching factor
            move |inner| {
                let option_values = inner
                    .clone()
                    .prop_filter_map("Option construction failed", |v| Value::some(v).ok())
                    .boxed();

                let inner_for_lists = inner.clone();
                let lists_from_inner = inner
                    .clone()
                    .prop_flat_map(move |prototype| {
                        let sig = TypeSignature::type_of(&prototype)
                            .expect("Values generated by strategy should have a type signature");
                        let sig_for_filter = sig.clone();
                        let prototype_for_elements = prototype.clone();
                        let element_strategy = inner_for_lists.clone().prop_map(move |candidate| {
                            if TypeSignature::type_of(&candidate)
                                .ok()
                                .is_some_and(|t| t == sig_for_filter)
                            {
                                candidate
                            } else {
                                prototype_for_elements.clone()
                            }
                        });
                        let prototype_for_list = prototype.clone();
                        vec(element_strategy, 0..3).prop_map(move |rest| {
                            let mut values = Vec::with_capacity(rest.len() + 1);
                            values.push(prototype_for_list.clone());
                            values.extend(rest);
                            Value::list_from(values)
                                .expect("List construction should succeed with homogeneous values")
                        })
                    })
                    .boxed();

                let bool_lists = vec(any::<bool>().prop_map(Value::Bool), 1..4)
                    .prop_filter_map("List<bool> construction failed", |values| {
                        Value::list_from(values).ok()
                    })
                    .boxed();

                let uint_lists = vec(any::<u64>().prop_map(|v| Value::UInt(v as u128)), 1..4)
                    .prop_filter_map("List<uint> construction failed", |values| {
                        Value::list_from(values).ok()
                    })
                    .boxed();

                if include_responses {
                    let ok_responses = inner
                        .clone()
                        .prop_filter_map("Response(ok) construction failed", |v| {
                            Value::okay(v).ok()
                        })
                        .boxed();

                    let err_responses = inner
                        .clone()
                        .prop_filter_map("Response(err) construction failed", |v| {
                            Value::error(v).ok()
                        })
                        .boxed();

                    prop_oneof![
                        option_values,
                        ok_responses,
                        err_responses,
                        lists_from_inner,
                        bool_lists,
                        uint_lists,
                    ]
                    .boxed()
                } else {
                    prop_oneof![option_values, lists_from_inner, bool_lists, uint_lists].boxed()
                }
            },
        )
        .boxed()
}

/// A strategy that generates STX transfer expressions with amounts between
/// 1 and 1,000,000 micro-STX.
pub fn stx_transfer_expressions() -> impl Strategy<Value = String> {
    (1u64..1_000_000u64).prop_map(|amount| {
        format!("(try! (stx-transfer? u{amount} tx-sender 'SP000000000000000000002Q6VF78))")
    })
}

/// A strategy that generates `(begin ...)` expressions containing between
/// 1 and 8 expressions, each of which is either a Clarity value literal or
/// an STX transfer expression.
pub fn begin_block() -> impl Strategy<Value = String> {
    vec(
        prop_oneof![
            clarity_values_no_response().prop_map(|value| value_to_clarity_literal(&value)),
            stx_transfer_expressions(),
        ],
        1..8,
    )
    .prop_shuffle()
    .prop_map(|expressions| {
        let body = expressions.join(" ");
        format!("(begin {body})")
    })
}

/// Convert a Clarity `Value` into a Clarity literal string.
pub fn value_to_clarity_literal(value: &Value) -> String {
    match value {
        Value::Sequence(SequenceData::List(list_data)) => {
            let items: Vec<_> = list_data
                .data
                .iter()
                .map(value_to_clarity_literal)
                .collect();
            if items.is_empty() {
                "(list)".to_string()
            } else {
                format!("(list {})", items.join(" "))
            }
        }
        Value::Sequence(SequenceData::String(CharType::ASCII(data))) => format!("{data}"),
        Value::Sequence(SequenceData::String(CharType::UTF8(data))) => utf8_string_literal(data),
        Value::Optional(optional) => match optional.data.as_deref() {
            Some(inner) => format!("(some {})", value_to_clarity_literal(inner)),
            None => "none".to_string(),
        },
        Value::Response(response) => {
            let inner = value_to_clarity_literal(response.data.as_ref());
            if response.committed {
                format!("(ok {})", inner)
            } else {
                format!("(err {})", inner)
            }
        }
        Value::Principal(principal) => format!("'{}", principal),
        Value::Tuple(tuple) => {
            let mut literal = String::from("(tuple");
            for (name, field) in tuple.data_map.iter() {
                literal.push(' ');
                literal.push('(');
                literal.push_str(&name.to_string());
                literal.push(' ');
                literal.push_str(&value_to_clarity_literal(field));
                literal.push(')');
            }
            literal.push(')');
            literal
        }
        _ => format!("{value}"),
    }
}

/// Convert UTF-8 data into a Clarity UTF-8 string literal.
pub fn utf8_string_literal(data: &UTF8Data) -> String {
    let mut literal = String::from("u\"");
    for bytes in &data.data {
        if bytes.len() == 1 {
            for escaped in std::ascii::escape_default(bytes[0]) {
                literal.push(escaped as char);
            }
        } else {
            let ch = std::str::from_utf8(bytes)
                .expect("UTF-8 data should decode to a scalar value")
                .chars()
                .next()
                .expect("UTF-8 data should contain at least one scalar");
            literal.push_str(&format!("\\u{{{:X}}}", ch as u32));
        }
    }
    literal.push('"');
    literal
}
