// Copyright (C) 2025-2026 Stacks Open Internet Foundation
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

use std::collections::BTreeSet;
use std::result::Result;

use clarity_types::types::{
    CharType, MAX_TO_ASCII_BUFFER_LEN, MAX_UTF8_VALUE_SIZE, MAX_VALUE_SIZE, PrincipalData,
    QualifiedContractIdentifier, SequenceData, StandardPrincipalData, TypeSignature, UTF8Data,
};
use clarity_types::{ContractName, Value};
use proptest::array::uniform20;
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::strategy::BoxedStrategy;
use proptest::string::string_regex;
use stacks_common::types::StacksEpochId;
use stacks_common::types::chainstate::StacksPrivateKey;
use stacks_common::util::hash::to_hex;

use crate::vm::analysis::type_checker::v2_1::natives::post_conditions::{
    MAX_ALLOWANCES, MAX_NFT_IDENTIFIERS,
};
use crate::vm::contexts::GlobalContext;
use crate::vm::database::STXBalance;
use crate::vm::errors::VmExecutionError;
use crate::vm::{ClarityVersion, execute_with_parameters_and_call_in_global_context};

const DEFAULT_EPOCH: StacksEpochId = StacksEpochId::Epoch34;
const DEFAULT_CLARITY_VERSION: ClarityVersion = ClarityVersion::Clarity5;
const INITIAL_BALANCE: u128 = 1_000_000_000;
const UTF8_SNIPPET_MAX_SEGMENTS: usize = 16;
const UTF8_SIMPLE_ESCAPES: [&str; 6] = ["\\\"", "\\\\", "\\n", "\\t", "\\r", "\\0"];

fn initialize_balances(
    g: &mut GlobalContext,
    sender: &StandardPrincipalData,
) -> Result<(), VmExecutionError> {
    let sender_principal = PrincipalData::Standard(sender.clone());
    let contract_principal = PrincipalData::Contract(QualifiedContractIdentifier::new(
        sender.clone(),
        "contract".into(),
    ));
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
pub fn execute(snippet: &str) -> Result<Option<Value>, VmExecutionError> {
    execute_versioned(snippet, DEFAULT_CLARITY_VERSION)
}

/// Execute a Clarity code snippet with the specified Clarity version in a
/// fresh global context with default parameters, setting up initial balances.
pub fn execute_versioned(
    snippet: &str,
    version: ClarityVersion,
) -> Result<Option<Value>, VmExecutionError> {
    let sender_pk = StacksPrivateKey::random();
    let sender: StandardPrincipalData = (&sender_pk).into();
    let contract_id = QualifiedContractIdentifier::new(sender.clone(), "contract".into());
    let sender_for_init = sender.clone();
    execute_with_parameters_and_call_in_global_context(
        snippet,
        version,
        DEFAULT_EPOCH,
        false,
        sender,
        move |g| initialize_balances(g, &sender_for_init),
        |_| Ok(()),
    )
}

/// Execute a Clarity code snippet in a fresh global context with default
/// parameters, setting up initial balances, returning the resulting value
/// along with the final asset map.
pub fn execute_and_check<F>(
    snippet: &str,
    sender: StandardPrincipalData,
    check: F,
) -> Result<Option<Value>, VmExecutionError>
where
    F: FnMut(&mut GlobalContext) -> Result<(), VmExecutionError>,
{
    execute_and_check_versioned(snippet, DEFAULT_CLARITY_VERSION, sender, check)
}

/// Execute a Clarity code snippet with the specified Clarity version in a
/// fresh global context with default parameters, setting up initial balances,
/// returning the resulting value along with the final asset map.
pub fn execute_and_check_versioned<F>(
    snippet: &str,
    version: ClarityVersion,
    sender: StandardPrincipalData,
    mut check: F,
) -> Result<Option<Value>, VmExecutionError>
where
    F: FnMut(&mut GlobalContext) -> Result<(), VmExecutionError>,
{
    let sender_for_init = sender.clone();
    execute_with_parameters_and_call_in_global_context(
        snippet,
        version,
        DEFAULT_EPOCH,
        false,
        sender,
        move |g| initialize_balances(g, &sender_for_init),
        move |g| check(g),
    )
}

/// A strategy that generates valid Clarity contract names.
pub fn contract_name_strategy() -> BoxedStrategy<ContractName> {
    prop_oneof![
        string_regex("[a-tv-z][a-z0-9-?!]{0,39}").unwrap(),
        string_regex("u[a-z-?!][a-z0-9-?!]{0,38}").unwrap(),
    ]
    .prop_filter_map("Invalid contract name", |name| {
        ContractName::try_from(name).ok()
    })
    .boxed()
}

/// A strategy that generates `uint` snippets
pub fn uint_snippet_strategy() -> impl Strategy<Value = String> {
    any::<u128>().prop_map(|value| format!("u{value}"))
}

/// A strategy that generates `int` snippets
pub fn int_snippet_strategy() -> impl Strategy<Value = String> {
    any::<i128>().prop_map(|value| value.to_string())
}

/// A strategy that generates `bool` snippets
pub fn bool_snippet_strategy() -> impl Strategy<Value = String> {
    any::<bool>().prop_map(|value| value.to_string())
}

/// A strategy that generates standard `principal`s
/// The version is restricted to those currently valid: 20, 21, 22, and 26
pub fn standard_principal_strategy() -> impl Strategy<Value = StandardPrincipalData> {
    (
        prop::sample::select(&[20u8, 21u8, 22u8, 26u8]),
        uniform20(any::<u8>()),
    )
        .prop_filter_map("Invalid standard principal", |(version, bytes)| {
            StandardPrincipalData::new(version, bytes).ok()
        })
}

/// A strategy that generates standard `principal` snippets
pub fn standard_principal_snippet_strategy() -> impl Strategy<Value = String> {
    standard_principal_strategy().prop_map(|principal| format!("'{principal}"))
}

/// A strategy that generates contract `principal` snippets
pub fn contract_principal_snippet_strategy() -> impl Strategy<Value = String> {
    (standard_principal_strategy(), contract_name_strategy()).prop_map(|(issuer, name)| {
        let contract_id = QualifiedContractIdentifier::new(issuer, name);
        format!("'{contract_id}")
    })
}

/// A strategy that generates `principal` snippets, either standard or contract
pub fn principal_snippet_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        standard_principal_snippet_strategy().boxed(),
        contract_principal_snippet_strategy().boxed(),
    ]
}

/// A strategy that generates `buff` snippets
pub fn buffer_snippet_strategy() -> impl Strategy<Value = String> {
    vec(any::<u8>(), 0..MAX_VALUE_SIZE as usize).prop_map(|bytes| {
        let hex = to_hex(&bytes);
        format!("0x{hex}")
    })
}

pub fn to_ascii_buffer_snippet_strategy() -> impl Strategy<Value = String> {
    vec(any::<u8>(), 0..=MAX_TO_ASCII_BUFFER_LEN as usize).prop_map(|bytes| {
        let hex = to_hex(&bytes);
        format!("0x{hex}")
    })
}

/// A strategy that generates ASCII snippets
pub fn ascii_string_snippet_strategy() -> impl Strategy<Value = String> {
    string_regex(&format!(
        r#"(?x)
        "                              # opening quote
        (?:                            # body: zero or more of...
          [\x20\x21\x23-\x5B\x5D-\x7E] #   printable ASCII except " and \
          | \\[\\"ntr]                 #   valid escape sequences
        ){{0,{}}}                      # up to MAX_VALUE_SIZE
        "                              # closing quote
        "#,
        MAX_VALUE_SIZE
    ))
    .unwrap()
}

/// A strategy that generates UTF8 snippets that only contain ASCII characters
pub fn utf8_string_ascii_only_snippet_strategy() -> impl Strategy<Value = String> {
    string_regex(&format!(
        r#"(?x)
        u"                             # opening quote
        (?:                            # body: zero or more of...
          [\x20\x21\x23-\x5B\x5D-\x7E] #   printable ASCII except " and \
          | \\[\\"ntr]                 #   valid escape sequences
        ){{0,{}}}                      # up to MAX_UTF8_VALUE_SIZE
        "                              # closing quote
        "#,
        MAX_UTF8_VALUE_SIZE
    ))
    .unwrap()
}

/// A strategy that generates UTF-8 string snippets
pub fn utf8_string_snippet_strategy() -> impl Strategy<Value = String> {
    let ascii_chars: Vec<char> = (0x20u8..=0x7E)
        .filter(|byte| *byte != b'"' && *byte != b'\\')
        .map(|byte| byte as char)
        .collect();

    let ascii_char_segment = prop::sample::select(ascii_chars).prop_map(|ch| ch.to_string());

    let simple_escape_segment =
        prop::sample::select(&UTF8_SIMPLE_ESCAPES).prop_map(|escape| escape.to_string());

    let unicode_escape_segment =
        proptest::char::any().prop_map(|ch| format!("\\u{{{:X}}}", ch as u32));

    vec(
        prop_oneof![
            ascii_char_segment,
            simple_escape_segment,
            unicode_escape_segment,
        ],
        0..=MAX_UTF8_VALUE_SIZE as usize,
    )
    .prop_map(|segments: Vec<String>| format!("u\"{}\"", segments.concat()))
}

/// A strategy that generates simple Clarity value snippets
/// including uint, int, bool, principal, buffer, and string types.
pub fn simple_value_snippet_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        uint_snippet_strategy().boxed(),
        int_snippet_strategy().boxed(),
        bool_snippet_strategy().boxed(),
        principal_snippet_strategy().boxed(),
        buffer_snippet_strategy().boxed(),
        ascii_string_snippet_strategy().boxed(),
        utf8_string_snippet_strategy().boxed(),
    ]
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
        any::<i128>().prop_map(Value::Int),
        any::<u128>().prop_map(Value::UInt),
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

                let uint_lists = vec(any::<u128>().prop_map(Value::UInt), 1..4)
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

/// A strategy that generates STX transfer snippets with amounts between
/// 1 and 1,000,000 micro-STX.
pub fn stx_transfer_snippets() -> impl Strategy<Value = String> {
    (1u64..1_000_000u64).prop_map(|amount| {
        format!("(stx-transfer? u{amount} tx-sender 'SP000000000000000000002Q6VF78)")
    })
}

/// A strategy that generates STX transfer snippets with amounts between
/// 1 and 1,000,000 micro-STX and a corresponding allowance to use with
/// `as-contract?` or `restrict-assets?`.
pub fn stx_transfer_and_allowance_snippets() -> impl Strategy<Value = (String, String)> {
    (1u64..1_000_000u64).prop_flat_map(|amount| {
        let transfer_snippet =
            format!("(stx-transfer? u{amount} tx-sender 'SP000000000000000000002Q6VF78)");
        (amount..=1_000_000).prop_map(move |allowance_amount| {
            let allowance_snippet = format!("(with-stx u{allowance_amount})");
            (transfer_snippet.clone(), allowance_snippet)
        })
    })
}

/// A strategy that generates FT mint snippets with amounts between
/// 1 and 1,000,000 units of the token. The FT contract is always
/// `current-contract` and the token name is always `stackos`.
pub fn ft_mint_snippets(recipient: String) -> impl Strategy<Value = String> {
    (1u64..1_000_000u64).prop_map(move |amount| format!("(ft-mint? stackos u{amount} {recipient})"))
}

/// A strategy that generates FT transfer snippets with amounts between
/// 1 and 1,000,000 units of the token. The FT contract is always
/// `current-contract` and the token name is always `stackos`.
pub fn ft_transfer_snippets() -> impl Strategy<Value = String> {
    (1u64..1_000_000u64).prop_map(|amount| {
        format!("(ft-transfer? stackos u{amount} tx-sender 'SP000000000000000000002Q6VF78)")
    })
}

/// A strategy that generates FT transfer snippets with amounts between
/// 1 and 1,000,000 units of the token and a corresponding allowance to use with
/// `as-contract?` or `restrict-assets?`. The FT contract is always
/// `current-contract` and the token name is always `stackos`.
pub fn ft_transfer_and_allowance_snippets() -> impl Strategy<Value = (String, String)> {
    (1u64..1_000_000u64).prop_flat_map(|amount| {
        let transfer_snippet =
            format!("(ft-transfer? stackos u{amount} tx-sender 'SP000000000000000000002Q6VF78)");
        (amount..=1_000_000).prop_map(move |allowance_amount| {
            let allowance_snippet =
                format!("(with-ft current-contract \"stackos\" u{allowance_amount})");
            (transfer_snippet.clone(), allowance_snippet)
        })
    })
}

/// A strategy that generates NFT mint snippets. The NFT contract is always
/// `current-contract` and the token name is always `stackaroo`. A random
/// `uint` identifier is generated for each snippet.
pub fn nft_mint_snippets(recipient: String) -> impl Strategy<Value = String> {
    any::<u128>().prop_map(move |id| format!("(nft-mint? stackaroo u{id} {recipient})"))
}

/// A strategy that generates NFT transfer snippets. The NFT contract is always
/// `current-contract` and the token name is always `stackaroo`. A random
/// `uint` identifier is generated for each snippet.
pub fn nft_transfer_snippets() -> impl Strategy<Value = String> {
    any::<u128>().prop_map(|id| {
        format!("(nft-transfer? stackaroo u{id} tx-sender 'SP000000000000000000002Q6VF78)")
    })
}

/// A strategy that generates NFT transfer snippets with a corresponding
/// allowance to use with `as-contract?` or `restrict-assets?`. The NFT
/// contract is always `current-contract` and the token name is always
/// `stackaroo`. A random list of u128 IDs is generated for the allowance, then
/// one of those is transferred.
pub fn nft_transfer_and_allowance_snippets() -> impl Strategy<Value = (String, String)> {
    prop::collection::vec(any::<u128>(), 1..=MAX_NFT_IDENTIFIERS as usize).prop_flat_map(|ids| {
        let allowance_snippet = format!(
            "(with-nft current-contract \"stackaroo\" (list {}))",
            ids.iter()
                .map(|id| format!("u{id}"))
                .collect::<Vec<_>>()
                .join(" ")
        );

        // Choose one of those ids to transfer
        prop::sample::select(ids).prop_map(move |transfer_id| {
            let transfer_snippet = format!(
                "(nft-transfer? stackaroo u{transfer_id} tx-sender 'SP000000000000000000002Q6VF78)"
            );
            (transfer_snippet, allowance_snippet.clone())
        })
    })
}

pub fn any_transfer_and_allowance_snippets() -> impl Strategy<Value = (String, String)> {
    prop_oneof![
        stx_transfer_and_allowance_snippets().boxed(),
        ft_transfer_and_allowance_snippets().boxed(),
        nft_transfer_and_allowance_snippets().boxed(),
    ]
}

/// A strategy that generates a `try!`-wrapped version of the given
/// Clarity code snippet generator. This is useful for wrapping expressions
/// that return a `Response` type, so that they can be used in contexts
/// that expect a non-`Response` value.
pub fn try_response_snippets<S>(response: S) -> impl Strategy<Value = String>
where
    S: Strategy<Value = String>,
{
    response.prop_map(|snippet| format!("(try! {snippet})"))
}

/// A strategy that generates a `match`-wrapped version of the given
/// Clarity code snippet generator. This is useful for wrapping expressions
/// that return a `Response` type, so that they can be used in contexts
/// that expect a non-`Response` value and will not cause an error.
pub fn match_response_snippets<S>(response: S) -> impl Strategy<Value = String>
where
    S: Strategy<Value = String>,
{
    response.prop_map(|snippet| format!("(match {snippet} v true e false)"))
}

/// A strategy that generates Clarity code snippets for STX allowances.
fn stx_allowance_snippets() -> impl Strategy<Value = String> {
    any::<u128>().prop_map(|amount| format!("(with-stx u{amount})"))
}

/// A stategy that generates Clarity code snippets for FT allowances.
/// The FT contract is always `current-contract` and the token name is always
/// `stackos`.
pub fn ft_allowance_snippets() -> impl Strategy<Value = String> {
    any::<u128>().prop_map(|amount| format!("(with-ft current-contract \"stackos\" u{amount})"))
}

/// A strategy that generates Clarity code snippets for NFT allowances.
/// The NFT contract is always `current-contract` and the token name is always
/// `stackaroo`, and a random list of u128 IDs is generated.
pub fn nft_allowance_snippets() -> impl Strategy<Value = String> {
    let nft_ids = prop::collection::vec(any::<u128>(), 0..=MAX_NFT_IDENTIFIERS as usize);
    nft_ids.prop_map(|ids| {
        format!(
            "(with-nft current-contract \"stackaroo\" (list {}))",
            ids.iter()
                .map(|id| format!("u{id}"))
                .collect::<Vec<_>>()
                .join(" ")
        )
    })
}

/// A strategy that generates Clarity code snippets for stacking allowances.
pub fn stacking_allowance_snippets() -> impl Strategy<Value = String> {
    any::<u128>().prop_map(|amount| format!("(with-stacking u{amount})"))
}

/// A strategy that generates Clarity code snippets for allowances.
pub fn allowance_snippets() -> impl Strategy<Value = String> {
    let stx_allowance = stx_allowance_snippets();
    let ft_allowance = ft_allowance_snippets();
    let nft_allowance = nft_allowance_snippets();
    let stacking_allowance = stacking_allowance_snippets();
    prop_oneof![
        stx_allowance,
        ft_allowance,
        nft_allowance,
        stacking_allowance
    ]
}

/// A strategy that generates Clarity code snippets for allowances lists.
pub fn allowance_list_snippets() -> impl Strategy<Value = String> {
    prop::collection::vec(allowance_snippets(), 0..MAX_ALLOWANCES).prop_map(|allowances| {
        if allowances.is_empty() {
            "()".to_string()
        } else {
            format!("({})", allowances.join(" "))
        }
    })
}

/// A strategy that generates a list of expressions, including STX, FT, and NFT
/// transfers along with allowances that cover any of those transfers.
pub fn body_with_allowances_snippets() -> impl Strategy<Value = (String, String)> {
    #[derive(Clone, Debug)]
    enum TransferSpec {
        Stx(u128),
        Ft(u128),
        Nft(u128),
    }

    let transfer_spec = prop_oneof![
        (1u64..1_000_000u64)
            .prop_map(|amount| TransferSpec::Stx(amount as u128))
            .boxed(),
        (1u64..1_000_000u64)
            .prop_map(|amount| TransferSpec::Ft(amount as u128))
            .boxed(),
        any::<u128>().prop_map(TransferSpec::Nft).boxed(),
    ];

    prop::collection::vec(transfer_spec, 1..8).prop_flat_map(|transfer_specs| {
        let mut stx_allowance: Option<u128> = None;
        let mut ft_allowance: Option<u128> = None;
        let mut nft_ids = BTreeSet::new();
        let mut transfer_exprs = Vec::new();

        for spec in transfer_specs.iter() {
            match spec {
                TransferSpec::Stx(amount) => {
                    stx_allowance = Some(stx_allowance.map_or(*amount, |m| m + *amount));
                    transfer_exprs.push(format!(
                        "(match (stx-transfer? u{amount} tx-sender 'SP000000000000000000002Q6VF78) v true e false)"
                    ));
                }
                TransferSpec::Ft(amount) => {
                    ft_allowance = Some(ft_allowance.map_or(*amount, |m| m + *amount));
                    transfer_exprs.push(format!(
                        "(match (ft-transfer? stackos u{amount} tx-sender 'SP000000000000000000002Q6VF78) v true e false)"
                    ));
                }
                TransferSpec::Nft(token_id) => {
                    nft_ids.insert(*token_id);
                    transfer_exprs.push(format!(
                        "(match (nft-transfer? stackaroo u{token_id} tx-sender 'SP000000000000000000002Q6VF78) v true e false)"
                    ));
                }
            }
        }

        let mut allowances: Vec<String> = Vec::new();
        if let Some(amount) = stx_allowance {
            allowances.push(format!("(with-stx u{amount})"));
        }
        if let Some(amount) = ft_allowance {
            allowances.push(format!("(with-ft current-contract \"stackos\" u{amount})"));
        }
        if !nft_ids.is_empty() {
            let ids = nft_ids
                .iter()
                .map(|id| format!("u{id}"))
                .collect::<Vec<_>>()
                .join(" ");
            allowances.push(format!(
                "(with-nft current-contract \"stackaroo\" (list {}))",
                ids
            ));
        }

        let allowances_snippet = format!("({})", allowances.join(" "));

        prop::collection::vec(
            clarity_values_no_response().prop_map(|v| value_to_clarity_literal(&v)),
            0..=8,
        )
        .prop_flat_map(move |extra_exprs| {
            let mut all = transfer_exprs.clone();
            all.extend(extra_exprs);
            Just(all).prop_shuffle().prop_map({
                let allowances_snippet = allowances_snippet.clone();
                move |shuffled| {
                    let body = shuffled.join(" ");
                    (allowances_snippet.clone(), body)
                }
            })
        })
    })
}

/// A strategy that generates `(begin ...)` expressions containing between
/// 1 and 8 expressions, each of which is either a Clarity value literal or
/// an STX transfer expression.
pub fn begin_block() -> impl Strategy<Value = String> {
    vec(
        prop_oneof![
            clarity_values_no_response().prop_map(|value| value_to_clarity_literal(&value)),
            try_response_snippets(stx_transfer_snippets()),
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
