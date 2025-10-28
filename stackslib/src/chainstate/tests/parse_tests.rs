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

use clarity::vm::ast::stack_depth_checker::AST_CALL_STACK_DEPTH_BUFFER;
use clarity::vm::MAX_CALL_STACK_DEPTH;
#[allow(unused_imports)]
use clarity_types::errors::ParseErrors; // Just used for documentation purpose
use crate::chainstate::tests::consensus::contract_deploy_consensus_test;

/// ParserError: [`ParseErrors::ExpressionStackDepthTooDeep`]
/// Caused by: nested contract body exceeding stack depth limit
/// Outcome: block rejected.
contract_deploy_consensus_test!(
    parse_error__stack_depth_too_deep,
    contract_name: "my-contract",
    contract_code: &{
        let count = AST_CALL_STACK_DEPTH_BUFFER + (MAX_CALL_STACK_DEPTH as u64);
        let body_start = "{ a : ".repeat(count as usize);
        let body_end = "} ".repeat(count as usize);
        format!("{body_start}u1 {body_end}")
    },
);

/// ParserError: [`ParseErrors::FailedParsingIntValue`]
/// Caused by: number bigger than i128
/// Outcome: block accepted.
contract_deploy_consensus_test!(
    parse_error__failed_parsing_int_value,
    contract_name: "my-contract",
    contract_code: &{"
        (define-data-var my-int int 340282366920938463463374607431768211455)   
    "},
);

/// ParserError [`ParseErrors::FailedParsingUIntValue`]
/// Caused by: number bigger than u128
/// Outcome: block accepted.
contract_deploy_consensus_test!(
    parse_error__failed_parsing_uint_value,
    contract_name: "my-contract",
    contract_code: &{"
        (define-data-var my-uint uint u999340282366920938463463374607431768211455)
    "},
);

/// ParserError [`ParseErrors::CircularReference`]
/// Caused by: interdependent functions
/// Outcome: block accepted.
contract_deploy_consensus_test!(
    parse_error__circular_reference,
    contract_name: "my-contract",
    contract_code: &{"
        (define-constant my-a my-b)
        (define-constant my-b my-a)
    "},
);

/// ParserError [`ParseErrors::NameAlreadyUsed`]
/// Caused by: trait name conflicts only
/// Outcome: block accepted.
contract_deploy_consensus_test!(
    parse_error__named_already_used,
    contract_name: "my-contract",
    contract_code: &{"
        (define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-trait trait-1 (
            (get-1 (int) (response uint uint)))) 
    "},
);

/// ParserError [`ParseErrors::TraitReferenceNotAllowed`]
/// Caused by: trait reference can not be stored
/// Outcome: block accepted.
contract_deploy_consensus_test!(
    parse_error__trait_ref_not_allowed,
    contract_name: "my-contract",
    contract_code: &{"
        (define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-map kv-store { key: uint } { value: <trait-1> }) 
    "},
);

/// ParserError [`ParseErrors::ImportTraitBadSignature`]
/// Caused by: trait import with bad signature (missing trait name or identifier)
/// Outcome: block accepted.
contract_deploy_consensus_test!(
    parse_error__import_trait_bad_signature,
    contract_name: "my-contract",
    contract_code: &{"
        (use-trait)   
    "},
);

/// ParserError [`ParseErrors::DefineTraitBadSignature`]
/// Caused by: trait define with bad signature (missing trait name or definition)
/// Outcome: block accepted.
contract_deploy_consensus_test!(
    parse_error__define_trait_bad_signature,
    contract_name: "my-contract",
    contract_code: &{"
        (define-trait)
    "},
);

/// ParserError [`ParseErrors::ImplTraitBadSignature`]
/// Caused by: trait implementation with bad signature (missing trait identifier)
/// Outcome: block accepted.
contract_deploy_consensus_test!(
    parse_error__impl_trait_bad_signature,
    contract_name: "my-contract",
    contract_code: &{"
        (impl-trait)
    "},
);

/// ParserError [`ParseErrors::TraitReferenceUnknown`]
/// Caused by: referencing an undeclared trait.
/// Outcome: block accepted.
contract_deploy_consensus_test!(
    parse_error__trait_reference_unknown,
    contract_name: "my-contract",
    contract_code: &{"
        (+ 1 <my-trait>) 
    "},
);

/// ParserError: [`ParseErrors::Lexer`]
/// Caused by: unknown symbol
/// Outcome: block accepted.
contract_deploy_consensus_test!(
    parse_error__lexer__unknown_symbol,
    contract_name: "my-contract",
    contract_code: &{"
        (define-data-var my-uint uint _)
    "},
);
