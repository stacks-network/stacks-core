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

//! This module contains consensus tests related to Clarity Parse errors.

use clarity::vm::ast::errors::ParseErrors;
use clarity::vm::ast::parser::v2::{MAX_NESTING_DEPTH, MAX_STRING_LEN};
use clarity::vm::ast::stack_depth_checker::AST_CALL_STACK_DEPTH_BUFFER;
use clarity::vm::MAX_CALL_STACK_DEPTH;

use crate::chainstate::tests::consensus::contract_deploy_consensus_test;

/// ParserError: [`ParseErrors::ExpressionStackDepthTooDeep`]
/// Caused by: nested contract body exceeding stack depth limit on parsing tuples
/// Outcome: block rejected
#[test]
fn test_stack_depth_too_deep_case_1_tuple_only_parsing() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: &{
            // In parse v2, open brace '{' have a stack count of 2.
            let count = MAX_NESTING_DEPTH / 2 + 1;
            let body_start = "{ a : ".repeat(count as usize);
            let body_end = "} ".repeat(count as usize);
            format!("{body_start}u1 {body_end}")
        },
    );
}

/// ParserError: [`ParseErrors::ExpressionStackDepthTooDeep`]
/// Caused by: nested contract body exceeding stack depth limit on parsing lists
/// Outcome: block rejected
#[test]
fn test_stack_depth_too_deep_case_2_list_only_parsing() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: &{
            // In parse v2, open parent '(' have a stack count of 1.
            let count = MAX_NESTING_DEPTH;
            let body_start = "(list ".repeat(count as usize);
            let body_end = ")".repeat(count as usize);
            format!("{body_start}u1 {body_end}")
        },
    );
}

/// ParserError: [`ParseErrors::ExpressionStackDepthTooDeep`]
/// Caused by: nested contract body exceeding stack depth limit on checking lists ast
/// Outcome: block rejected
#[test]
fn test_stack_depth_too_deep_case_3_list_only_checker() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: &{
            // In parse v2, open parent '(' have a stack count of 1.
            let count = AST_CALL_STACK_DEPTH_BUFFER + MAX_CALL_STACK_DEPTH as u64;
            let body_start = "(list ".repeat(count as usize);
            let body_end = ")".repeat(count as usize);
            format!("{body_start}u1 {body_end}")
        },
    );
}

/// ParserError: [`ParseErrors::VaryExpressionStackDepthTooDeep`]
/// Caused by: nested contract body exceeding stack depth limit on checking vary list/tuple ast
/// Outcome: block rejected
#[test]
fn test_vary_stack_depth_too_deep_checker() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: &{
            let count = AST_CALL_STACK_DEPTH_BUFFER + (MAX_CALL_STACK_DEPTH as u64) - 1;
            let body_start = "(list ".repeat(count as usize);
            let body_end = ")".repeat(count as usize);
            format!("{{ a: {body_start}u1 {body_end} }}")
        },
    );
}

/// ParserError: [`ParseErrors::FailedParsingIntValue`]
/// Caused by: number bigger than i128
/// Outcome: block accepted
#[test]
fn test_failed_parsing_int_value() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: "(define-data-var my-int int 340282366920938463463374607431768211455)",
    );
}

/// ParserError [`ParseErrors::FailedParsingUIntValue`]
/// Caused by: number bigger than u128
/// Outcome: block accepted
#[test]
fn test_failed_parsing_uint_value() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: "(define-data-var my-uint uint u999340282366920938463463374607431768211455)",
    );
}

/// ParserError [`ParseErrors::CircularReference`]
/// Caused by: interdependent functions
/// Outcome: block accepted
#[test]
fn test_circular_reference() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: "
            (define-constant my-a my-b)
            (define-constant my-b my-a)
        ",
    );
}

/// ParserError [`ParseErrors::NameAlreadyUsed`]
/// Caused by: trait name conflicts only
/// Outcome: block accepted
#[test]
fn test_named_already_used() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: "
            (define-trait trait-1 (
                (get-1 (uint) (response uint uint))))
            (define-trait trait-1 (
                (get-1 (int) (response uint uint)))) 
        ",
    );
}

/// ParserError [`ParseErrors::TraitReferenceNotAllowed`]
/// Caused by: trait reference can not be stored
/// Outcome: block accepted
#[test]
fn test_trait_ref_not_allowed() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: "
            (define-trait trait-1 (
                (get-1 (uint) (response uint uint))))
            (define-map kv-store { key: uint } { value: <trait-1> }) 
        ",
    );
}

/// ParserError [`ParseErrors::ImportTraitBadSignature`]
/// Caused by: trait import with bad signature (missing trait name or identifier)
/// Outcome: block accepted
#[test]
fn test_import_trait_bad_signature() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: "(use-trait)",
    );
}

/// ParserError [`ParseErrors::DefineTraitBadSignature`]
/// Caused by: trait define with bad signature (missing trait name or definition)
/// Outcome: block accepted
#[test]
fn test_define_trait_bad_signature() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: "(define-trait)",
    );
}

/// ParserError [`ParseErrors::ImplTraitBadSignature`]
/// Caused by: trait implementation with bad signature (missing trait identifier)
/// Outcome: block accepted
#[test]
fn test_impl_trait_bad_signature() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: "(impl-trait)",
    );
}

/// ParserError [`ParseErrors::TraitReferenceUnknown`]
/// Caused by: referencing an undeclared trait
/// Outcome: block accepted
#[test]
fn test_trait_reference_unknown() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: "(+ 1 <my-trait>)",
    );
}

/// ParserError: [`ParseErrors::Lexer`]
/// Caused by: unknown symbol
/// Outcome: block accepted
#[test]
fn test_lexer_unknown_symbol() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: "(define-data-var my-uint uint _)",
    );
}

/// ParserError: [`ParseErrors::ExpectedClosing`]
/// Caused by: missing closing parenthesis
/// Outcome: block accepted
#[test]
fn test_expected_closing() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: "(",
    );
}

/// ParserError: [`ParseErrors::NoteToMatchThis`]
/// Caused by: missing open parenthesis matching the close one
/// Outcome: block accepted
#[test]
fn test_note_to_match_this() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: "())",
    );
}

/// ParserError: [`ParseErrors::ExpectedWhitespace`]
/// Caused by: missing space before expression
/// Outcome: block accepted
#[test]
fn test_expected_white_space() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        //miss space between (get-one) and (ok u1)
        contract_code: "(define-public (get-one)(ok u1))",
    );
}

/// ParserError: [`ParseErrors::UnexpectedToken`]
/// Caused by: unexpected token in the expression (rightest paranthesis)
/// Outcome: block accepted
#[test]
fn test_unexpected_token() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: "(define-public (get-one) (ok u1)) )",
    );
}

/// ParserError: [`ParseErrors::NameTooLong`]
/// Caused by: identifier longer than [`MAX_STRING_LEN`]
/// Outcome: block accepted
#[test]
fn test_name_too_long() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: &{
            let name = "n".repeat(MAX_STRING_LEN + 1);
            format!("(define-public ({name}) (ok u1))")
        },
    );
}

fn variant_coverage_report(variant: ParseErrors) {
    enum VariantCoverage {
        Unreachable_Functionally,
        Unreachable_ExpectLike,
        Unreachable_NotUsed,
        Skipped,
        Tested,

        TODO,
    }

    use ParseErrors::*;
    use VariantCoverage::*;

    _ = match variant {
        // Costs
        CostOverflow => Unreachable_ExpectLike,
        CostBalanceExceeded(_, _) => Unreachable_Functionally,
        MemoryBalanceExceeded(_, _) => Unreachable_NotUsed,
        CostComputationFailed(_) => Unreachable_ExpectLike,
        ExecutionTimeExpired => Unreachable_NotUsed, // To re-check

        TooManyExpressions => Unreachable_ExpectLike,
        ExpressionStackDepthTooDeep => Tested,
        VaryExpressionStackDepthTooDeep => Tested,
        FailedParsingIntValue(_) => Tested,
        CircularReference(_) => Tested,
        NameAlreadyUsed(_) => Tested,
        TraitReferenceNotAllowed => Tested,
        ImportTraitBadSignature => Tested,
        DefineTraitBadSignature => Tested,
        ImplTraitBadSignature => Tested,
        TraitReferenceUnknown(_) => Tested,

        Lexer(LexerError) => Tested,
        ContractNameTooLong(String) => Unreachable_Functionally,
        ExpectedClosing(Token) => Tested,
        ExpectedContractIdentifier => TODO,
        ExpectedTraitIdentifier => TODO,
        ExpectedWhitespace => Tested,
        FailedParsingUIntValue(_) => Tested,
        IllegalTraitName(_) => TODO,
        InvalidPrincipalLiteral => TODO,
        InvalidBuffer => TODO,
        NameTooLong(_) => Tested,
        UnexpectedToken(_) => Tested,
        TupleColonExpectedv2 => TODO,
        TupleCommaExpectedv2 => TODO,
        TupleValueExpected => TODO,
        IllegalClarityName(_) => TODO,
        IllegalASCIIString(_) => TODO,
        IllegalContractName(_) => TODO,
        NoteToMatchThis(_) => Tested,
        UnexpectedParserFailure => Unreachable_ExpectLike,
        InterpreterFailure => Unreachable_ExpectLike, // currently cause block rejection

        // V1
        FailedCapturingInput
        | SeparatorExpected(_)
        | SeparatorExpectedAfterColon(_)
        | ProgramTooLarge
        | IllegalVariableName(_)
        | FailedParsingBuffer(_)
        | FailedParsingHexValue(_, _)
        | FailedParsingPrincipal(_)
        | FailedParsingField(_)
        | FailedParsingRemainder(_)
        | ClosingParenthesisUnexpected
        | ClosingParenthesisExpected
        | ClosingTupleLiteralUnexpected
        | ClosingTupleLiteralExpected
        | TupleColonExpected(_)
        | TupleCommaExpected(_)
        | TupleItemExpected(_)
        | CommaSeparatorUnexpected
        | ColonSeparatorUnexpected
        | InvalidCharactersDetected
        | InvalidEscaping => Skipped, //parser v1 should be removed?!
    }
}
