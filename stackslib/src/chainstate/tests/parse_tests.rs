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

use std::collections::HashMap;

use clarity::vm::ast::errors::ParseErrorKind;
use clarity::vm::ast::parser::v2::{max_nesting_depth, MAX_CONTRACT_NAME_LEN, MAX_STRING_LEN};
use clarity::vm::ast::stack_depth_checker::AST_CALL_STACK_DEPTH_BUFFER;
use clarity::vm::max_call_stack_depth_for_epoch;
use clarity::vm::types::MAX_VALUE_SIZE;
use stacks_common::types::StacksEpochId;

use crate::chainstate::tests::consensus::{
    clarity_versions_for_epoch, contract_deploy_consensus_test, ConsensusTest, ConsensusUtils,
    TestBlock, EPOCHS_TO_TEST,
};
use crate::core::BLOCK_LIMIT_MAINNET_21;

/// Generates a coverage classification report for a specific [`ParseErrorKind`] variant.
///
/// This method exists purely for **documentation and tracking purposes**.
/// It helps maintainers understand which error variants have been:
///
/// - ✅ **Tested** — verified through consensus tests.
/// - ⚙️ **Ignored** — not tested on purpose. (e.g. parser v1 errors).
/// - 🚫 **Unreachable** — not testable from consensus test side for reasons.
#[allow(dead_code)]
fn variant_coverage_report(variant: ParseErrorKind) {
    enum VariantCoverage {
        // Cannot occur through valid execution. The string is to explain the reason.
        Unreachable_Functionally(&'static str),
        // Unexpected error, that should never happen
        Unreachable_ExpectLike,
        // Defined but never used
        Unreachable_NotUsed,
        // Not tested on purpose. The string is to explain the reason.
        Ignored(&'static str),
        // Covered by consensus tests. The func lists is for to link the variant with the related tests
        Tested(Vec<fn()>),
    }

    use ParseErrorKind::*;
    use VariantCoverage::*;

    _ = match variant {
        // Costs
        CostOverflow => Unreachable_ExpectLike,
        CostBalanceExceeded(_, _) => Tested(vec![test_cost_balance_exceeded]),
        MemoryBalanceExceeded(_, _) => Unreachable_NotUsed,
        CostComputationFailed(_) => Unreachable_ExpectLike,
        ExecutionTimeExpired => Unreachable_NotUsed,

        TooManyExpressions => Unreachable_ExpectLike,
        ExpressionStackDepthTooDeep { .. } => Tested(vec![
            test_stack_depth_too_deep_case_2_list_only_parsing,
            test_stack_depth_too_deep_case_2_list_only_parsing,
            test_stack_depth_too_deep_case_3_list_only_checker,
        ]),
        VaryExpressionStackDepthTooDeep { .. } => Tested(vec![test_vary_stack_depth_too_deep_checker]),
        FailedParsingIntValue(_) => Tested(vec![test_failed_parsing_int_value]),
        CircularReference(_) => Tested(vec![test_circular_reference]),
        NameAlreadyUsed(_) => Tested(vec![test_named_already_used]),
        TraitReferenceNotAllowed => Tested(vec![test_trait_ref_not_allowed]),
        ImportTraitBadSignature => Tested(vec![test_import_trait_bad_signature]),
        DefineTraitBadSignature => Tested(vec![test_define_trait_bad_signature]),
        ImplTraitBadSignature => Tested(vec![test_impl_trait_bad_signature]),
        TraitReferenceUnknown(_) => Tested(vec![test_trait_reference_unknown]),
        Lexer(LexerError) => Tested(vec![test_lexer_unknown_symbol]),
        ContractNameTooLong(String) => Tested(vec![test_contract_name_too_long]),
        ExpectedClosing(Token) => Tested(vec![test_expected_closing]),
        ExpectedContractIdentifier => Tested(vec![test_expected_contract_identifier]),
        ExpectedTraitIdentifier => Tested(vec![test_expected_trait_identifier]),
        ExpectedWhitespace => Tested(vec![test_expected_white_space]),
        FailedParsingUIntValue(_) => Tested(vec![test_failed_parsing_uint_value]),
        IllegalTraitName(_) => Unreachable_Functionally("prevented by Lexer checks returning `Lexer` variant"),
        InvalidPrincipalLiteral => Tested(vec![test_invalid_principal_literal, principal_wrong_byte_length]),
        InvalidBuffer => Unreachable_Functionally("prevented by both Lexer checks, and StacksTransaction::consensus_serialize with MAX_TRANSACTION_LEN (panic)"),
        NameTooLong(_) => Tested(vec![test_name_too_long]),
        UnexpectedToken(_) => Tested(vec![test_unexpected_token]),
        TupleColonExpectedv2 => Tested(vec![test_tuple_colon_expected_v2]),
        TupleCommaExpectedv2 => Tested(vec![test_tuple_comma_expected_v2]),
        TupleValueExpected => Tested(vec![test_tuple_value_expected]),
        IllegalClarityName(_) => Unreachable_Functionally("prevented by Lexer checks returning `Lexer` variant"),
        IllegalASCIIString(_) => Tested(vec![test_illegal_ascii_string]),
        IllegalContractName(_) => Unreachable_Functionally("prevented by Lexer checks returning `Lexer` variant or Parser by MAX_CONTRACT_NAME_LEN returning `ContractNameTooLong` variant"),
        NoteToMatchThis(_) => Unreachable_Functionally("It is reachable, but only visible in diagnostic mode as it comes as a later diagnostic error"),
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
        | InvalidEscaping => Ignored("parser v1 is deprecated and maybe removed in the next future."),
    }
}

/// ParserError: [`ParseErrorKind::CostBalanceExceeded`]
/// Caused by: exceeding runtime cost limit [`BLOCK_LIMIT_MAINNET_21`] during contract deploy parsing
/// Outcome: block rejected
/// Note: This cost error is remapped as [`crate::chainstate::stacks::Error::CostOverflowError`]
#[test]
fn test_cost_balance_exceeded() {
    const RUNTIME_LIMIT: u64 = BLOCK_LIMIT_MAINNET_21.runtime;
    // Arbitrary parameters determined through empirical testing
    const CONTRACT_FUNC_INVOCATIONS: u64 = 29_022;
    const CALL_RUNTIME_COST: u64 = 249_996_284;
    const CALLS_NEEDED: u64 = RUNTIME_LIMIT / CALL_RUNTIME_COST - 1;

    let costly_contract_code = {
        let mut code = String::from(
            "(define-constant msg 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f)\n\
             (define-constant sig 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40)\n\
             (define-constant key 0xfffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0df)\n\
             (define-read-only (costly-func)\n  (begin\n",
        );
        for _ in 0..CONTRACT_FUNC_INVOCATIONS {
            code.push_str("    (secp256k1-verify msg sig key)\n");
        }
        code.push_str("    true))");
        code
    };

    let large_contract_code = &{
        let mut code = String::new();
        for i in 0..50_000u64 {
            code.push_str(&format!("(define-public (gen-fn-{i}) (ok {i}))\n", i = i));
        }
        code
    };

    let mut result = vec![];
    for each_epoch in EPOCHS_TO_TEST {
        for &each_clarity_ver in clarity_versions_for_epoch(*each_epoch) {
            let mut nonce = 0;
            let mut txs = vec![];

            // Create a contract that will be costly to execute
            txs.push(ConsensusUtils::new_deploy_tx(
                nonce,
                "costly-contract",
                &costly_contract_code,
                None,
            ));

            // Create contract calls that push the runtime cost to a considerably high value
            while nonce < CALLS_NEEDED {
                nonce += 1;
                txs.push(ConsensusUtils::new_call_tx(
                    nonce,
                    "costly-contract",
                    "costly-func",
                ));
            }

            // Create a large contract that push the runtime cost close to the limit
            nonce += 1;
            txs.push(ConsensusUtils::new_deploy_tx(
                nonce,
                "runtime-close",
                large_contract_code,
                None,
            ));

            // Create a large contract that exceeds the runtime cost limit during parsing
            // NOTE: This is the only transaction relevant for demonstrating the runtime cost exceeding the limit during parsing.
            //        Previous transactions are included only for test setup. Hence, clarity version is used here.
            nonce += 1;
            txs.push(ConsensusUtils::new_deploy_tx(
                nonce,
                "runtime-exceeded",
                large_contract_code,
                Some(each_clarity_ver),
            ));

            let block = TestBlock { transactions: txs };

            let epoch_blocks = HashMap::from([(*each_epoch, vec![block])]);

            let each_result = ConsensusTest::new(function_name!(), vec![], epoch_blocks).run();
            result.extend(each_result);
        }
    }

    insta::assert_ron_snapshot!(result);
}

/// ParserError: [`ParseErrorKind::ExpressionStackDepthTooDeep`]
/// Caused by: nested contract body exceeding stack depth limit on parsing tuples
/// Outcome: block rejected
#[test]
fn test_stack_depth_too_deep_case_1_tuple_only_parsing() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: &{
            // In parse v2, open brace '{' have a stack count of 2.
            let max_call_stack_depth = max_call_stack_depth_for_epoch(StacksEpochId::Epoch33);
            let count = max_nesting_depth(max_call_stack_depth) / 2 + 1;
            let body_start = "{ a : ".repeat(count as usize);
            let body_end = "} ".repeat(count as usize);
            format!("{body_start}u1 {body_end}")
        },
    );
}

/// ParserError: [`ParseErrorKind::ExpressionStackDepthTooDeep`]
/// Caused by: nested contract body exceeding stack depth limit on parsing lists
/// Outcome: block rejected
#[test]
fn test_stack_depth_too_deep_case_2_list_only_parsing() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: &{
            // In parse v2, open parenthesis '(' have a stack count of 1.
            let max_call_stack_depth = max_call_stack_depth_for_epoch(StacksEpochId::Epoch33);
            let count = max_nesting_depth(max_call_stack_depth);
            let body_start = "(list ".repeat(count as usize);
            let body_end = ")".repeat(count as usize);
            format!("{body_start}u1 {body_end}")
        },
    );
}

/// ParserError: [`ParseErrorKind::ExpressionStackDepthTooDeep`]
/// Caused by: nested contract body exceeding stack depth limit on checking lists ast
/// Outcome: block rejected
#[test]
fn test_stack_depth_too_deep_case_3_list_only_checker() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: &{
            // In parse v2, open parenthesis '(' have a stack count of 1.
            let max_call_stack_depth = max_call_stack_depth_for_epoch(StacksEpochId::Epoch33);
            let count = AST_CALL_STACK_DEPTH_BUFFER + max_call_stack_depth as u64;
            let body_start = "(list ".repeat(count as usize);
            let body_end = ")".repeat(count as usize);
            format!("{body_start}u1 {body_end}")
        },
    );
}

/// ParserError: [`ParseErrorKind::VaryExpressionStackDepthTooDeep`]
/// Caused by: nested contract body exceeding stack depth limit on checking vary list/tuple ast
/// Outcome: block rejected
#[test]
fn test_vary_stack_depth_too_deep_checker() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: &{
            let max_call_stack_depth = max_call_stack_depth_for_epoch(StacksEpochId::Epoch33);
            let count = AST_CALL_STACK_DEPTH_BUFFER + (max_call_stack_depth as u64) - 1;
            let body_start = "(list ".repeat(count as usize);
            let body_end = ")".repeat(count as usize);
            format!("{{ a: {body_start}u1 {body_end} }}")
        },
    );
}

/// ParserError: [`ParseErrorKind::ExpressionStackDepthTooDeep`]
/// Caused by: nested contract body exceeding stack depth limit on parsing tuples
/// Outcome: block rejected
#[test]
fn test_stack_depth_too_deep_case_1_tuple_only_parsing_latest_limit() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: &{
            // In parse v2, open brace '{' have a stack count of 2.
            let max_call_stack_depth = max_call_stack_depth_for_epoch(StacksEpochId::latest());
            let count = max_nesting_depth(max_call_stack_depth) / 2 + 1;
            let body_start = "{ a : ".repeat(count as usize);
            let body_end = "} ".repeat(count as usize);
            format!("{body_start}u1 {body_end}")
        },
    );
}

/// ParserError: [`ParseErrorKind::ExpressionStackDepthTooDeep`]
/// Caused by: nested contract body exceeding stack depth limit on parsing lists
/// Outcome: block rejected
#[test]
fn test_stack_depth_too_deep_case_2_list_only_parsing_latest_limit() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: &{
            // In parse v2, open parenthesis '(' have a stack count of 1.
            let max_call_stack_depth = max_call_stack_depth_for_epoch(StacksEpochId::latest());
            let count = max_nesting_depth(max_call_stack_depth);
            let body_start = "(list ".repeat(count as usize);
            let body_end = ")".repeat(count as usize);
            format!("{body_start}u1 {body_end}")
        },
    );
}

/// ParserError: [`ParseErrorKind::ExpressionStackDepthTooDeep`]
/// Caused by: nested contract body exceeding stack depth limit on checking lists ast
/// Outcome: block rejected
#[test]
fn test_stack_depth_too_deep_case_3_list_only_checker_latest_limit() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: &{
            // In parse v2, open parenthesis '(' have a stack count of 1.
            let max_call_stack_depth = max_call_stack_depth_for_epoch(StacksEpochId::latest());
            let count = AST_CALL_STACK_DEPTH_BUFFER + max_call_stack_depth as u64;
            let body_start = "(list ".repeat(count as usize);
            let body_end = ")".repeat(count as usize);
            format!("{body_start}u1 {body_end}")
        },
    );
}

/// ParserError: [`ParseErrorKind::VaryExpressionStackDepthTooDeep`]
/// Caused by: nested contract body exceeding stack depth limit on checking vary list/tuple ast
/// Outcome: block rejected
#[test]
fn test_vary_stack_depth_too_deep_checker_latest_limit() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: &{
            let max_call_stack_depth = max_call_stack_depth_for_epoch(StacksEpochId::latest());
            let count = AST_CALL_STACK_DEPTH_BUFFER + (max_call_stack_depth as u64) - 1;
            let body_start = "(list ".repeat(count as usize);
            let body_end = ")".repeat(count as usize);
            format!("{{ a: {body_start}u1 {body_end} }}")
        },
    );
}

/// ParserError: [`ParseErrorKind::FailedParsingIntValue`]
/// Caused by: number bigger than i128
/// Outcome: block accepted
#[test]
fn test_failed_parsing_int_value() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: "(define-data-var my-int int 340282366920938463463374607431768211455)",
    );
}

/// ParserError [`ParseErrorKind::FailedParsingUIntValue`]
/// Caused by: number bigger than u128
/// Outcome: block accepted
#[test]
fn test_failed_parsing_uint_value() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: "(define-data-var my-uint uint u999340282366920938463463374607431768211455)",
    );
}

/// ParserError [`ParseErrorKind::CircularReference`]
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

/// ParserError [`ParseErrorKind::NameAlreadyUsed`]
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

/// ParserError [`ParseErrorKind::TraitReferenceNotAllowed`]
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

/// ParserError [`ParseErrorKind::ImportTraitBadSignature`]
/// Caused by: trait import with bad signature (missing trait name or identifier)
/// Outcome: block accepted
#[test]
fn test_import_trait_bad_signature() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: "(use-trait)",
    );
}

/// ParserError [`ParseErrorKind::DefineTraitBadSignature`]
/// Caused by: trait define with bad signature (missing trait name or definition)
/// Outcome: block accepted
#[test]
fn test_define_trait_bad_signature() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: "(define-trait)",
    );
}

/// ParserError [`ParseErrorKind::ImplTraitBadSignature`]
/// Caused by: trait implementation with bad signature (missing trait identifier)
/// Outcome: block accepted
#[test]
fn test_impl_trait_bad_signature() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: "(impl-trait)",
    );
}

/// ParserError [`ParseErrorKind::TraitReferenceUnknown`]
/// Caused by: referencing an undeclared trait
/// Outcome: block accepted
#[test]
fn test_trait_reference_unknown() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: "(+ 1 <my-trait>)",
    );
}

/// ParserError: [`ParseErrorKind::Lexer`]
/// Caused by: unknown symbol
/// Outcome: block accepted
#[test]
fn test_lexer_unknown_symbol() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: "(define-data-var my-uint uint _)",
    );
}

/// ParserError: [`ParseErrorKind::ExpectedClosing`]
/// Caused by: missing closing parenthesis
/// Outcome: block accepted
#[test]
fn test_expected_closing() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: "(",
    );
}

/// ParserError: [`ParseErrorKind::ExpectedWhitespace`]
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

/// ParserError: [`ParseErrorKind::UnexpectedToken`]
/// Caused by: unexpected token in the expression (rightest paranthesis)
/// Outcome: block accepted
#[test]
fn test_unexpected_token() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: "(define-public (get-one) (ok u1)) )",
    );
}

/// ParserError: [`ParseErrorKind::NameTooLong`]
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

/// ParserError: [`ParseErrorKind::InvalidPrincipalLiteral`]
/// Caused by: valid principal chars but wrong format (due to the starting "AAA")
/// Outcome: block accepted
#[test]
fn test_invalid_principal_literal() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: "(define-constant my-principal 'AAAST3J2GVMMM2R07ZFBJDWTYEYAR8FZH5WKDTFJ9AHA)",
    );
}

/// ParserError: [`ParseErrorKind::InvalidPrincipalLiteral`]
/// Caused by: invalid standard principal literal (wrong byte length)
/// Outcome: block accepted.
#[test]
fn principal_wrong_byte_length() {
    contract_deploy_consensus_test!(
        contract_name: "wrong-byte-length",
        contract_code: "
;; This literal decodes via c32 but has the wrong byte length
(define-constant my-principal 'S162RK3CHJPCSSK6BM757FW)",
    );
}

/// ParserError: [`ParseErrorKind::ExpectedContractIdentifier`]
/// Caused by: missing name in contract identifier (nothing after the dot '.')
/// Outcome: block accepted
#[test]
fn test_expected_contract_identifier() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: "(define-constant my-contract-id 'ST3J2GVMMM2R07ZFBJDWTYEYAR8FZH5WKDTFJ9AHA.)",
    );
}

/// ParserError: [`ParseErrorKind::ExpectedTraitIdentifier`]
/// Caused by: missing name in trait identifier (nothing after the dot '.')
/// Outcome: block accepted
#[test]
fn test_expected_trait_identifier() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: "(define-constant my-trait-id 'ST3J2GVMMM2R07ZFBJDWTYEYAR8FZH5WKDTFJ9AHA.contract.)",
    );
}

/// ParserError: [`ParseErrorKind::TupleColonExpectedv2`]
/// Caused by: missing colon between field name and value in tuple definition
/// Outcome: block accepted
#[test]
fn test_tuple_colon_expected_v2() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: "{ a 1 }",
    );
}

/// ParserError: [`ParseErrorKind::TupleCommaExpectedv2`]
/// Caused by: missing comma between fields in tuple definition
/// Outcome: block accepted
#[test]
fn test_tuple_comma_expected_v2() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: "{ a : 1  b : 2 }",
    );
}

/// ParserError: [`ParseErrorKind::TupleValueExpected`]
/// Caused by: missing value for field in tuple definition
/// Outcome: block accepted
#[test]
fn test_tuple_value_expected() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: "{ a : ",
    );
}

/// ParserError: [`ParseErrorKind::ContractNameTooLong`]
/// Caused by: contract name longer than [`MAX_CONTRACT_NAME_LEN`]
/// Outcome: block accepted
#[test]
fn test_contract_name_too_long() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: &{
            let name = "a".repeat(MAX_CONTRACT_NAME_LEN + 1);
            format!("(define-constant my-contract-id 'ST3J2GVMMM2R07ZFBJDWTYEYAR8FZH5WKDTFJ9AHA.{name})")
        },
    );
}

/// ParserError: [`ParseErrorKind::IllegalASCIIString`]
/// Caused by: string longer than [`MAX_VALUE_SIZE`]
/// Outcome: block accepted
#[test]
fn test_illegal_ascii_string() {
    contract_deploy_consensus_test!(
        contract_name: "my-contract",
        contract_code: &{
            let string = "a".repeat(MAX_VALUE_SIZE as usize + 1);
            format!("(define-constant my-str \"{string}\")")
        },
    );
}
