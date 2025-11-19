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

//! This module contains consensus tests related to Clarity StaticCheckErrorKind errors that happens during contract analysis.

use std::collections::HashMap;

use clarity::codec::StacksMessageCodec as _;
use clarity::consts::CHAIN_ID_TESTNET;
use clarity::types::StacksEpochId;
use clarity::vm::analysis::type_checker::v2_1::{MAX_FUNCTION_PARAMETERS, MAX_TRAIT_METHODS};
#[allow(unused_imports)]
use clarity::vm::analysis::StaticCheckErrorKind;
use clarity::vm::types::MAX_TYPE_DEPTH;

use crate::chainstate::stacks::StacksTransaction;
use crate::chainstate::tests::consensus::{
    clarity_versions_for_epoch, contract_deploy_consensus_test, ConsensusTest, TestBlock,
    EPOCHS_TO_TEST, FAUCET_PRIV_KEY,
};
use crate::core::test_util::make_contract_publish_versioned;
use crate::core::BLOCK_LIMIT_MAINNET_21;
use crate::util_lib::boot::boot_code_test_addr;

/// StaticCheckErrorKind: [`StaticCheckErrorKind::CostBalanceExceeded`]
/// Caused by: exceeding the static-read analysis budget during contract deployment.
/// The contract repeatedly performs static-dispatch `contract-call?` lookups against the boot
/// `.costs-3` contract, forcing the type checker to fetch the remote function signature enough
/// times to surpass the read-count limit in [`BLOCK_LIMIT_MAINNET_21`].
/// Outcome: block rejected.
/// Note: Takes a couple of minutes to run!
#[ignore]
#[test]
fn static_check_error_cost_balance_exceeded() {
    contract_deploy_consensus_test!(
        contract_name: "cost-balance-exceeded",
        contract_code: &{
            let boot_addr = boot_code_test_addr();
            let mut contract = String::from("(define-read-only (trigger)\n  (begin\n");
            let call_count = BLOCK_LIMIT_MAINNET_21.read_count as usize + 1;
            let call_line = format!(
                "(contract-call? '{boot_addr}.costs-3 cost_analysis_type_check u0)\n",
            );
            for _ in 0..call_count {
                contract.push_str(&call_line);
            }
            contract.push_str("true))");
            contract
        },
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::ValueTooLarge`]
/// Caused by: Value exceeds the maximum allowed size for type-checking
/// Outcome: block accepted.
#[test]
fn static_check_error_value_too_large() {
    contract_deploy_consensus_test!(
        contract_name: "value-too-large",
        contract_code: "(as-max-len? 0x01 u1048577)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::ValueOutOfBounds`]
/// Caused by: Value is outside the acceptable range for its type
/// Outcome: block accepted.
#[test]
fn static_check_error_value_out_of_bounds() {
    contract_deploy_consensus_test!(
    contract_name: "value-out-of-bounds",
    contract_code: "(define-private (func (x (buff -12))) (len x))
        (func 0x00)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::ExpectedName`]
/// Caused by: Expected a name (e.g., variable) but found an different expression.
/// Outcome: block accepted.
#[test]
fn static_check_error_expected_name() {
    contract_deploy_consensus_test!(
        contract_name: "expected-name",
        contract_code: "(match (some 1) 2 (+ 1 1) (+ 3 4))",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::ExpectedResponseType`]
/// Caused by: Expected a response type but found a different type.
/// Outcome: block accepted.
#[test]
fn static_check_error_expected_response_type() {
    contract_deploy_consensus_test!(
        contract_name: "expected-response-type",
        contract_code: "(unwrap-err! (some 2) 2)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::CouldNotDetermineResponseOkType`]
/// Caused by: `unwrap!` on literal `(err 3)` leaves the response `ok` type unknown.
/// Outcome: block accepted.
#[test]
fn static_check_error_could_not_determine_response_ok_type() {
    contract_deploy_consensus_test!(
        contract_name: "could-not-determine",
        contract_code: "(unwrap! (err 3) 2)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::CouldNotDetermineResponseErrType`]
/// Caused by: `unwrap-err-panic` on `(ok 3)` gives no way to infer the response `err` type.
/// Outcome: block accepted.
#[test]
fn static_check_error_could_not_determine_response_err_type() {
    contract_deploy_consensus_test!(
        contract_name: "could-not-determine",
        contract_code: "(unwrap-err-panic (ok 3))",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::CouldNotDetermineMatchTypes`]
/// Caused by: matching a bare `none` provides no option type, leaving branch types ambiguous.
/// Outcome: block accepted.
#[test]
fn static_check_error_could_not_determine_match_types() {
    contract_deploy_consensus_test!(
        contract_name: "could-not-determine",
        contract_code: "(match none inner-value (/ 1 0) (+ 1 8))",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::MatchArmsMustMatch`]
/// Caused by: the `some` arm yields an int while the `none` arm yields a bool.
/// Outcome: block accepted.
#[test]
fn static_check_error_match_arms_must_match() {
    contract_deploy_consensus_test!(
        contract_name: "match-arms-must-match",
        contract_code: "(match (some 1) inner-value (+ 1 inner-value) (> 1 28))",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::BadMatchOptionSyntax`]
/// Caused by: option `match` expecting 4 arguments, got 3
/// Outcome: block accepted.
#[test]
fn static_check_error_bad_match_option_syntax() {
    contract_deploy_consensus_test!(
        contract_name: "bad-match-option",
        contract_code: "(match (some 1) inner-value (+ 1 inner-value))",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::BadMatchResponseSyntax`]
/// Caused by: response `match` expecting 5 arguments, got 3.
/// Outcome: block accepted.
#[test]
fn static_check_error_bad_match_response_syntax() {
    contract_deploy_consensus_test!(
        contract_name: "bad-match-response",
        contract_code: "(match (ok 1) inner-value (+ 1 inner-value))",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::RequiresAtLeastArguments`]
/// Caused by: invoking `match` with no arguments.
/// Outcome: block accepted.
#[test]
fn static_check_error_requires_at_least_arguments() {
    contract_deploy_consensus_test!(
        contract_name: "requires-at-least",
        contract_code: "(match)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::RequiresAtMostArguments`]
/// Caused by: `principal-construct?` is called with too many arguments.
/// Outcome: block accepted.
#[test]
fn static_check_error_requires_at_most_arguments() {
    contract_deploy_consensus_test!(
        contract_name: "requires-at-most",
        contract_code: r#"(principal-construct? 0x22 0xfa6bf38ed557fe417333710d6033e9419391a320 "foo" "bar")"#,
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::BadMatchInput`]
/// Caused by: `match` input is the integer `1`, not an option or response.
/// Outcome: block accepted.
#[test]
fn static_check_error_bad_match_input() {
    contract_deploy_consensus_test!(
        contract_name: "bad-match-input",
        contract_code: "(match 1 ok-val (/ ok-val 0) err-val (+ err-val 7))",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::ExpectedOptionalType`]
/// Caused by: `default-to` second argument `5` is not an optional value.
/// Outcome: block accepted.
#[test]
fn static_check_error_expected_optional_type() {
    contract_deploy_consensus_test!(
        contract_name: "expected-optional-type",
        contract_code: "(default-to 3 5)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::NameAlreadyUsed`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_name_already_used() {
    contract_deploy_consensus_test!(
        contract_name: "name-already-used",
        contract_code: "
        (define-constant foo 10)
        (define-constant foo 20)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::ReturnTypesMustMatch`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_return_types_must_match() {
    contract_deploy_consensus_test!(
        contract_name: "return-types-must",
        contract_code: "
        (define-map tokens { id: int } { balance: int })
        (define-private (my-get-token-balance)
            (let ((balance (unwrap!
                              (get balance (map-get? tokens (tuple (id 0))))
                              (err 1))))
              (err false)))",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::TypeError`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_type_error() {
    contract_deploy_consensus_test!(
        contract_name: "type-error",
        contract_code: "(define-data-var cursor int true)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::DefineVariableBadSignature`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_define_variable_bad_signature() {
    contract_deploy_consensus_test!(
        contract_name: "define-variable-bad",
        contract_code: "(define-data-var cursor 0x00)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::InvalidTypeDescription`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_invalid_type_description() {
    contract_deploy_consensus_test!(
        contract_name: "invalid-type-desc",
        contract_code: "(define-data-var cursor 0x00 true)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::TypeSignatureTooDeep`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_type_signature_too_deep() {
    contract_deploy_consensus_test!(
        contract_name: "signature-too-deep",
        contract_code: &{
            let depth: usize = MAX_TYPE_DEPTH as usize + 1;
            let mut s = String::from("(define-public (f (x ");
            for _ in 0..depth {
                s.push_str("(optional ");
            }
            s.push_str("uint");
            for _ in 0..depth {
                s.push_str(") ");
            }
            s.push_str(")) (ok x))");
            s
        },
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::SupertypeTooLarge`]
// Caused by:
// Outcome: block rejected.
#[test]
fn static_check_error_supertype_too_large() {
    contract_deploy_consensus_test!(
        contract_name: "supertype-too-large",
        contract_code: "
        (define-data-var big (buff 600000) 0x00)
        (define-data-var small (buff 10) 0x00)
        (define-public (trigger)
            (let ((initial (list (tuple (a (var-get big)) (b (var-get small))))))
                (ok (append initial (tuple (a (var-get small)) (b (var-get big)))))))",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::ConstructedListTooLarge`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_constructed_list_too_large() {
    contract_deploy_consensus_test!(
        contract_name: "constructed-list-large",
        contract_code: "
        (define-data-var ints (list 65535 int) (list 0))
        (define-public (trigger)
            (let ((mapped (map sha512 (var-get ints))))
                (ok mapped)
            )
        )",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::UnknownTypeName`]
// Caused by:
// Outcome: block accepted.
// Note: during analysis, this error can only be triggered by `from-consensus-buff?`
//       which is only available in Clarity 2 and later. So Clarity 1 will not trigger
//       this error.
#[test]
fn static_check_error_unknown_type_name() {
    contract_deploy_consensus_test!(
        contract_name: "unknown-type-name",
        contract_code: "
        (define-public (trigger)
            (ok (from-consensus-buff? foo 0x00)))",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::UnionTypeError`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_union_type_error() {
    contract_deploy_consensus_test!(
        contract_name: "union-type-error",
        contract_code: "(map - (list true false true false))",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::UndefinedVariable`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_undefined_variable() {
    contract_deploy_consensus_test!(
        contract_name: "undefined-variable",
        contract_code: "(+ x y z)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::BadMapTypeDefinition`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_bad_map_type_definition() {
    contract_deploy_consensus_test!(
        contract_name: "bad-map-type",
        contract_code: "(define-map lists { name: int } contents)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::CouldNotDetermineType`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_could_not_determine_type() {
    contract_deploy_consensus_test!(
        contract_name: "could-not-determine",
        contract_code: "(index-of (list) none)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::ExpectedSequence`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_expected_sequence() {
    contract_deploy_consensus_test!(
        contract_name: "expected-sequence",
        contract_code: r#"(index-of 3 "a")"#,
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::CouldNotDetermineSerializationType`]
// Caused by:
// Outcome: block accepted.
// Note: during analysis, this error can only be triggered by `from-consensus-buff?`
//       which is only available in Clarity 2 and later. So Clarity 1 will not trigger
//       this error.
#[test]
fn static_check_error_could_not_determine_serialization_type() {
    contract_deploy_consensus_test!(
        contract_name: "serialization-type",
        contract_code: "
        (define-trait trait-a ((ping () (response bool bool))))
        (define-trait trait-b ((pong () (response bool bool))))
        (define-public (trigger (first <trait-a>) (second <trait-b>))
            (ok (to-consensus-buff? (list first second))))",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::UncheckedIntermediaryResponses`]
// Caused by: Intermediate `(ok ...)` expressions inside a `begin` block that are not unwrapped.
// Outcome: block accepted.
#[test]
fn static_check_error_unchecked_intermediary_responses() {
    contract_deploy_consensus_test!(
        contract_name: "unchecked-resp",
        contract_code: "
        (define-public (trigger)
            (begin
                (ok true)
                (ok true)))",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::NoSuchFT`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_no_such_ft() {
    contract_deploy_consensus_test!(
        contract_name: "no-such-ft",
        contract_code: "(ft-get-balance stackoos tx-sender)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::NoSuchNFT`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_no_such_nft() {
    contract_deploy_consensus_test!(
        contract_name: "no-such-nft",
        contract_code: r#"(nft-get-owner? stackoos "abc")"#,
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::DefineNFTBadSignature`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_define_nft_bad_signature() {
    contract_deploy_consensus_test!(
        contract_name: "nft-bad-signature",
        contract_code: "(define-non-fungible-token stackaroos integer)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::BadTokenName`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_bad_token_name() {
    contract_deploy_consensus_test!(
        contract_name: "bad-token-name",
        contract_code: "(ft-get-balance u1234 tx-sender)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::EmptyTuplesNotAllowed`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_empty_tuples_not_allowed() {
    contract_deploy_consensus_test!(
        contract_name: "empty-tuples-not",
        contract_code: "
        (define-private (set-cursor (value (tuple)))
            value)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::NoSuchDataVariable`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_no_such_data_variable() {
    contract_deploy_consensus_test!(
        contract_name: "no-such-data-var",
        contract_code: "
        (define-private (get-cursor)
            (unwrap! (var-get cursor) 0))",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::NonFunctionApplication`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_non_function_application() {
    contract_deploy_consensus_test!(
        contract_name: "non-function-appl",
        contract_code: "((lambda (x y) 1) 2 1)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::ExpectedListApplication`]
// Caused by: calling append with lhs that is not a list.
// Outcome: block accepted.
#[test]
fn static_check_error_expected_list_application() {
    contract_deploy_consensus_test!(
        contract_name: "expected-list-appl",
        contract_code: "(append 2 3)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::NoSuchContract`]
// Caused by: calling contract-call? with a non-existent contract name.
// Outcome: block accepted.
#[test]
fn static_check_error_no_such_contract() {
    contract_deploy_consensus_test!(
        contract_name: "no-such-contract",
        contract_code: "(contract-call? 'S1G2081040G2081040G2081040G208105NK8PE5.contract-name test! u1)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::ContractCallExpectName`]
// Caused by: calling contract-call? without a contract function name.
// Outcome: block accepted.
#[test]
fn static_check_error_contract_call_expect_name() {
    contract_deploy_consensus_test!(
        contract_name: "ccall-expect-name",
        contract_code: "(contract-call? 'S1G2081040G2081040G2081040G208105NK8PE5.contract-name u1)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::ExpectedCallableType`]
// Caused by: passing a non-callable constant as the contract principal in `contract-call?`.
// Outcome: block accepted.
// Note: This error was added in Clarity 2. Clarity 1 will trigger a [`StaticCheckErrorKind::TraitReferenceUnknown`].
#[test]
fn static_check_error_expected_callable_type() {
    contract_deploy_consensus_test!(
        contract_name: "exp-callable-type",
        contract_code: "
        (define-constant bad-contract u1)
        (contract-call? bad-contract call-me)
    ",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::NoSuchPublicFunction`]
// Caused by: calling a non-existent public or read-only function on a contract literal.
// Outcome: block accepted.
#[test]
fn static_check_error_no_such_public_function() {
    contract_deploy_consensus_test!(
        contract_name: "no-such-pub-func-lit",
        // using the pox-4 contract as we know it exists!
        contract_code: &format!("(contract-call? '{}.pox-4 missing-func)", boot_code_test_addr()),
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::DefaultTypesMustMatch`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_default_types_must_match() {
    contract_deploy_consensus_test!(
        contract_name: "default-types-must",
        contract_code: "
        (define-map tokens { id: int } { balance: int })
        (default-to false (get balance (map-get? tokens (tuple (id 0)))))",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::IfArmsMustMatch`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_if_arms_must_match() {
    contract_deploy_consensus_test!(
        contract_name: "if-arms-must-match",
        contract_code: "(if true true 1)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::IllegalOrUnknownFunctionApplication`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_illegal_or_unknown_function_application() {
    contract_deploy_consensus_test!(
        contract_name: "illegal-or-unknown",
        contract_code: "(map if (list 1 2 3 4 5))",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::UnknownFunction`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_unknown_function() {
    contract_deploy_consensus_test!(
        contract_name: "unknown-function",
        contract_code: "(ynot 1 2)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::IncorrectArgumentCount`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_incorrect_argument_count() {
    contract_deploy_consensus_test!(
        contract_name: "incorrect-arg-count",
        contract_code: "(len (list 1) (list 1))",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::BadLetSyntax`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_bad_let_syntax() {
    contract_deploy_consensus_test!(
        contract_name: "bad-let-syntax",
        contract_code: "(let 1 2)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::BadSyntaxBinding`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_bad_syntax_binding() {
    contract_deploy_consensus_test!(
        contract_name: "bad-syntax-binding",
        contract_code: "(let ((1)) (+ 1 2))",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::ExpectedOptionalOrResponseType`]
// Caused by: expected an optional or response type, but got a value
// Outcome: block accepted.
#[test]
fn static_check_error_expected_optional_or_response_type() {
    contract_deploy_consensus_test!(
        contract_name: "exp-opt-or-res",
        contract_code: "(try! 3)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::DefineTraitBadSignature`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_define_trait_bad_signature() {
    contract_deploy_consensus_test!(
        contract_name: "def-trait-bad-sign",
        contract_code: "(define-trait trait-1 ((get-1 uint uint)))",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::DefineTraitDuplicateMethod`]
// Caused by: trait definition contains duplicate method names
// Outcome: block accepted.
// Note: This error was added in Clarity 2. Clarity 1 will accept the contract.
#[test]
fn static_check_error_define_trait_duplicate_method() {
    contract_deploy_consensus_test!(
        contract_name: "def-trait-dup-method",
        contract_code: "
        (define-trait double-method (
            (foo (uint) (response uint uint))
            (foo (bool) (response bool bool))
        ))",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::UnexpectedTraitOrFieldReference`]
// Caused by: unexpected use of trait reference or field
// Outcome: block accepted.
#[test]
fn static_check_error_unexpected_trait_or_field_reference() {
    contract_deploy_consensus_test!(
        contract_name: "trait-or-field-ref",
        contract_code: "(+ 1 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR.contract.field)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::IncompatibleTrait`]
// Caused by: pass a trait to a trait parameter which is not compatible.
// Outcome: block accepted.
// Note: Added in Clarity 2. Clarity 1 will trigger a [`StaticCheckErrorKind::TypeError`].
#[test]
fn static_check_error_incompatible_trait() {
    contract_deploy_consensus_test!(
        contract_name: "incompatible-trait",
        contract_code: "
    (define-trait trait-1 (
        (get-1 (uint) (response uint uint))
    ))
    (define-trait trait-2 (
        (get-2 (uint) (response uint uint))
    ))
    (define-public (wrapped-get-2 (contract <trait-1>))
        (internal-get-2 contract))
    (define-public (internal-get-2 (contract <trait-2>))
        (contract-call? contract get-2 u1))",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::TraitTooManyMethods`]
// Caused by: a trait has too many methods.
// Outcome: block accepted.
#[test]
fn static_check_error_trait_too_many_methods() {
    contract_deploy_consensus_test!(
        contract_name: "too-many-methods",
        contract_code: &format!(
            "(define-trait trait-1 ({}))",
            (0..(MAX_TRAIT_METHODS + 1))
                .map(|i| format!("(method-{i} (uint) (response uint uint))"))
                .collect::<Vec<String>>()
                .join(" ")
        ),
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::TooManyFunctionParameters`]
// Caused by: a function has too many parameters.
// Outcome: block accepted.
#[test]
fn static_check_error_too_many_function_parameters() {
    contract_deploy_consensus_test!(
        contract_name: "too-many-params",
        contract_code: &format!(
            "(define-trait trait-1 ((method ({}) (response uint uint))))",
            (0..(MAX_FUNCTION_PARAMETERS + 1))
                .map(|i| "uint".to_string())
                .collect::<Vec<String>>()
                .join(" ")
        ),
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::ReservedWord`]
// Caused by: name is a reserved word
// Outcome: block accepted.
// Note: This error was added in Clarity 3. Clarity 1 and 2
//       will trigger a [`CheckErrorKind::NameAlreadyUsed`].
#[test]
fn static_check_error_reserved_word() {
    contract_deploy_consensus_test!(
        contract_name: "reserved-word",
        contract_code: "(define-private (block-height) true)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::NoSuchBlockInfoProperty`]
// Caused by: referenced an unknown property of a burn block
// Outcome: block accepted.
#[test]
fn static_check_error_no_such_block_info_property() {
    contract_deploy_consensus_test!(
        contract_name: "no-such-block-info",
        contract_code: "(get-burn-block-info? none u1)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::NoSuchStacksBlockInfoProperty`]
// Caused by: referenced an unknown property of a stacks block
// Outcome: block accepted.
// Note: This error was added in Clarity 3. Clarity 1, and 2
//       will trigger a [`StaticCheckErrorKind::UnknownFunction`].
#[test]
fn static_check_error_no_such_stacks_block_info_property() {
    contract_deploy_consensus_test!(
        contract_name: "no-such-stacks-info",
        contract_code: "(get-stacks-block-info? none u1)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::NoSuchTenureInfoProperty`]
// Caused by: referenced an unknown property of a tenure
// Outcome: block accepted.
// Note: This error was added in Clarity 3. Clarity 1, and 2
//       will trigger a [`StaticCheckErrorKind::UnknownFunction`].
#[test]
fn static_check_error_no_such_tenure_info_property() {
    contract_deploy_consensus_test!(
        contract_name: "no-such-tenure-info",
        contract_code: "(get-tenure-info? none u1)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::TraitReferenceUnknown`]
// Caused by: referenced trait is unknown
// Outcome: block accepted.
#[test]
fn static_check_error_trait_reference_unknown() {
    contract_deploy_consensus_test!(
        contract_name: "trait-ref-unknown",
        contract_code: "(+ 1 <kvstore>)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::ContractOfExpectsTrait`]
// Caused by: calling `contract-of` with a non-trait argument.
// Outcome: block accepted.
#[test]
fn static_check_error_contract_of_expects_trait() {
    contract_deploy_consensus_test!(
        contract_name: "expect-trait",
        contract_code: "(contract-of u1)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::TraitMethodUnknown`]
// Caused by: defining a method that is not declared in the trait
// Outcome: block accepted.
#[test]
fn static_check_error_trait_method_unknown() {
    contract_deploy_consensus_test!(
        contract_name: "trait-method-unknown",
        contract_code: "
        (define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-public (wrapped-get-1 (contract <trait-1>))
            (contract-call? contract get-2 u0))",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::WriteAttemptedInReadOnly`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_write_attempted_in_read_only() {
    contract_deploy_consensus_test!(
        contract_name: "write-attempted-in-ro",
        contract_code: "
        (define-read-only (silly)
            (map-delete map-name (tuple (value 1))))
        (silly)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::AtBlockClosureMustBeReadOnly`]
// Caused by: `at-block` closure must be read-only but contains write operations.
// Outcome: block accepted.
#[test]
fn static_check_error_at_block_closure_must_be_read_only() {
    contract_deploy_consensus_test!(
        contract_name: "closure-must-be-ro",
        contract_code: "
        (define-data-var foo int 1)
        (define-private (foo-bar)
            (at-block (sha256 0)
               (var-set foo 0)))",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::AllowanceExprNotAllowed`]
// Caused by: using an allowance expression outside of `restrict-assets?` or `as-contract?`.
// Outcome: block accepted.
// Note: This error was added in Clarity 4. Clarity 1, 2, and 3
//       will trigger a [`StaticCheckErrorKind::UnknownFunction`].
#[test]
fn static_check_error_allowance_expr_not_allowed() {
    contract_deploy_consensus_test!(
        contract_name: "allow-expr-not-allo",
        contract_code: "(with-stx u1)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::ExpectedListOfAllowances`]
// Caused by: post-condition expects a list of asset allowances but received invalid input.
// Outcome: block accepted.
// Note: This error was added in Clarity 4. Clarity 1, 2, and 3
//       will trigger a [`StaticCheckErrorKind::UnknownFunction`].
#[test]
fn static_check_error_expected_list_of_allowances() {
    contract_deploy_consensus_test!(
        contract_name: "exp-list-of-allowances",
        contract_code: "(restrict-assets? tx-sender u1 true)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::ExpectedAllowanceExpr`]
// Caused by: allowance list contains a non-allowance expression.
// Outcome: block accepted.
// Note: This error was added in Clarity 4. Clarity 1, 2, and 3
//       will trigger a [`StaticCheckErrorKind::UnknownFunction`].
#[test]
fn static_check_error_expected_allowance_expr() {
    contract_deploy_consensus_test!(
        contract_name: "exp-allowa-expr",
        contract_code: "(restrict-assets? tx-sender ((not true)) true)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::WithAllAllowanceNotAllowed`]
// Caused by:
// Outcome: block accepted.
// Note: This error was added in Clarity 4. Clarity 1, 2, and 3
//       will trigger a [`StaticCheckErrorKind::UnknownFunction`].
#[test]
fn static_check_error_with_all_allowance_not_allowed() {
    contract_deploy_consensus_test!(
        contract_name: "all-allow-not-allowed",
        contract_code: "(restrict-assets? tx-sender ((with-all-assets-unsafe)) true)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::WithAllAllowanceNotAlone`]
// Caused by:
// Outcome: block accepted.
// Note: This error was added in Clarity 4. Clarity 1, 2, and 3
//       will trigger a [`StaticCheckErrorKind::UnknownFunction`].
#[test]
fn static_check_error_with_all_allowance_not_alone() {
    contract_deploy_consensus_test!(
        contract_name: "all-allow-not-alone",
        contract_code: "(as-contract? ((with-all-assets-unsafe) (with-stx u1000)) true)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::WithNftExpectedListOfIdentifiers`]
// Caused by: the third argument to `with-nft` is not a list of identifiers.
// Outcome: block accepted.
// Note: This error was added in Clarity 4. Clarity 1, 2, and 3
//       will trigger a [`StaticCheckErrorKind::UnknownFunction`].
#[test]
fn static_check_error_with_nft_expected_list_of_identifiers() {
    contract_deploy_consensus_test!(
        contract_name: "with-nft-exp-ident",
        contract_code: r#"(restrict-assets? tx-sender ((with-nft tx-sender "token-name" tx-sender)) true)"#,
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::MaxIdentifierLengthExceeded`]
// Caused by:
// Outcome: block accepted.
// Note: This error was added in Clarity 4. Clarity 1, 2, and 3
//       will trigger a [`StaticCheckErrorKind::UnknownFunction`].
#[test]
fn static_check_error_max_identifier_length_exceeded() {
    contract_deploy_consensus_test!(
        contract_name: "max-ident-len-excd",
        contract_code: &format!(
            "(restrict-assets? tx-sender ((with-nft .token \"token-name\" (list {}))) true)",
            std::iter::repeat_n("u1", 130)
                .collect::<Vec<_>>()
                .join(" ")
        ),
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::TooManyAllowances`]
// Caused by:
// Outcome: block accepted.
// Note: This error was added in Clarity 4. Clarity 1, 2, and 3
//       will trigger a [`StaticCheckErrorKind::UnknownFunction`].
#[test]
fn static_check_error_too_many_allowances() {
    contract_deploy_consensus_test!(
        contract_name: "too-many-allowances",
        contract_code: &format!(
            "(restrict-assets? tx-sender ({} ) true)",
            std::iter::repeat_n("(with-stx u1)", 130)
                .collect::<Vec<_>>()
                .join(" ")
        ),
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::BadTupleConstruction`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_bad_tuple_construction() {
    contract_deploy_consensus_test!(
        contract_name: "bad-tuple-constr",
        contract_code: "(tuple (name 1) (name 2))",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::ExpectedTuple`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_expected_tuple() {
    contract_deploy_consensus_test!(
        contract_name: "expected-tuple",
        contract_code: "(get field-0 (some 1))",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::NoSuchTupleField`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_no_such_tuple_field() {
    contract_deploy_consensus_test!(
        contract_name: "no-such-tuple-f",
        contract_code: "(get value (tuple (name 1)))",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::NoSuchMap`]
// Caused by:
// Outcome: block accepted.
#[test]
fn static_check_error_no_such_map() {
    contract_deploy_consensus_test!(
        contract_name: "no-such-map",
        contract_code: "(map-get? non-existent (tuple (name 1)))",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::BadFunctionName`]
// Caused by: defining a function whose signature does not start with an atom name.
// Outcome: block accepted.
#[test]
fn static_check_error_bad_function_name() {
    contract_deploy_consensus_test!(
        contract_name: "bad-func-name",
        contract_code: "(define-private (u1) u0)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::DefineFunctionBadSignature`]
// Caused by: defining a function with an empty signature list.
// Outcome: block accepted.
#[test]
fn static_check_error_define_function_bad_signature() {
    contract_deploy_consensus_test!(
        contract_name: "def-func-bad-sign",
        contract_code: "(define-private () 1)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::BadTupleFieldName`]
// Caused by: using `(get ...)` with a tuple field argument that is not an atom.
// Outcome: block accepted.
#[test]
fn static_check_error_bad_tuple_field_name() {
    contract_deploy_consensus_test!(
        contract_name: "bad-tuple-field-name",
        contract_code: "(get u1 (tuple (foo u0)))",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::BadMapName`]
// Caused by: passing a literal instead of a map identifier to `map-get?`.
// Outcome: block accepted.
#[test]
fn static_check_error_bad_map_name() {
    contract_deploy_consensus_test!(
        contract_name: "bad-map-name",
        contract_code: "(map-get? u1 (tuple (id u0)))",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::GetBlockInfoExpectPropertyName`]
// Caused by: calling `get-block-info` with a non-atom property argument.
// Outcome: block accepted.
// Note: Only Clarity 1 and 2 will trigger this error. Clarity 3 and 4
//       will trigger a [`StaticCheckErrorKind::UnknownFunction`].
#[test]
fn static_check_error_get_block_info_expect_property_name() {
    contract_deploy_consensus_test!(
        contract_name: "info-exp-prop-name",
        contract_code: "(get-block-info? u1 u0)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::GetBurnBlockInfoExpectPropertyName`]
// Caused by: calling `get-burn-block-info` with a non-atom property argument.
// Outcome: block accepted.
// Note: This error was added in Clarity 2. Clarity 1 will trigger
//       a [`StaticCheckErrorKind::UnknownFunction`].
#[test]
fn static_check_error_get_burn_block_info_expect_property_name() {
    contract_deploy_consensus_test!(
        contract_name: "burn-exp-prop-name",
        contract_code: "(get-burn-block-info? u1 u0)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::GetStacksBlockInfoExpectPropertyName`]
// Caused by: calling `get-stacks-block-info` with a non-atom property argument.
// Outcome: block accepted.
// Note: This error was added in Clarity 3. Clarity 1 and 2 will trigger
//       a [`StaticCheckErrorKind::UnknownFunction`].
#[test]
fn static_check_error_get_stacks_block_info_expect_property_name() {
    contract_deploy_consensus_test!(
        contract_name: "stacks-exp-prop-name",
        contract_code: "(get-stacks-block-info? u1 u0)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::GetTenureInfoExpectPropertyName`]
// Caused by: calling `get-tenure-info` with a non-atom property argument.
// Outcome: block accepted.
// Note: This error was added in Clarity 3. Clarity 1 and 2 will trigger
//       a [`StaticCheckErrorKind::UnknownFunction`].
#[test]
fn static_check_error_get_tenure_info_expect_property_name() {
    contract_deploy_consensus_test!(
        contract_name: "tenure-exp-prop-name",
        contract_code: "(get-tenure-info? u1 u0)",
    );
}

// StaticCheckErrorKind: [`StaticCheckErrorKind::BadTraitImplementation`]
// Caused by: trying to implement a trait with a bad implementation.
// Outcome: block accepted.
#[test]
fn static_check_error_bad_trait_implementation() {
    let setup_contract = SetupContract::new(
        "trait-contract",
        "(define-trait trait-1 ((get-1 ((list 10 uint)) (response uint uint))))",
    );

    contract_deploy_consensus_test!(
        contract_name: "contract-name",
        contract_code: &format!("
            (impl-trait .trait-contract.trait-1)
            (define-public (get-1 (x (list 5 uint))) (ok u1))",
        ),
        setup_contracts: &[setup_contract],
    );
}

// Error: [`Error::InvalidStacksTransaction("Duplicate contract")`]
// Caused by: trying to deploy a contract that already exists.
// Outcome: block rejected.
#[test]
fn error_invalid_stacks_transaction_duplicate_contract() {
    let contract_code = "(define-constant buff-0 0x00)";
    let mut nonce = 0;

    let tx_fee = (contract_code.len() * 100) as u64;
    let mut epochs_blocks: HashMap<StacksEpochId, Vec<TestBlock>> = HashMap::new();
    let contract_name = "contract-name";
    let deploy_tx = make_contract_publish_versioned(
        &FAUCET_PRIV_KEY,
        nonce,
        tx_fee,
        CHAIN_ID_TESTNET,
        &contract_name,
        &contract_code,
        None,
    );
    nonce += 1;
    epochs_blocks
        .entry(*EPOCHS_TO_TEST.first().unwrap())
        .or_insert(vec![])
        .push(TestBlock {
            transactions: vec![
                StacksTransaction::consensus_deserialize(&mut deploy_tx.as_slice()).unwrap(),
            ],
        });

    for epoch in EPOCHS_TO_TEST {
        for version in clarity_versions_for_epoch(*epoch) {
            let deploy_tx = make_contract_publish_versioned(
                &FAUCET_PRIV_KEY,
                nonce,
                tx_fee,
                CHAIN_ID_TESTNET,
                &contract_name,
                &contract_code,
                Some(*version),
            );

            let deploy_tx =
                StacksTransaction::consensus_deserialize(&mut deploy_tx.as_slice()).unwrap();

            let entry = epochs_blocks
                .entry(*epoch)
                .or_insert(vec![])
                .push(TestBlock {
                    transactions: vec![deploy_tx],
                });
        }
    }

    let result = ConsensusTest::new(function_name!(), vec![], epochs_blocks).run();

    insta::assert_ron_snapshot!(result);
}

// pub enum StaticCheckErrorKind {
//     CostOverflow,  // Unreachable: should exceed u64
//     CostBalanceExceeded(ExecutionCost, ExecutionCost), [`static_check_error_cost_balance_exceeded`]
//     MemoryBalanceExceeded(u64, u64),
//     CostComputationFailed(String),  // Unreachable
//     ExecutionTimeExpired, // Unreachable: can only be triggered at runtime. The CostError::ExecutionTimeExpired is immediately transformed into a VmExecutionError::Unchecked
//     ValueTooLarge, [`static_check_error_value_too_large`]
//     ValueOutOfBounds, [`static_check_error_value_out_of_bounds`]
//     TypeSignatureTooDeep, [`static_check_error_type_signature_too_deep`]
//     ExpectedName, [`static_check_error_expected_name`]
//     SupertypeTooLarge, [`static_check_error_supertype_too_large`]
//     Expects(String),  // unreachable
//     BadMatchOptionSyntax(Box<StaticCheckErrorKind>), [`static_check_error_bad_match_option_syntax`]
//     BadMatchResponseSyntax(Box<StaticCheckErrorKind>), [`static_check_error_bad_match_response_syntax`]
//     BadMatchInput(Box<TypeSignature>), [`static_check_error_bad_match_input`]
//     ConstructedListTooLarge, [`static_check_error_constructed_list_too_large`]
//     TypeError(Box<TypeSignature>, Box<TypeSignature>),  [`static_check_error_type_error`]
//     InvalidTypeDescription, [`static_check_error_invalid_type_description`]
//     UnknownTypeName(String), [`static_check_error_unknown_type_name`]
//     UnionTypeError(Vec<TypeSignature>, Box<TypeSignature>), [`static_check_error_union_type_error`]
//     ExpectedOptionalType(Box<TypeSignature>), [`static_check_error_expected_optional_type`]
//     ExpectedResponseType(Box<TypeSignature>), [`static_check_error_expected_response_type`]
//     ExpectedOptionalOrResponseType(Box<TypeSignature>), [`static_check_error_expected_optional_or_response_type`]
//     CouldNotDetermineResponseOkType, [`static_check_error_could_not_determine_response_ok_type`]
//     CouldNotDetermineResponseErrType, [`static_check_error_could_not_determine_response_err_type`]
//     CouldNotDetermineSerializationType, [`static_check_error_could_not_determine_serialization_type`]
//     UncheckedIntermediaryResponses, [`static_check_error_unchecked_intermediary_responses`]
//     CouldNotDetermineMatchTypes, [`static_check_error_could_not_determine_match_types`]
//     CouldNotDetermineType, [`static_check_error_could_not_determine_type`]
//     TypeAlreadyAnnotatedFailure,  // Unreachable: The AST assigner gives each node a unique `id`, and the type checker visits each node exactly once, so duplicate annotations cannot occur.
//     CheckerImplementationFailure,  // Unreachable
//     BadTokenName, [`static_check_error_bad_token_name`]
//     DefineNFTBadSignature, [`static_check_error_define_nft_bad_signature`]
//     NoSuchNFT(String), [`static_check_error_no_such_nft`]
//     NoSuchFT(String), [`static_check_error_no_such_ft`]
//     BadTupleFieldName, [`static_check_error_bad_tuple_field_name`]
//     ExpectedTuple(Box<TypeSignature>), [`static_check_error_expected_tuple`]
//     NoSuchTupleField(String, TupleTypeSignature), [`static_check_error_no_such_tuple_field`]
//     EmptyTuplesNotAllowed, [`static_check_error_empty_tuples_not_allowed`]
//     BadTupleConstruction(String), [`static_check_error_bad_tuple_construction`]
//     NoSuchDataVariable(String), [`static_check_error_no_such_data_variable`]
//     BadMapName, [`static_check_error_bad_map_name`]
//     NoSuchMap(String), [`static_check_error_no_such_map`]
//     DefineFunctionBadSignature, [`static_check_error_define_function_bad_signature`]
//     BadFunctionName, [`static_check_error_bad_function_name`]
//     BadMapTypeDefinition, [`static_check_error_bad_map_type_definition`]
//     PublicFunctionMustReturnResponse(Box<TypeSignature>),
//     DefineVariableBadSignature, [`static_check_error_define_variable_bad_signature`]
//     ReturnTypesMustMatch(Box<TypeSignature>, Box<TypeSignature>), [`static_check_error_return_types_must_match`]
//     NoSuchContract(String), [`static_check_error_no_such_contract`]
//     NoSuchPublicFunction(String, String), [`static_check_error_no_such_public_function`]
//     ContractAlreadyExists(String), Unreachable: during normal operations, `StacksChainState::process_transaction_payload` will check if the contract exists already, invalidating the block before executing analysis.
//     ContractCallExpectName, [`static_check_error_contract_call_expect_name`]
//     ExpectedCallableType(Box<TypeSignature>), [`static_check_error_expected_callable_type`]
//     NoSuchBlockInfoProperty(String), [`static_check_error_no_such_block_info_property`]
//     NoSuchStacksBlockInfoProperty(String), [`static_check_error_no_such_stacks_block_info_property`]
//     NoSuchTenureInfoProperty(String), [`static_check_error_no_such_tenure_info_property`]
//     GetBlockInfoExpectPropertyName, [`static_check_error_get_block_info_expect_property_name`]
//     GetBurnBlockInfoExpectPropertyName, [`static_check_error_get_burn_block_info_expect_property_name`]
//     GetStacksBlockInfoExpectPropertyName, [`static_check_error_get_stacks_block_info_expect_property_name`]
//     GetTenureInfoExpectPropertyName, [`static_check_error_get_tenure_info_expect_property_name`]
//     NameAlreadyUsed(String), [`static_check_error_name_already_used`]
//     ReservedWord(String), [`static_check_error_reserved_word`]
//     NonFunctionApplication, [`static_check_error_non_function_application`]
//     ExpectedListApplication, [`static_check_error_expected_list_application`]
//     ExpectedSequence(Box<TypeSignature>), [`static_check_error_expected_sequence`]
//     MaxLengthOverflow, UNREACHABLE: should exceed u32 elements in memory.
//     BadLetSyntax, [`static_check_error_bad_let_syntax`]
//     BadSyntaxBinding(SyntaxBindingError), [`static_check_error_bad_syntax_binding`]
//     MaxContextDepthReached, /// Unreachable: Before type checking runs, the parser enforces an AST nesting limit of (5 + 64). Any contract exceeding depth 69 fails with [`ParseErrorKind::ExpressionStackDepthTooDeep`].
//     UndefinedVariable(String), [`static_check_error_undefined_variable`]
//     RequiresAtLeastArguments(usize, usize), [`static_check_error_requires_at_least_arguments`]
//     RequiresAtMostArguments(usize, usize), [`static_check_error_requires_at_most_arguments`]
//     IncorrectArgumentCount(usize, usize), [`static_check_error_incorrect_argument_count`]
//     IfArmsMustMatch(Box<TypeSignature>, Box<TypeSignature>), [`static_check_error_if_arms_must_match`]
//     MatchArmsMustMatch(Box<TypeSignature>, Box<TypeSignature>), [`static_check_error_match_arms_must_match`]
//     DefaultTypesMustMatch(Box<TypeSignature>, Box<TypeSignature>), [`static_check_error_default_types_must_match`]
//     IllegalOrUnknownFunctionApplication(String), [`static_check_error_illegal_or_unknown_function_application`]
//     UnknownFunction(String), [`static_check_error_unknown_function`]
//     TooManyFunctionParameters(usize, usize), [`static_check_error_too_many_function_parameters`]
//     NoSuchTrait(String, String), // Unreachable: all trait identifiers are validated by the parser and TraitsResolve before type checking; invalid or missing traits trigger TraitReferenceUnknown earlier, so this error is never returned.
//     TraitReferenceUnknown(String), [`static_check_error_trait_reference_unknown`]
//     TraitMethodUnknown(String, String), [`static_check_error_trait_method_unknown`]
//     ExpectedTraitIdentifier, // Unreachable: (use-trait …) or (impl-trait …) with an invalid second argument fails in the AST stage, raising ParseErrorKind::ImportTraitBadSignature/ImplTraitBadSignature before static checks run.
//     BadTraitImplementation(String, String), [`static_check_error_bad_trait_implementation`]
//     DefineTraitBadSignature, [`static_check_error_define_trait_bad_signature`]
//     DefineTraitDuplicateMethod(String), [`static_check_error_define_trait_duplicate_method`]
//     UnexpectedTraitOrFieldReference, [`static_check_error_unexpected_trait_or_field_reference`]
//     ContractOfExpectsTrait, [`static_check_error_contract_of_expects_trait`]
//     IncompatibleTrait(Box<TraitIdentifier>, Box<TraitIdentifier>), [`static_check_error_incompatible_trait`]
//     TraitTooManyMethods(usize, usize), [`static_check_error_trait_too_many_methods`]
//     WriteAttemptedInReadOnly, [`static_check_error_write_attempted_in_read_only`]
//     AtBlockClosureMustBeReadOnly, [`static_check_error_at_block_closure_must_be_read_only`]
//     ExpectedListOfAllowances(String, i32), [`static_check_error_expected_list_of_allowances`]
//     AllowanceExprNotAllowed, [`static_check_error_allowance_expr_not_allowed`]
//     ExpectedAllowanceExpr(String), [`static_check_error_expected_allowance_expr`]
//     WithAllAllowanceNotAllowed, [`static_check_error_with_all_allowance_not_allowed`]
//     WithAllAllowanceNotAlone, [`static_check_error_with_all_allowance_not_alone`]
//     WithNftExpectedListOfIdentifiers, [`static_check_error_with_nft_expected_list_of_identifiers`]
//     MaxIdentifierLengthExceeded(u32, u32), [`static_check_error_max_identifier_length_exceeded`]
//     TooManyAllowances(usize, usize), [`static_check_error_too_many_allowances`]
// }
