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

//! This module contains consensus tests related to Clarity CheckErrorKind errors that happens during contract analysis.

#[allow(unused_imports)]
use clarity::vm::analysis::CheckErrorKind;
use clarity::vm::types::MAX_TYPE_DEPTH;

use crate::chainstate::tests::consensus::{contract_deploy_consensus_test, SetupContract};
use crate::core::BLOCK_LIMIT_MAINNET_21;
use crate::util_lib::boot::boot_code_test_addr;

/// CheckErrorKind: [`CheckErrorKind::CostBalanceExceeded`]
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

/// CheckErrorKind: [`CheckErrorKind::ValueTooLarge`]
/// Caused by: Value exceeds the maximum allowed size for type-checking
/// Outcome: block accepted.
#[test]
fn static_check_error_value_too_large() {
    contract_deploy_consensus_test!(
        contract_name: "value-too-large",
        contract_code: "(as-max-len? 0x01 u1048577)",
    );
}

/// CheckErrorKind: [`CheckErrorKind::ValueOutOfBounds`]
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

/// CheckErrorKind: [`CheckErrorKind::ExpectedName`]
/// Caused by: Expected a name (e.g., variable) but found an different expression.
/// Outcome: block accepted.
#[test]
fn static_check_error_expected_name() {
    contract_deploy_consensus_test!(
        contract_name: "expected-name",
        contract_code: "(match (some 1) 2 (+ 1 1) (+ 3 4))",
    );
}

/// CheckErrorKind: [`CheckErrorKind::ExpectedResponseType`]
/// Caused by: Expected a response type but found a different type.
/// Outcome: block accepted.
#[test]
fn static_check_error_expected_response_type() {
    contract_deploy_consensus_test!(
        contract_name: "expected-response-type",
        contract_code: "(unwrap-err! (some 2) 2)",
    );
}

/// CheckErrorKind: [`CheckErrorKind::CouldNotDetermineResponseOkType`]
/// Caused by: `unwrap!` on literal `(err 3)` leaves the response `ok` type unknown.
/// Outcome: block accepted.
#[test]
fn static_check_error_could_not_determine_response_ok_type() {
    contract_deploy_consensus_test!(
        contract_name: "could-not-determine",
        contract_code: "(unwrap! (err 3) 2)",
    );
}

/// CheckErrorKind: [`CheckErrorKind::CouldNotDetermineResponseErrType`]
/// Caused by: `unwrap-err-panic` on `(ok 3)` gives no way to infer the response `err` type.
/// Outcome: block accepted.
#[test]
fn static_check_error_could_not_determine_response_err_type() {
    contract_deploy_consensus_test!(
        contract_name: "could-not-determine",
        contract_code: "(unwrap-err-panic (ok 3))",
    );
}

/// CheckErrorKind: [`CheckErrorKind::CouldNotDetermineMatchTypes`]
/// Caused by: matching a bare `none` provides no option type, leaving branch types ambiguous.
/// Outcome: block accepted.
#[test]
fn static_check_error_could_not_determine_match_types() {
    contract_deploy_consensus_test!(
        contract_name: "could-not-determine",
        contract_code: "(match none inner-value (/ 1 0) (+ 1 8))",
    );
}

/// CheckErrorKind: [`CheckErrorKind::MatchArmsMustMatch`]
/// Caused by: the `some` arm yields an int while the `none` arm yields a bool.
/// Outcome: block accepted.
#[test]
fn static_check_error_match_arms_must_match() {
    contract_deploy_consensus_test!(
        contract_name: "match-arms-must-match",
        contract_code: "(match (some 1) inner-value (+ 1 inner-value) (> 1 28))",
    );
}

/// CheckErrorKind: [`CheckErrorKind::BadMatchOptionSyntax`]
/// Caused by: option `match` expecting 4 arguments, got 3.
/// Outcome: block accepted.
#[test]
fn static_check_error_bad_match_option_syntax() {
    contract_deploy_consensus_test!(
        contract_name: "bad-match-option",
        contract_code: "(match (some 1) inner-value (+ 1 inner-value))",
    );
}

/// CheckErrorKind: [`CheckErrorKind::BadMatchResponseSyntax`]
/// Caused by: response `match` expecting 5 arguments, got 3.
/// Outcome: block accepted.
#[test]
fn static_check_error_bad_match_response_syntax() {
    contract_deploy_consensus_test!(
        contract_name: "bad-match-response",
        contract_code: "(match (ok 1) inner-value (+ 1 inner-value))",
    );
}

/// CheckErrorKind: [`CheckErrorKind::RequiresAtLeastArguments`]
/// Caused by: invoking `match` with no arguments.
/// Outcome: block accepted.
#[test]
fn static_check_error_requires_at_least_arguments() {
    contract_deploy_consensus_test!(
        contract_name: "requires-at-least",
        contract_code: "(match)",
    );
}

/// CheckErrorKind: [`CheckErrorKind::RequiresAtMostArguments`]
/// Caused by: `principal-construct?` is called with too many arguments.
/// Outcome: block accepted.
#[test]
fn static_check_error_requires_at_most_arguments() {
    contract_deploy_consensus_test!(
        contract_name: "requires-at-most",
        contract_code: r#"(principal-construct? 0x22 0xfa6bf38ed557fe417333710d6033e9419391a320 "foo" "bar")"#,
    );
}

/// CheckErrorKind: [`CheckErrorKind::BadMatchInput`]
/// Caused by: `match` input is the integer `1`, not an option or response.
/// Outcome: block accepted.
#[test]
fn static_check_error_bad_match_input() {
    contract_deploy_consensus_test!(
        contract_name: "bad-match-input",
        contract_code: "(match 1 ok-val (/ ok-val 0) err-val (+ err-val 7))",
    );
}

/// CheckErrorKind: [`CheckErrorKind::ExpectedOptionalType`]
/// Caused by: `default-to` second argument `5` is not an optional value.
/// Outcome: block accepted.
#[test]
fn static_check_error_expected_optional_type() {
    contract_deploy_consensus_test!(
        contract_name: "expected-optional-type",
        contract_code: "(default-to 3 5)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::BadTraitImplementation`]
/// Caused by: trying to implement a trait with a bad implementation.
/// Outcome: block accepted.
#[test]
fn static_check_error_bad_trait_implementation() {
    let setup_contract = SetupContract::new(
        "trait-contract",
        "(define-trait trait-1 ((get-1 ((list 10 uint)) (response uint uint))))",
    );

    contract_deploy_consensus_test!(
        contract_name: "contract-name",
        contract_code: "
        (impl-trait .trait-contract.trait-1)
        (define-public (get-1 (x (list 5 uint))) (ok u1))",
        setup_contracts: &[setup_contract],
    );
}

/// CheckErrorKind: [`CheckErrorKind::NameAlreadyUsed`]
/// Caused by: redefining constant `foo` a second time.
/// Outcome: block accepted.
#[test]
fn static_check_error_name_already_used() {
    contract_deploy_consensus_test!(
        contract_name: "name-already-used",
        contract_code: "
        (define-constant foo 10)
        (define-constant foo 20)",
    );
}

/// CheckErrorKind: [`CheckErrorKind::ReturnTypesMustMatch`]
/// Caused by: `unwrap!` default returns `err 1` while the function returns `err false`, so response types diverge.
/// Outcome: block accepted.
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

/// CheckErrorKind: [`CheckErrorKind::TypeError`]
/// Caused by: initializing `define-data-var cursor int` with the boolean `true`.
/// Outcome: block accepted.
#[test]
fn static_check_error_type_error() {
    contract_deploy_consensus_test!(
        contract_name: "type-error",
        contract_code: "(define-data-var cursor int true)",
    );
}

/// CheckErrorKind: [`CheckErrorKind::DefineVariableBadSignature`]
/// Caused by: `define-data-var` is provided only a name and value, missing the required type.
/// Outcome: block accepted.
#[test]
fn static_check_error_define_variable_bad_signature() {
    contract_deploy_consensus_test!(
        contract_name: "define-variable-bad",
        contract_code: "(define-data-var cursor 0x00)",
    );
}

/// CheckErrorKind: [`CheckErrorKind::InvalidTypeDescription`]
/// Caused by: `define-data-var` uses `0x00` where a valid type description is required.
/// Outcome: block accepted.
#[test]
fn static_check_error_invalid_type_description() {
    contract_deploy_consensus_test!(
        contract_name: "invalid-type-desc",
        contract_code: "(define-data-var cursor 0x00 true)",
    );
}

/// CheckErrorKind: [`CheckErrorKind::TypeSignatureTooDeep`]
/// Caused by: parameter type nests `optional` wrappers deeper than [`MAX_TYPE_DEPTH`].
/// Outcome: block accepted.
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

/// CheckErrorKind: [`CheckErrorKind::SupertypeTooLarge`]
/// Caused by: combining tuples with `buff 600000` and `buff 10` forces a supertype beyond the size limit.
/// Outcome: block rejected.
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

/// CheckErrorKind: [`CheckErrorKind::ConstructedListTooLarge`]
/// Caused by: mapping `sha512` over a list capped at 65,535 elements constructs a list past [`MAX_VALUE_SIZE`].
/// Outcome: block accepted.
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

/// CheckErrorKind: [`CheckErrorKind::UnknownTypeName`]
/// Caused by: `from-consensus-buff?` references an undefined type named `foo`.
/// Outcome: block accepted.
/// Note: during analysis, this error can only be triggered by `from-consensus-buff?`
///       which is only available in Clarity 2 and later. So Clarity 1 will not trigger
///       this error.
#[test]
fn static_check_error_unknown_type_name() {
    contract_deploy_consensus_test!(
        contract_name: "unknown-type-name",
        contract_code: "
        (define-public (trigger)
            (ok (from-consensus-buff? foo 0x00)))",
    );
}

/// CheckErrorKind: [`CheckErrorKind::UnionTypeError`]
/// Caused by: `map` applies subtraction to booleans.
/// Outcome: block accepted.
#[test]
fn static_check_error_union_type_error() {
    contract_deploy_consensus_test!(
        contract_name: "union-type-error",
        contract_code: "(map - (list true false true false))",
    );
}

/// CheckErrorKind: [`CheckErrorKind::UndefinedVariable`]
/// Caused by: `x`, `y`, and `z` are referenced without being defined.
/// Outcome: block accepted.
#[test]
fn static_check_error_undefined_variable() {
    contract_deploy_consensus_test!(
        contract_name: "undefined-variable",
        contract_code: "(+ x y z)",
    );
}

/// CheckErrorKind: [`CheckErrorKind::BadMapTypeDefinition`]
/// Caused by: Invalid map type definition in a `(define-map ...)` expression.
/// Outcome: block accepted.
#[test]
fn static_check_error_bad_map_type_definition() {
    contract_deploy_consensus_test!(
        contract_name: "bad-map-type",
        contract_code: "(define-map lists { name: int } contents)",
    );
}

/// CheckErrorKind: [`CheckErrorKind::CouldNotDetermineType`]
/// Caused by: `(index-of (list) none)` supplies no concrete element types.
/// Outcome: block accepted.
#[test]
fn static_check_error_could_not_determine_type() {
    contract_deploy_consensus_test!(
        contract_name: "could-not-determine",
        contract_code: "(index-of (list) none)",
    );
}

/// CheckErrorKind: [`CheckErrorKind::ExpectedSequence`]
/// Caused by: passing integer `3` as the sequence argument to `index-of` instead of a list or string.
/// Outcome: block accepted.
#[test]
fn static_check_error_expected_sequence() {
    contract_deploy_consensus_test!(
        contract_name: "expected-sequence",
        contract_code: r#"(index-of 3 "a")"#,
    );
}

/// CheckErrorKind: [`CheckErrorKind::CouldNotDetermineSerializationType`]
/// Caused by: `to-consensus-buff?` over a list of trait references lacks a serialization type.
/// Outcome: block accepted.
/// Note: during analysis, this error can only be triggered by `from-consensus-buff?`
///       which is only available in Clarity 2 and later. So Clarity 1 will not trigger
///       this error.
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
