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

use crate::chainstate::tests::consensus::contract_deploy_consensus_test;
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
/// Caused by: option `match` expecting 4 arguments, got 3
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
