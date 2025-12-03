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

//! This module contains consensus tests related to EarlyReturn errors.

use clarity::vm::errors::EarlyReturnError;
use clarity::vm::types::ResponseData;
use clarity::vm::Value as ClarityValue;

use crate::chainstate::tests::consensus::{
    contract_call_consensus_test, contract_deploy_consensus_test,
};

/// Generates a coverage classification report for a specific [`EarlyReturnError`] variant.
///
/// This method exists purely for **documentation and tracking purposes**.
/// It helps maintainers understand which error variants have been:
///
/// - ✅ **Tested** — verified through consensus tests.
/// - ⚙️ **Ignored** — not tested on purpose.
/// - 🚫 **Unreachable** — not testable from consensus test side for reasons.
#[allow(dead_code)]
fn variant_coverage_report(variant: EarlyReturnError) {
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

    use EarlyReturnError::*;
    use VariantCoverage::*;

    _ = match variant {
        UnwrapFailed(_) => Tested(vec![
            native_try_ret_err_cdeploy,
            native_try_ret_err_ccall,
            native_try_ret_none_cdeploy,
            native_try_ret_none_ccall,
            native_unwrap_err_or_ret_cdeploy,
            native_unwrap_err_or_ret_ccall,
            native_unwrap_or_ret_none_cdeploy,
            native_unwrap_or_ret_none_ccall,
        ]),
        AssertionFailed(_) => Tested(vec![
            native_special_asserts_cdeploy,
            native_special_asserts_ccall,
        ]),
    };
}

/// Error: [`EarlyReturnError::UnwrapFailed`]
/// Caused by: attempting to `try!` unwrap an `err` response at deploy time.
/// Outcome: block accepted
#[test]
fn native_try_ret_err_cdeploy() {
    contract_deploy_consensus_test!(
        contract_name: "unwrap-try-resp",
        contract_code: "(begin (try! (if true (err u200) (ok u1))))",
    );
}

/// Error: [`EarlyReturnError::UnwrapFailed`]
/// Caused by: attempting to `try!` unwrap an `err` response at call time.
/// Outcome: block accepted
/// Note: [`clarity::vm::callables::DefinedFunction::execute_apply`] converts [`EarlyReturnError::UnwrapFailed`]
/// into a successful return wrapping the internal thrown value.
#[test]
fn native_try_ret_err_ccall() {
    contract_call_consensus_test!(
        contract_name: "unwrap-err",
        contract_code: "
            (define-read-only (trigger (resp (response uint uint)))
                (begin
                    (try! resp)
                    (ok u1)
                )
            )
        ",
        function_name: "trigger",
        function_args: &[ClarityValue::Response(ResponseData {
            committed: false,
            data: Box::new(ClarityValue::UInt(42))
        })],
    );
}

/// Error: [`EarlyReturnError::UnwrapFailed`]
/// Caused by: attempting to `try!` unwrap a `None` optional at deploy time.
/// Outcome: block accepted
#[test]
fn native_try_ret_none_cdeploy() {
    contract_deploy_consensus_test!(
        contract_name: "unwrap-try-opt",
        contract_code: "(begin (try! (if true none (some true))))",
    );
}

/// Error: [`EarlyReturnError::UnwrapFailed`]
/// Caused by: attempting to `try!` unwrap an `None` optional at call time.
/// Outcome: block accepted
/// Note: [`clarity::vm::callables::DefinedFunction::execute_apply`] converts [`EarlyReturnError::UnwrapFailed`]
/// into a successful return wrapping the internal thrown value.
#[test]
fn native_try_ret_none_ccall() {
    contract_call_consensus_test!(
        contract_name: "unwrap-try-opt",
        contract_code: "
            (define-read-only (trigger (opt (optional bool)))
                (begin
                    (try! opt)
                    (some true)
                )
            )
        ",
        function_name: "trigger",
        function_args: &[ClarityValue::none()],
    );
}

/// Error: [`EarlyReturnError::UnwrapFailed`]
/// Caused by: calling `unwrap-err!` on an `(ok ...)` value at deploy time.
/// Outcome: block accepted
#[test]
fn native_unwrap_err_or_ret_cdeploy() {
    contract_deploy_consensus_test!(
        contract_name: "unwrap-err",
        contract_code: "(begin (unwrap-err! (if true (ok u3) (err u1)) (err u9)))",
    );
}

/// Error: [`EarlyReturnError::UnwrapFailed`]
/// Caused by: calling `unwrap-err!` on an `(ok ...)` value at call time.
/// Outcome: block accepted
/// Note: [`clarity::vm::callables::DefinedFunction::execute_apply`] converts [`EarlyReturnError::UnwrapFailed`]
/// into a successful return wrapping the internal thrown value.
#[test]
fn native_unwrap_err_or_ret_ccall() {
    contract_call_consensus_test!(
        contract_name: "unwrap-err",
        contract_code: "
            (define-public (trigger)
                (begin
                    (unwrap-err! (if true (ok u3) (err u1)) (err u9))
                    (ok u1)
                )
            )
        ",
        function_name: "trigger",
        function_args: &[],
    );
}

/// Error: [`EarlyReturnError::UnwrapFailed`]
/// Caused by: calling `unwrap!` on a `None` optional at deploy time.
/// Outcome: block accepted
#[test]
fn native_unwrap_or_ret_none_cdeploy() {
    contract_deploy_consensus_test!(
        contract_name: "unwrap-opt",
        contract_code: "(begin (unwrap! (if true none (some true)) (err u9)))",
    );
}

/// Error: [`EarlyReturnError::UnwrapFailed`]
/// Caused by: calling `unwrap!` on a `None` optional at call time.
/// Outcome: block accepted
/// Note: [`clarity::vm::callables::DefinedFunction::execute_apply`] converts [`EarlyReturnError::UnwrapFailed`]
/// into a successful return wrapping the internal thrown value.
#[test]
fn native_unwrap_or_ret_none_ccall() {
    contract_call_consensus_test!(
        contract_name: "unwrap-opt",
        contract_code: "
            (define-read-only (trigger (opt (optional bool)))
                (begin
                    (unwrap! opt (err false))
                    (ok true)
                )
            )
        ",
        function_name: "trigger",
        function_args: &[ClarityValue::none()],
    );
}

/// Error: [`EarlyReturnError::AssertionFailed`]
/// Caused by: failing `asserts!` condition at deploy time.
/// Outcome: block accepted
#[test]
fn native_special_asserts_cdeploy() {
    contract_deploy_consensus_test!(
        contract_name: "asserts-fail",
        contract_code: "(begin (asserts! (is-eq 1 0) (err u0)) (ok u1))",
    );
}

/// Error: [`EarlyReturnError::AssertionFailed`]
/// Caused by: failing `asserts!` condition at call time.
/// Outcome: block accepted
/// Note: [`clarity::vm::callables::DefinedFunction::execute_apply`] converts [`EarlyReturnError::AssertionFailed`]
/// into a successful return wrapping the internal thrown value.
#[test]
fn native_special_asserts_ccall() {
    contract_call_consensus_test!(
        contract_name: "asserts-fail",
        contract_code: "(define-public (trigger) (begin (asserts! false (err u0)) (ok u1)))",
        function_name: "trigger",
        function_args: &[],
    );
}
