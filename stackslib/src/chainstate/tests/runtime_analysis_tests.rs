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

//! This module contains consensus tests related to Clarity CheckErrorKind errors that happens during contract initialization and execution.

#[allow(unused_imports)]
use clarity::vm::analysis::CheckErrorKind;
use clarity::vm::types::MAX_TYPE_DEPTH;
use clarity::vm::Value as ClarityValue;

use crate::chainstate::tests::consensus::{
    contract_call_consensus_test, contract_deploy_consensus_test,
};
use crate::core::BLOCK_LIMIT_MAINNET_21;

/// CheckError: [`CheckErrorKind::CostBalanceExceeded`]
/// Caused by: exceeding the cost analysis budget during contract initialization.
///   The contract repeatedly performs `var-get` lookups on a data variable,
///   forcing the type checker to fetch the variable enough times to exceed
///   the read-count limit in [`BLOCK_LIMIT_MAINNET_21`].
/// Outcome: block rejected.
#[test]
fn check_error_cost_balance_exceeded_cdeploy() {
    contract_deploy_consensus_test!(
        contract_name: "cost-balance-exceeded",
        contract_code: &format!("
        (define-data-var foo int 1)
        (begin
            {}
        )",
            "(var-get foo)\n".repeat(BLOCK_LIMIT_MAINNET_21.read_count as usize + 1)
        ),
    );
}
/// CheckError: [`CheckErrorKind::NameAlreadyUsed`]
/// Caused by: name is already used by a standard clarity function.
/// Outcome: block rejected.
#[test]
fn check_error_kind_name_already_used_cdeploy() {
    contract_deploy_consensus_test!(
        contract_name: "name-already-used",
        contract_code: "(define-private (ft-get-supply) 1)",
    );
}
/// CheckErrorKind: [`CheckErrorKind::ValueTooLarge`]
/// Caused by: `(as-max-len? …)` wraps a buffer whose serialized size plus the optional wrapper
///   exceeds `MAX_VALUE_SIZE`. Static analysis allows this construction, but initialization fails
///   at runtime when `Value::some` detects the oversized payload.
/// Outcome: block accepted.
#[test]
fn check_error_kind_value_too_large_cdeploy() {
    contract_deploy_consensus_test!(
        contract_name: "value-too-large",
        contract_code: r#"
        (define-private (make-buff-256)
            (let ((b16 0x00112233445566778899aabbccddeeff)
                  (b32 (concat b16 b16))
                  (b64 (concat b32 b32))
                  (b128 (concat b64 b64))
                  (b256 (concat b128 b128)))
              b256))

        (define-private (make-buff-4096)
            (let ((b256 (make-buff-256))
                  (b512 (concat b256 b256))
                  (b1024 (concat b512 b512))
                  (b2048 (concat b1024 b1024))
                  (b4096 (concat b2048 b2048)))
              b4096))

        (define-private (make-buff-65536)
            (let ((b4096 (make-buff-4096))
                  (b8192 (concat b4096 b4096))
                  (b16384 (concat b8192 b8192))
                  (b32768 (concat b16384 b16384))
                  (b65536 (concat b32768 b32768)))
              b65536))

        (define-private (make-buff-1048576)
            (let ((b65536 (make-buff-65536))
                  (b131072 (concat b65536 b65536))
                  (b262144 (concat b131072 b131072))
                  (b524288 (concat b262144 b262144))
                  (b1048576 (concat b524288 b524288)))
              b1048576))

        (begin
            (unwrap-panic (as-max-len? (make-buff-1048576) u1048576))
            u0)
    "#,
    );
}

/// CheckErrorKind: [`CheckErrorKind::TypeSignatureTooDeep`]
/// Caused by: inserting into a map whose value type already has depth `MAX_TYPE_DEPTH`.
///   The runtime wraps stored entries in an optional, pushing the depth past the limit.
/// Outcome: block accepted.
#[test]
fn check_error_kind_type_signature_too_deep_cdeploy() {
    contract_deploy_consensus_test!(
        contract_name: "type-depth-runtime",
        contract_code: &{
            let optional_layers: usize = MAX_TYPE_DEPTH as usize - 2;

            let mut value_type = String::new();
            for _ in 0..optional_layers {
                value_type.push_str("(optional ");
            }
            value_type.push_str("uint");
            for _ in 0..optional_layers {
                value_type.push(')');
            }

            let mut let_bindings = String::from("(v0 u0)");
            for i in 1..=optional_layers {
                let_bindings.push_str("\n            ");
                let_bindings.push_str(&format!("(v{i} (some v{}))", i - 1));
            }
            let final_var = format!("v{optional_layers}");

            format!(
                "(define-map deep {{ key: uint }} {{ data: {value_type} }})
            (define-constant deep-value
                (let (
                    {let_bindings}
                )
                    {final_var}))
            (begin
                (map-insert deep (tuple (key u0)) (tuple (data deep-value)))
                u0)"
            )
        },
    );
}

/// CheckErrorKind: [`CheckErrorKind::TypeValueError`]
/// Caused by: passing a value of the wrong type to a function.
/// Outcome: block accepted.
#[test]
fn check_error_kind_type_value_error_cdeploy() {
    contract_deploy_consensus_test!(
        contract_name: "check-error-kind",
        contract_code: "
        ;; `as-max-len?` widens `0x` to type `(buff 33)` even though it contains 0 bytes.
        ;; This passes the analyzer but fails at runtime when `principal-of` enforces
        ;; the exact length, raising `CheckErrorKind::TypeValueError`.
        (principal-of? (unwrap-panic (as-max-len? 0x u33)))",
    );
}

// pub enum CheckErrorKind {
//     CostOverflow, // Unreachable: should exceed u64
//     CostBalanceExceeded(ExecutionCost, ExecutionCost), [`check_error_cost_balance_exceeded`]
//     MemoryBalanceExceeded(u64, u64),
//     CostComputationFailed(String), // Unreachable
//     ExecutionTimeExpired,
//     ValueTooLarge, [`check_error_kind_value_too_large`]
//     ValueOutOfBounds,
//     TypeSignatureTooDeep, [`check_error_kind_type_signature_too_deep`]
//     ExpectedName,
//     SupertypeTooLarge,
//     Expects(String),
//     BadMatchOptionSyntax(Box<CheckErrorKind>),
//     BadMatchResponseSyntax(Box<CheckErrorKind>),
//     BadMatchInput(Box<TypeSignature>),
//     ListTypesMustMatch,
//     TypeError(Box<TypeSignature>, Box<TypeSignature>),
//     TypeValueError(Box<TypeSignature>, Box<Value>), [`check_error_kind_type_value_error_cdeploy`]
//     InvalidTypeDescription,
//     UnknownTypeName(String),
//     UnionTypeError(Vec<TypeSignature>, Box<TypeSignature>),
//     UnionTypeValueError(Vec<TypeSignature>, Box<Value>),
//     ExpectedOptionalValue(Box<Value>),
//     ExpectedResponseValue(Box<Value>),
//     ExpectedOptionalOrResponseValue(Box<Value>),
//     ExpectedContractPrincipalValue(Box<Value>),
//     CouldNotDetermineType,
//     BadTokenName,
//     NoSuchNFT(String),
//     NoSuchFT(String),
//     BadTransferSTXArguments,
//     BadTransferFTArguments,
//     BadTransferNFTArguments,
//     BadMintFTArguments,
//     BadBurnFTArguments,
//     ExpectedTuple(Box<TypeSignature>),
//     NoSuchTupleField(String, TupleTypeSignature),
//     EmptyTuplesNotAllowed,
//     NoSuchDataVariable(String),
//     NoSuchMap(String),
//     DefineFunctionBadSignature,
//     BadFunctionName,
//     PublicFunctionMustReturnResponse(Box<TypeSignature>),
//     ReturnTypesMustMatch(Box<TypeSignature>, Box<TypeSignature>),
//     CircularReference(Vec<String>),
//     NoSuchContract(String),
//     NoSuchPublicFunction(String, String),
//     PublicFunctionNotReadOnly(String, String),
//     ContractAlreadyExists(String),
//     ContractCallExpectName,
//     NoSuchBurnBlockInfoProperty(String),
//     NoSuchStacksBlockInfoProperty(String),
//     GetBlockInfoExpectPropertyName,
//     GetStacksBlockInfoExpectPropertyName,
//     GetTenureInfoExpectPropertyName,
//     NameAlreadyUsed(String),
//     NonFunctionApplication,
//     ExpectedListApplication,
//     ExpectedSequence(Box<TypeSignature>),
//     BadLetSyntax,
//     BadSyntaxBinding(SyntaxBindingError),
//     UndefinedFunction(String),
//     UndefinedVariable(String),
//     RequiresAtLeastArguments(usize, usize),
//     RequiresAtMostArguments(usize, usize),
//     IncorrectArgumentCount(usize, usize),
//     TooManyFunctionParameters(usize, usize),
//     TraitReferenceUnknown(String),
//     TraitMethodUnknown(String, String),
//     ExpectedTraitIdentifier,
//     BadTraitImplementation(String, String),
//     DefineTraitBadSignature,
//     DefineTraitDuplicateMethod(String),
//     TraitBasedContractCallInReadOnly,
//     ContractOfExpectsTrait,
//     TraitTooManyMethods(usize, usize),
//     InvalidCharactersDetected,
//     InvalidUTF8Encoding,
//     InvalidSecp65k1Signature,
//     WriteAttemptedInReadOnly,
//     AtBlockClosureMustBeReadOnly,
//     ExpectedListOfAllowances(String, i32),
//     AllowanceExprNotAllowed,
//     ExpectedAllowanceExpr(String),
//     WithAllAllowanceNotAllowed,
//     WithAllAllowanceNotAlone,
//     WithNftExpectedListOfIdentifiers,
//     MaxIdentifierLengthExceeded(u32, u32),
//     TooManyAllowances(usize, usize),
// }

/// CheckErrorKind: [`CheckErrorKind::TypeValueError`]
/// Caused by: passing a value of the wrong type to a function.
/// Outcome: block accepted.
#[test]
fn check_error_kind_type_value_error_ccall() {
    contract_call_consensus_test!(
        contract_name: "check-error-kind",
        contract_code: "(define-public (trigger-error (x uint)) (ok true))",
        function_name: "trigger-error",
        function_args: &[ClarityValue::Bool(true)],
    );
}
