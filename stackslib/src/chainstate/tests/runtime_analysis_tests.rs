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

use std::collections::HashMap;

use clarity::types::StacksEpochId;
#[allow(unused_imports)]
use clarity::vm::analysis::CheckErrorKind;
use clarity::vm::types::{QualifiedContractIdentifier, MAX_TYPE_DEPTH};
use clarity::vm::{ClarityVersion, Value as ClarityValue};

use crate::chainstate::tests::consensus::{
    contract_call_consensus_test, contract_deploy_consensus_test, ConsensusTest, ConsensusUtils,
    SetupContract, TestBlock, EPOCHS_TO_TEST, FAUCET_PRIV_KEY,
};
use crate::core::test_util::to_addr;
use crate::core::BLOCK_LIMIT_MAINNET_21;

/// CheckErrorKind: [`CheckErrorKind::CostBalanceExceeded`]
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

/// CheckErrorKind: [`CheckErrorKind::NameAlreadyUsed`]
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

/// CheckErrorKind: [`CheckErrorKind::ContractCallExpectName`]
/// Caused by: the trait reference is stored as a constant, so the runtime never
///     binds it in `LocalContext::callable_contracts` and `special_contract_call`
///     cannot resolve the callee.
/// Outcome: block accepted.
/// Note: This test only works for Clarity 2 and later.
///     Clarity 1 will not be able to upload contract-3.
#[test]
fn check_error_kind_contract_call_expect_name_cdeploy() {
    let contract_1 = SetupContract::new(
        "contract-1",
        "(define-trait simple-trait (
            (ping () (response bool uint))))",
    );

    let contract_2 = SetupContract::new(
        "contract-2",
        "(impl-trait .contract-1.simple-trait)
         (define-public (ping)
            (ok true))",
    );

    contract_deploy_consensus_test!(
        contract_name: "contract-3",
        contract_code: "
            (use-trait simple-trait .contract-1.simple-trait)

            ;; Evaluated during initialization; runtime cannot resolve the callable.
            (define-constant default-target .contract-2)

            (contract-call? default-target ping)",
        exclude_clarity_versions: &[ClarityVersion::Clarity1],
        setup_contracts: &[contract_1, contract_2],
    );
}

/// CheckErrorKind: [`CheckErrorKind::UnionTypeValueError`]
/// Caused by:
/// Outcome: block accepted.
/// Note: This test only works for Clarity 4 and later.
///     Clarity 1, 2, 3 will return a [`StaticCheckErrorKind::UnknownFunction`].
#[test]
fn check_error_kind_union_type_value_error_cdeploy() {
    let contract_1 = SetupContract::new(
        "contract-1",
        "(define-public (dummy)
                (ok true))",
    );

    contract_deploy_consensus_test!(
        contract_name: "contract-2",
        contract_code: "
            (define-trait trait-1 (
                (dummy () (response bool uint))))

            (define-public (foo (contract <trait-1>))
                (to-ascii? contract))

            (define-constant trigger-error
                (foo .contract-1))",
        exclude_clarity_versions: &[ClarityVersion::Clarity1, ClarityVersion::Clarity2, ClarityVersion::Clarity3],
        setup_contracts: &[contract_1],
    );
}

/// CheckErrorKind: [`CheckErrorKind::ListTypesMustMatch`]
/// Caused by:
/// Outcome: block accepted.
/// Note: The error is only triggered since Clarity 2. In Clarity 1 the tx is valid and accepted.
#[test]
fn check_error_kind_list_types_must_match_cdeploy() {
    let contract_1 = SetupContract::new(
        "contract-1",
        "
(define-trait trait-a (
    (ping () (response bool uint))))

(define-trait trait-b (
    (pong () (response bool uint))))",
    );
    let contract_2 = SetupContract::new(
        "contract-2",
        "
;; Implements both trait interfaces defined in contract-3 and exposes a
;; helper that returns a list mixing the two callable types.

(use-trait trait-a .contract-1.trait-a)
(use-trait trait-b .contract-1.trait-b)

(impl-trait .contract-1.trait-a)
(impl-trait .contract-1.trait-b)

(define-public (ping)
    (ok true))

(define-public (pong)
    (ok true))

(define-public (make-callables (first <trait-a>) (second <trait-b>))
    ;; Returning mixedgenous callable references forces the runtime to
    ;; sanitize a `ListUnionType` value.
    (ok (list first second)))",
    );

    contract_deploy_consensus_test!(
        contract_name: "contract-3",
        contract_code: "
;; Contract under test: during initialization it defines a constant list that
;; mixes callable references to two distinct traits.  The list's entry type is a
;; `ListUnionType`, which the runtime sanitization in `put_value_with_size`
;; cannot admit, triggering `CheckErrorKind::CouldNotDetermineType`.

(use-trait trait-a .contract-1.trait-a)
(use-trait trait-b .contract-1.trait-b)

(define-private (as-trait-a (target <trait-a>)) target)
(define-private (as-trait-b (target <trait-b>)) target)

(define-constant mixed-callables
    (list
        (as-trait-a .contract-2)
        (as-trait-b .contract-2)))

(define-public (noop)
    (ok u0))
",
        setup_contracts: &[contract_1, contract_2],
    );
}

/// CheckErrorKind: [`CheckErrorKind::ExpectedContractPrincipalValue`]
/// Caused by: Supplying tx-sender to with-ft inside as-contract? forces eval_allowance to inspect a standard principal
/// Outcome: block accepted.
/// Note: This test only works for Clarity 4 and later. 'as-contract?' is not supported in earlier versions.
#[test]
fn check_error_kind_expected_contract_principal_value_cdeploy() {
    contract_deploy_consensus_test!(
        contract_name: "contract",
        contract_code: r#"
            (define-constant trigger-error
                (as-contract?
                    ((with-ft tx-sender "token" u0))
                    true))"#,
        exclude_clarity_versions: &[ClarityVersion::Clarity1, ClarityVersion::Clarity2, ClarityVersion::Clarity3],
    );
}

// pub enum CheckErrorKind {
//     CostOverflow, // Unreachable: should exceed u64
//     CostBalanceExceeded(ExecutionCost, ExecutionCost), [`check_error_cost_balance_exceeded_cdeploy`]
//     MemoryBalanceExceeded(u64, u64),
//     CostComputationFailed(String), // Unreachable
//     ExecutionTimeExpired,
//     ValueTooLarge, [`check_error_kind_value_too_large_cdeploy`]
//     ValueOutOfBounds,  // Unreachable: validated before reaching the runtime error
//     TypeSignatureTooDeep, [`check_error_kind_type_signature_too_deep_cdeploy`]
//     ExpectedName,  // Unreachable: every place in the runtime where ExpectedName is raised comes from a direct call to SymbolicExpression::match_atom() on the original AST node and the type checker runs the same structure check during analysis.
//     SupertypeTooLarge, // unreachable: equality's least_supertype checks already run in analysis, and
//                       // runtime values are sanitized to their declared signatures, so the VM never
//                       // sees a pair of values whose unified type wasn't accepted earlier.
//     Expects(String),  // unreachable
//     BadMatchOptionSyntax(Box<CheckErrorKind>), Unreachable: Both the analyzer and the runtime examine the exact same match AST slice. The static pass invokes check_special_match_opt, which enforces the three-argument structure and the some binding name before any code is accepted.
//     BadMatchResponseSyntax(Box<CheckErrorKind>), Unreachable: Both the analyzer and the runtime examine the exact same match AST slice. The static pass invokes check_special_match_resp, which enforces the four-argument structure and the ok and err binding names before any code is accepted.
//     BadMatchInput(Box<TypeSignature>), Unreachable: Both the analyzer and the runtime examine the exact same match AST slice. The static pass invokes check_special_match, which enforces the two-argument structure and the input type before any code is accepted.
//     ListTypesMustMatch, // Unrechable: list construction, append, replace-at?, and cons_list all sanitize their inputs before runtime
//     TypeError(Box<TypeSignature>, Box<TypeSignature>),
//     TypeValueError(Box<TypeSignature>, Box<Value>), [`check_error_kind_type_value_error_cdeploy`]
//     InvalidTypeDescription, // unreachable: every invalid type literal is parsed both
//                             // by the analyzer and by the runtime; both paths invoke
//                             // the same TypeSignature::parse_* helpers, so analysis
//                             // always fails before initialization can trigger it.
//     UnknownTypeName(String), // Unreachable: static analysis catches invalid types via `TypeSignature::parse_atom_type`, returning `StaticCheckErrorKind::UnknownTypeName`.
//     UnionTypeError(Vec<TypeSignature>, Box<TypeSignature>), Unreachable:
//                             // the analyzer enforces that every call to `bit-shift-left` / `bit-shift-right`
//                             // supplies an argument whose type is exactly `int` or `uint` (see
//                             // `NativeFunctions::BitwiseLShift|BitwiseRShift` using
//                             // `FunctionArgSignature::Union(IntType, UIntType)` and the
//                             // `TypeSignature::admits_type` checks in `type_checker::check_function_arg_signature`).
//                             // All dynamic sources that might yield a different runtime value (trait dispatch,
//                             // consensus buffers, callable constants, etc.) either fail earlier with their own
//                             // `CheckErrorKind` (e.g. `ReturnTypesMustMatch`, `UnionTypeValueError`) or sanitize
//                             // the value before it can reach the bitwise native. As a result, the VM never receives
//                             // a non-integer argument at these call sites, so this variant cannot be exercised.
//     UnionTypeValueError(Vec<TypeSignature>, Box<Value>), [`check_error_kind_union_type_value_error_cdeploy`] [`check_error_kind_union_type_value_error_ccall`]
//     ExpectedOptionalValue(Box<Value>),  // Unreachable: every optional primitive (`is-some`,
//                                         // `default-to`, `unwrap!`, etc.) has a dedicated
//                                         // analysis hook (`check_special_is_optional`,
//                                         // `check_special_default_to`, `inner_unwrap`, …) that
//                                         // enforces the optional type before a contract can be
//                                         // published, so the runtime never sees a plain `Value`
//                                         // arrive at `native_default_to` / `is_some`.
//     ExpectedResponseValue(Box<Value>),   // Unreachable for the same reason: response helpers are
//                                         // validated by `check_special_is_response` /
//                                         // `inner_unwrap_err` during static analysis, preventing a
//                                         // non-response from reaching the runtime handlers.
//     ExpectedOptionalOrResponseValue(Box<Value>), // Unreachable: the mixed helpers (`match`,
//                                                  // `try!`, `unwrap!`/`unwrap-err!`) ultimately
//                                                  // delegate to `check_special_match` /
//                                                  // `inner_unwrap` in the analyzer, which enforce
//                                                  // that the argument is either an optional or a
//                                                  // response before the code is accepted. There is
//                                                  // no runtime path where a plain value reaches
//                                                  // `native_try_ret` or the option/response matchers.
//     ExpectedContractPrincipalValue(Box<Value>), [`check_error_kind_expected_contract_principal_value_cdeploy`] [`check_error_kind_expected_contract_principal_value_ccall`]
//     CouldNotDetermineType, [`check_error_kind_could_not_determine_type_cdeploy`] [`check_error_kind_could_not_determine_type_ccall`]
//     BadTokenName,  // Unreachable: asset natives call `match_atom()` on their token arg during analysis,
//     NoSuchNFT(String), // Unreachable: analysis uses contract_context.get_nft_type during every nft-* checker,
//                       // so a reference to an undefined NFT aborts before initialization.
//     NoSuchFT(String),  // Unreachable: ft-* analyzers call contract_context.ft_exists, preventing undefined
//                       // fungible tokens from ever reaching the runtime handlers.
//     BadTransferSTXArguments, // Unreachable: the analyzer routes all `stx-transfer?`,
//                              // `stx-transfer-memo?`, and `stx-burn?` calls through
//                              // `check_special_stx_transfer[_memo]` / `check_special_stx_burn`
//                              // (`clarity/src/vm/analysis/type_checker/v2_1/natives/assets.rs`),
//                              // which demand a `(uint, principal, principal)` (plus memo) signature
//                              // before a contract can be published. Because the runtime caches only
//                              // sanitized values, `special_stx_transfer` never receives a malformed
//                              // tuple of arguments and this variant cannot fire.
//     BadTransferFTArguments,  // Unreachable: `check_special_transfer_token` enforces the
//                              // `(uint, principal, principal)` argument contract for every FT
//                              // transfer during analysis, so `special_transfer_token` never sees a
//                              // mismatched set of values at runtime.
//     BadTransferNFTArguments, // Unreachable: `check_special_transfer_asset` ensures that the NFT
//                              // identifier plus `(principal, principal)` pair have the right types,
//                              // preventing `special_transfer_asset` from failing later.
//     BadMintFTArguments,      // Unreachable: `check_special_mint_token` requires a `(uint, principal)`
//                              // argument tuple for fungible minting before deployment, so the runtime
//                              // never raises `BadMintFTArguments`.
//     BadBurnFTArguments,      // Unreachable: `check_special_burn_token` enforces `(uint, principal)`
//                              // during static analysis, making the runtime variant unobservable.
//     ExpectedTuple(Box<TypeSignature>),        // Unreachable: `check_special_get`/`check_special_merge` ensure every
//                                              // `(get …)`/`(merge …)` argument is statically typed as a tuple (or
//                                              // option wrapping a tuple), so `tuple_get` / `tuple_merge` never see
//                                              // a non-tuple at runtime.
//     NoSuchTupleField(String, TupleTypeSignature), // Unreachable: `check_special_get` verifies tuple field existence
//                                                  // for every `(get …)` (including option-wrapped cases) before
//                                                  // deploy, so `tuple_get` never receives a missing field.
//     EmptyTuplesNotAllowed, // Unreachable: all code paths producing this error call `parse_type_repr`
//                            // (via `TupleTypeSignature::try_from`), which runs during BOTH static
//                            // analysis and runtime. Since static analysis runs first during contract
//                            // deployment, `StaticCheckErrorKind::EmptyTuplesNotAllowed` is always
//                            // triggered before the runtime equivalent. The only other path
//                            // (`TupleData::from_data`) is protected by `check_arguments_at_least(1, args)`
//                            // in `tuple_cons`, preventing empty tuple construction at runtime.
//     NoSuchDataVariable(String), // Unreachable: the analyzer registers every `(define-data-var …)`
//                                 // in `contract_context.meta_data_var` before any other top-level
//                                 // expression runs, so every `var-get`/`var-set` lookup already
//                                 // has a descriptor or fails during static analysis.
//     NoSuchMap(String), // Unreachable: analysis uses contract_context.get_map_type during every
//                        // map-* checker, so a reference to an undefined map aborts before initialization.
//     DefineFunctionBadSignature,
//     BadFunctionName,
//     PublicFunctionMustReturnResponse(Box<TypeSignature>),
//     ReturnTypesMustMatch(Box<TypeSignature>, Box<TypeSignature>), [`check_error_kind_return_types_must_match_ccall`]
//     CircularReference(Vec<String>),
//     NoSuchContract(String), [`check_error_kind_no_such_contract_ccall`]
//     NoSuchPublicFunction(String, String),
//     PublicFunctionNotReadOnly(String, String),
//     ContractAlreadyExists(String),
//     ContractCallExpectName, [`check_error_kind_contract_call_expect_name_cdeploy`]
//     NoSuchBurnBlockInfoProperty(String),
//     NoSuchStacksBlockInfoProperty(String),
//     GetBlockInfoExpectPropertyName,
//     GetStacksBlockInfoExpectPropertyName,
//     GetTenureInfoExpectPropertyName,
//     NameAlreadyUsed(String), [`check_error_kind_name_already_used_cdeploy`]
//     NonFunctionApplication,
//     ExpectedListApplication,
//     ExpectedSequence(Box<TypeSignature>),
//     BadLetSyntax,
//     BadSyntaxBinding(SyntaxBindingError),
//     UndefinedFunction(String),  // Unreachable? Wasn't able to trigger this error during contract initialization.
//     UndefinedVariable(String),
//     RequiresAtLeastArguments(usize, usize),
//     RequiresAtMostArguments(usize, usize),
//     IncorrectArgumentCount(usize, usize), [`check_error_kind_incorrect_argument_count_ccall`]
//     TooManyFunctionParameters(usize, usize),
//     TraitReferenceUnknown(String),
//     TraitMethodUnknown(String, String),
//     ExpectedTraitIdentifier, // Unreachable: callable trait values always carry their trait id after sanitization
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

/// CheckErrorKind: [`CheckErrorKind::IncorrectArgumentCount`]
/// Caused by: passing the wrong number of arguments to a function.
/// Outcome: block accepted.
#[test]
fn check_error_kind_incorrect_argument_count_ccall() {
    contract_call_consensus_test!(
        contract_name: "check-error-kind",
        contract_code: "(define-public (trigger-error (x uint)) (ok true))",
        function_name: "trigger-error",
        function_args: &[ClarityValue::Bool(true), ClarityValue::Bool(true)],
    );
}

/// CheckErrorKind: [`CheckErrorKind::ContractCallExpectName`]
/// Caused by: the trait reference is stored as a constant, so the runtime never
///     binds it in `LocalContext::callable_contracts` and `special_contract_call`
///     cannot resolve the callee.
/// Outcome: block accepted.
/// Note: This test only works for Clarity 2 and later.
///     Clarity 1 will not be able to upload contract-3.
#[test]
fn check_error_kind_contract_call_expect_name_ccall() {
    let contract_1 = SetupContract::new(
        "contract-1",
        "(define-trait simple-trait (
            (ping () (response bool uint))))",
    );

    let contract_2 = SetupContract::new(
        "contract-2",
        "(impl-trait .contract-1.simple-trait)
         (define-public (ping)
            (ok true))",
    );

    contract_call_consensus_test!(
        contract_name: "contract-3",
        contract_code: "
            (use-trait simple-trait .contract-1.simple-trait)

            ;; Trait reference stored as a constant.
            (define-constant default-target .contract-2)

            (define-public (trigger-error)
                (contract-call? default-target ping))",
        function_name: "trigger-error",
        function_args: &[],
        deploy_epochs: EPOCHS_TO_TEST,
        call_epochs: EPOCHS_TO_TEST,
        exclude_clarity_versions: &[ClarityVersion::Clarity1],
        setup_contracts: &[contract_1, contract_2],
    );
}

/// CheckErrorKind: [`CheckErrorKind::NameAlreadyUsed`]
/// Caused by: a `let` binding attempts to shadow the reserved keyword `stacks-block-height`.
///     The analyzer accepts the contract, but binding happens only when the public
///     function executes, so the runtime raises `NameAlreadyUsed`.
/// Outcome: block accepted.
#[test]
fn check_error_kind_name_already_used_ccall() {
    contract_call_consensus_test!(
        contract_name: "name-already-used",
        contract_code: "
        (define-public (trigger-error)
            (let ((ft-get-supply u0))
                (ok ft-get-supply)))",
        function_name: "trigger-error",
        function_args: &[],
    );
}

/// CheckErrorKind: [`CheckErrorKind::UndefinedFunction`]
/// Caused by: invoking a public function name that is not defined in the contract.
/// Outcome: block accepted (transaction aborts with the runtime error).
#[test]
fn check_error_kind_undefined_function_ccall() {
    contract_call_consensus_test!(
        contract_name: "undef-fn-call",
        contract_code: "
        (define-public (noop)
            (ok true))",
        function_name: "missing-func",
        function_args: &[],
    );
}

/// CheckErrorKind: [`CheckErrorKind::ReturnTypesMustMatch`]
/// Caused by: dynamic dispatch through a trait argument returns a value whose type does not
///     conform to the trait specification.
/// Outcome: block accepted.
#[test]
fn check_error_kind_return_types_must_match_ccall() {
    let trait_contract = SetupContract::new(
        "trait-contract",
        "(define-trait simple-trait (
            (get-1 (uint) (response uint uint))))",
    );

    let target_contract =
        SetupContract::new("target-contract", "(define-public (get-1 (x uint)) (ok 1))");

    let target_identifier = QualifiedContractIdentifier::parse(&format!(
        "{}.target-contract",
        to_addr(&FAUCET_PRIV_KEY)
    ))
    .unwrap();

    contract_call_consensus_test!(
        contract_name: "dispatching-contract",
        contract_code: "
        (use-trait simple-trait .trait-contract.simple-trait)
        (define-public (wrapped-get-1 (contract <simple-trait>))
            (contract-call? contract get-1 u0))",
        function_name: "wrapped-get-1",
        function_args: &[ClarityValue::from(target_identifier)],
        setup_contracts: &[trait_contract, target_contract],
    );
}

/// CheckErrorKind: [`CheckErrorKind::NoSuchContract`]
/// Caused by: calling a contract that does not exist.
/// Outcome: block accepted.
#[test]
fn check_error_kind_no_such_contract_ccall() {
    let mut nonce = 0;

    let mut epochs_blocks = HashMap::new();

    for epoch in EPOCHS_TO_TEST {
        let call_tx = ConsensusUtils::new_call_tx(
            nonce,
            "non-existent-contract",
            "this-function-does-not-exist",
        );
        epochs_blocks
            .entry(*epoch)
            .or_insert(vec![])
            .push(TestBlock {
                transactions: vec![call_tx],
            });

        nonce += 1;
    }

    let result = ConsensusTest::new(function_name!(), vec![], epochs_blocks).run();
    insta::assert_ron_snapshot!(result);
}

/// CheckErrorKind: [`CheckErrorKind::UnionTypeValueError`]
/// Caused by:
/// Outcome: block accepted.
/// Note: This test only works for Clarity 4 and later.
///     Clarity 1, 2, 3 will return a [`StaticCheckErrorKind::UnknownFunction`].
#[test]
fn check_error_kind_union_type_value_error_ccall() {
    let contract_1 = SetupContract::new(
        "contract-1",
        "(define-public (dummy)
                (ok true))",
    );

    contract_call_consensus_test!(
        contract_name: "contract-2",
        contract_code: "
            (define-trait trait-1 (
                (dummy () (response bool uint))))

            (define-public (foo (contract <trait-1>))
                (to-ascii? contract))

            (define-public (trigger-runtime-error)
                (foo .contract-1))",
        function_name: "trigger-runtime-error",
        function_args: &[],
        deploy_epochs: &StacksEpochId::ALL[11..], // Epochs 3.3 and later
        exclude_clarity_versions: &[ClarityVersion::Clarity1, ClarityVersion::Clarity2, ClarityVersion::Clarity3],
        setup_contracts: &[contract_1],
    );
}

/// CheckErrorKind: [`CheckErrorKind::ExpectedContractPrincipalValue`]
/// Caused by: Supplying tx-sender to with-ft inside as-contract? forces eval_allowance to inspect a standard principal
/// Outcome: block accepted.
/// Note: This test only works for Clarity 4 and later. 'as-contract?' is not supported in earlier versions.
#[test]
fn check_error_kind_expected_contract_principal_value_ccall() {
    contract_call_consensus_test!(
        contract_name: "contract",
        contract_code: r#"
            (define-public (trigger-error)
                (as-contract?
                    ((with-ft tx-sender "token" u0))
                    true))"#,
        function_name: "trigger-error",
        function_args: &[],
        deploy_epochs: &StacksEpochId::ALL[11..], // Epochs 3.3 and later
        exclude_clarity_versions: &[ClarityVersion::Clarity1, ClarityVersion::Clarity2, ClarityVersion::Clarity3],
    );
}

/// CheckErrorKind: [`CheckErrorKind::CouldNotDetermineType`]
/// Caused by: reading a constant that was created in a pre-2.4 epoch without
///     value sanitization. The constant stores a mixed list of callable
///     references which cannot be sanitized once sanitization is enforced.
/// Outcome: block accepted.
/// Note: This test only works in Clarity 2 deployed in Epoch 2.3.
#[test]
fn check_error_kind_could_not_determine_type_ccall() {
    let trait_contract = SetupContract::new(
        "contract-traits",
        "
        (define-trait trait-a (
            (ping () (response bool uint))))
        (define-trait trait-b (
            (pong () (response bool uint))))",
    )
    .with_epoch(StacksEpochId::Epoch23);

    let trait_impl = SetupContract::new(
        "trait-impl",
        "
        (use-trait trait-a .contract-traits.trait-a)
        (use-trait trait-b .contract-traits.trait-b)

        (impl-trait .contract-traits.trait-a)
        (impl-trait .contract-traits.trait-b)

        (define-public (ping) (ok true))
        (define-public (pong) (ok true))",
    )
    .with_epoch(StacksEpochId::Epoch23);

    contract_call_consensus_test!(
        contract_name: "mixed-constant",
        contract_code: "
        (use-trait trait-a .contract-traits.trait-a)
        (use-trait trait-b .contract-traits.trait-b)

        (define-private (cast-a (target <trait-a>)) target)
        (define-private (cast-b (target <trait-b>)) target)

        (define-constant mixed
            (list
                (cast-a .trait-impl)
                (cast-b .trait-impl)))

        (define-public (trigger-error)
            (ok mixed))",
        function_name: "trigger-error",
        function_args: &[],
        deploy_epochs: &[StacksEpochId::Epoch23],
        call_epochs: &StacksEpochId::ALL[6..], // Epochs 2.4 and later
        exclude_clarity_versions: &[ClarityVersion::Clarity1, ClarityVersion::Clarity3, ClarityVersion::Clarity4],
        setup_contracts: &[trait_contract, trait_impl],
    );
}
