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

//! This module contains consensus tests related to Clarity CheckErrorKind errors that happens during runtime analysis.

use std::collections::HashMap;

use clarity::types::StacksEpochId;
#[allow(unused_imports)]
use clarity::vm::analysis::CheckErrorKind;
#[allow(unused_imports)]
use clarity::vm::costs::CostErrors;
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier, MAX_TYPE_DEPTH};
use clarity::vm::{ClarityVersion, Value as ClarityValue};

use crate::chainstate::tests::consensus::{
    contract_call_consensus_test, contract_deploy_consensus_test, ConsensusTest, ConsensusUtils,
    SetupContract, TestBlock, EPOCHS_TO_TEST, FAUCET_ADDRESS, FAUCET_PRIV_KEY,
};
use crate::core::test_util::to_addr;
use crate::core::BLOCK_LIMIT_MAINNET_21;

/// Generates a coverage classification report for a specific [`CheckErrorKind`] variant.
///
/// This method exists purely for **documentation and tracking purposes**.
/// It helps maintainers understand which error variants have been:
///
/// - ✅ **Tested** — verified through consensus tests.
/// - ⚙️ **Ignored** — not tested on purpose. (e.g. parser v1 related errors).
/// - 🚫 **Unreachable** — not testable from consensus test side for reasons.
#[allow(dead_code)]
fn variant_coverage_report(variant: CheckErrorKind) {
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

    use CheckErrorKind::*;
    use VariantCoverage::*;

    _ = match variant {
        CostOverflow => Unreachable_ExpectLike, // Should exceed u64
        CostBalanceExceeded(_, _) => Tested(vec![
            check_error_cost_balance_exceeded_cdeploy,
            check_error_cost_balance_exceeded_ccall
        ]),
        MemoryBalanceExceeded(_, _) => Tested(vec![
            check_error_memory_balance_exceeded_cdeploy,
            check_error_memory_balance_exceeded_ccall
        ]),
        CostComputationFailed(_) => Tested(vec![
            empty_consensus_buff,
        ]),
        ExecutionTimeExpired => Unreachable_Functionally(
            "All consensus-critical code paths (block validation and transaction processing)
             pass `None` for max_execution_time to StacksChainState::process_transaction,
             causing GlobalContext::execution_time_tracker to remain ExecutionTimeTracker::NoTracking.
             The check_max_execution_time_expired function always returns Ok(()) when tracker
             is NoTracking. Execution time limits are only enforced in RPC API calls
             and miner-local transaction filtering."),
        ValueTooLarge => Tested(vec![
            check_error_kind_value_too_large_cdeploy,
            check_error_kind_value_too_large_ccall
        ]),
        ValueOutOfBounds => todo!(),
        TypeSignatureTooDeep => Tested(vec![
            check_error_kind_type_signature_too_deep_cdeploy,
            check_error_kind_type_signature_too_deep_ccall
        ]),
        ExpectedName => Unreachable_Functionally(
            "Every place in the runtime where ExpectedName is raised comes from a direct
            call to SymbolicExpression::match_atom() on the original AST node and the type
            checker runs the same structure check during analysis."),
        SupertypeTooLarge => Unreachable_Functionally(
            "least_supertype checks already run in analysis, and runtime values are
             sanitized to their declared signatures, so the VM never sees a pair of
             values whose unified type wasn't accepted earlier."),
        ExpectsAcceptable(_) => Unreachable_ExpectLike,
        ExpectsRejectable(_) => Unreachable_ExpectLike,
        BadMatchOptionSyntax(_) => Unreachable_Functionally(
            "Both the analyzer and the runtime examine the exact same match AST slice.
             The static pass invokes check_special_match_opt, which enforces the 3
             argument structure and the some binding name before any code is accepted"),
        BadMatchResponseSyntax(_) => Unreachable_Functionally(
            "Both the analyzer and the runtime examine the exact same match AST slice.
             The static pass invokes check_special_match_resp, which enforces the 4
             argument structure and the ok and err binding names before any code is accepted."),
        BadMatchInput(_) => Unreachable_Functionally(
            "Both the analyzer and the runtime examine the exact same match AST slice.
             The static pass invokes check_special_match, which enforces the 2 argument
             structure and the input type before any code is accepted."),
        ListTypesMustMatch => Tested(vec![check_error_kind_list_types_must_match_cdeploy]),
        TypeError(_, _) => Tested(vec![
            check_error_kind_type_error_cdeploy,
            check_error_kind_type_error_ccall
        ]),
        TypeValueError(_, _) => Tested(vec![
            check_error_kind_type_value_error_cdeploy,
            check_error_kind_type_value_error_ccall
        ]),
        InvalidTypeDescription => Unreachable_Functionally(
            "Every invalid type literal is parsed both by the analyzer and by the runtime.
             Both paths invoke the same TypeSignature::parse_* helpers, so analysis
             always fails before initialization can trigger it."),
        UnknownTypeName(_) => Unreachable_Functionally(
            "Static analysis catches invalid types via `TypeSignature::parse_atom_type`."),
        UnionTypeError(_, _) => Unreachable_Functionally(
            "The analyzer enforces that every call to `bit-shift-left` / `bit-shift-right`
             supplies an argument whose type is exactly `int` or `uint` (see
             `NativeFunctions::BitwiseLShift|BitwiseRShift` using
             `FunctionArgSignature::Union(IntType, UIntType)` and the
             `TypeSignature::admits_type` checks in `type_checker::check_function_arg_signature`)"),
        UnionTypeValueError(_, _) => Tested(vec![
            check_error_kind_union_type_value_error_cdeploy,
            check_error_kind_union_type_value_error_ccall
        ]),
        ExpectedOptionalValue(_) => Unreachable_Functionally(
            "Every optional primitive (`is-some`, `default-to`, `unwrap!`, etc.)
             has a dedicated analysis hook (`check_special_is_optional`,
             `check_special_default_to`, `inner_unwrap`, …) that enforces the optional
             type before a contract can be published, so the runtime never sees a plain
             `Value` arrive at `native_default_to` / `is_some`."),
        ExpectedResponseValue(_) => Unreachable_Functionally(
            "Response helpers are validated by `check_special_is_response` and `inner_unwrap_err`
            during static analysis, preventing a non-response from reaching the runtime handlers"),
        ExpectedOptionalOrResponseValue(_) => Unreachable_Functionally(
            "The mixed helpers (`match`, `try!`, `unwrap!`, `unwrap-err!`) ultimately
             delegate to `check_special_match` and `inner_unwrap` in the analyzer, which enforces
             that the argument is either an optional or a response before the code is accepted.
             There is no runtime path where a plain value reaches `native_try_ret` or the
             option/response matchers"),
        ExpectedContractPrincipalValue(_) => Tested(vec![
            check_error_kind_expected_contract_principal_value_cdeploy,
            check_error_kind_expected_contract_principal_value_ccall
        ]),
        CouldNotDetermineType => Tested(vec![check_error_kind_could_not_determine_type_ccall]),
        BadTokenName => Unreachable_Functionally(
            "Asset natives call `match_atom()` on their token arg during analysis."),
        NoSuchNFT(_) => Unreachable_Functionally(
            "Analysis uses contract_context.get_nft_type during every nft-* checker,
             so a reference to an undefined NFT aborts before initialization"),
        NoSuchFT(_) => Unreachable_Functionally(
            "ft-* analyzers call contract_context.ft_exists, preventing undefined
             fungible tokens from ever reaching the runtime handlers."),
        BadTransferSTXArguments => Unreachable_Functionally(
            "The analyzer routes all `stx-transfer?`, `stx-transfer-memo?`, and `stx-burn?`
             calls through `check_special_stx_transfer` / `check_special_stx_burn`
             which demand a `(uint, principal, principal)` signature before a contract
             can be published. Because the runtime caches only sanitized values,
             `special_stx_transfer` never receives a malformed value at runtime."),
        BadTransferFTArguments => Unreachable_Functionally(
            "`check_special_transfer_token` enforces the `(uint, principal, principal)`
            argument contract for every FT transfer during analysis, so `special_transfer_token`
            never sees a mismatched set of values at runtime."),
        BadTransferNFTArguments => Unreachable_Functionally(
            "`check_special_transfer_asset` ensures that the NFT
            identifier plus `(principal, principal)` pair have the right types,
            preventing `special_transfer_asset` from failing at runtime."),
        BadMintFTArguments => Unreachable_Functionally(
            "`check_special_mint_token` requires a `(uint, principal)`
             argument tuple for fungible minting before deployment, so the runtime
             never raises `BadMintFTArguments`"),
        BadBurnFTArguments => Unreachable_Functionally(
            "`check_special_burn_token` enforces `(uint, principal)`
             during static analysis, making the runtime variant unobservable."),
        ExpectedTuple(_) => Unreachable_Functionally(
            "`check_special_get`/`check_special_merge` ensure every
             `(get …)`/`(merge …)` argument is statically typed as a tuple (or
             option wrapping a tuple), so `tuple_get` / `tuple_merge` never see
             a non-tuple at runtime"),
        NoSuchTupleField(_, _) => Unreachable_Functionally(
            "`check_special_get` verifies tuple field existence for every `(get …)`
             during static analysis, so `tuple_get` never receives a missing field"),
        DefineFunctionBadSignature | BadFunctionName | PublicFunctionMustReturnResponse(_) => Unreachable_Functionally(
            "On contract deploy checked during static analysis."),
        EmptyTuplesNotAllowed | NoSuchMap(_) => Unreachable_Functionally(
            "On contract deploy checked during static analysis. (At runtime, just used for loading cost functions on block begin)"),
        NoSuchDataVariable(_) => Unreachable_Functionally(
            "On contract deploy checked during static analysis. (At runtime, just used for loading cost functions on block begin and for handle prepare phase)"),
        ReturnTypesMustMatch(_, _) => Tested(vec![check_error_kind_return_types_must_match_ccall]),
        CircularReference(_) => Tested(vec![check_error_kind_circular_reference_ccall]), // Possible only during contract call. On contract deploy checked during parsing.
        NoSuchContract(_) => Tested(vec![check_error_kind_no_such_contract_ccall]),
        NoSuchPublicFunction(_, _) => Tested(vec![check_error_kind_no_such_public_function_ccall]),
        PublicFunctionNotReadOnly(_, _) => Unreachable_Functionally("Environment::inner_execute_contract is invoked with read_only = false on the relevant code path, causing PublicFunctionNotReadOnly check to be skipped."),
        ContractAlreadyExists(_) => Unreachable_Functionally(
            "Contracts can only be created via SmartContract deployment transactions. \
             The runtime never performs contract installation or replacement.",
        ),
        ContractCallExpectName => Tested(vec![
            check_error_kind_contract_call_expect_name_cdeploy,
            check_error_kind_contract_call_expect_name_ccall
        ]),
        NoSuchBurnBlockInfoProperty(_) => Unreachable_Functionally(
            "Burn block info property names are validated during static analysis; \
             unknown properties are rejected at deploy time.",
        ),
        NoSuchStacksBlockInfoProperty(_) => Unreachable_Functionally(
            "Stacks block info property names are validated during static analysis; \
             unknown properties are rejected at deploy time.",
        ),
        GetBlockInfoExpectPropertyName => Unreachable_Functionally(
            "`get-block-info?` requires a literal property name; \
             non-atom arguments are rejected during static analysis.",
        ),
        GetStacksBlockInfoExpectPropertyName => Unreachable_Functionally(
            "`get-stacks-block-info?` requires a literal property name; \
             non-atom arguments are rejected during static analysis.",
        ),
        GetTenureInfoExpectPropertyName => Unreachable_Functionally(
            "`get-tenure-info?` requires a literal property name; \
             non-atom arguments are rejected during static analysis.",
        ),
        NameAlreadyUsed(_) => Tested(vec![
            check_error_kind_name_already_used_cdeploy,
            check_error_kind_name_already_used_ccall
        ]),
        NonFunctionApplication => Unreachable_Functionally(
            "Malformed function applications are syntactically rejected by the parser \
             and type checker before execution.",
        ),
        ExpectedListApplication => Unreachable_Functionally(
            "All `append` operations require a statically-checked list argument; \
             non-list values are rejected during static analysis.",
        ),
        ExpectedSequence(_) => Unreachable_Functionally(
            "Sequence operations are fully type-checked during analysis; \
             non-sequence values are rejected before execution.",
        ),
        BadLetSyntax => Unreachable_Functionally(
            "`let` binding structure is fully validated during static analysis; \
             malformed bindings never reach the runtime.",
        ),
        BadSyntaxBinding(_) => Unreachable_Functionally(
            "Binding syntax errors are detected during parsing and analysis; \
             runtime never re-parses bindings.",
        ),
        UndefinedFunction(_) => Tested(vec![check_error_kind_undefined_function_ccall]),
        UndefinedVariable(_) => Unreachable_Functionally(
            "All variable references are resolved during static analysis; \
             undefined variables cannot appear in executable code.",
        ),
        RequiresAtLeastArguments(_, _) => Unreachable_Functionally(
            "Minimum arity requirements are enforced during static analysis; \
             calls with too few arguments cannot reach execution.",
        ),
        RequiresAtMostArguments(_, _) => Unreachable_Functionally(
            "Maximum arity requirements are enforced during static analysis; \
             calls with too many arguments cannot reach execution.",
        ),
        IncorrectArgumentCount(_, _) => {
            Tested(vec![check_error_kind_incorrect_argument_count_ccall])
        }
        TooManyFunctionParameters(_, _) => Unreachable_Functionally(
            "Trait function parameter limits are enforced during trait parsing at deploy time; \
             oversized signatures are rejected before execution.",
        ),
        TraitReferenceUnknown(_) => Unreachable_Functionally(
            "All `use-trait` references are validated during static analysis; \
             unknown traits cannot appear at runtime.",
        ),
        TraitMethodUnknown(_, _) => Unreachable_Functionally(
            "Trait method existence is verified during static analysis; \
             missing methods prevent deployment.",
        ),
        ExpectedTraitIdentifier => Unreachable_Functionally(
            "Callable trait values always include a trait identifier after analysis; \
             the runtime never receives an untagged trait value.",
        ),
        BadTraitImplementation(_, _) => Tested(vec![bad_trait_implementation_mismatched_args]),
        DefineTraitBadSignature | DefineTraitDuplicateMethod(_) => Unreachable_Functionally(
            "Trait definitions are fully validated during deployment; \
             malformed trait signatures never reach runtime.",
        ),
        TraitBasedContractCallInReadOnly => Unreachable_Functionally(
            "Read-only contract-call restrictions are enforced during static analysis; \
             write-capable calls cannot exist in executable read-only code.",
        ),
        ContractOfExpectsTrait => Unreachable_Functionally(
            "`contract-of` only accepts statically-typed trait values; \
             invalid inputs are rejected during analysis.",
        ),
        TraitTooManyMethods(_, _) => Unreachable_Functionally(
            "Trait method count limits are enforced during deployment; \
             oversized traits cannot appear at runtime.",
        ),
        InvalidCharactersDetected => Tested(vec![
            invalid_characters_detected_invalid_ascii,
            invalid_characters_detected_invalid_utf8
        ]),
        InvalidUTF8Encoding => {
            Ignored("Only reachable via legacy v1 parsing paths")
        }
        WriteAttemptedInReadOnly => Unreachable_Functionally(
            "Write operations inside read-only contexts are rejected during static analysis.",
        ),
        ExpectedListOfAllowances(_, _)
        | AllowanceExprNotAllowed
        | ExpectedAllowanceExpr(_)
        | TooManyAllowances(_, _) => Unreachable_Functionally(
            "Allowance expressions are purely syntactic and fully validated during analysis; \
                 invalid constructions cannot be produced dynamically at runtime.",
        ),
    };
}

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

/// CheckErrorKind: [`CheckErrorKind::MemoryBalanceExceeded`]
/// Caused by: This test creates a contract that successfully passes analysis but fails during initialization
///   The contract defines large buffer constants (buff-20 = 1MB) and then creates many references
///   to it in a top-level `is-eq` expression, which exhausts the 100MB memory limit during initialization.
/// Outcome: block accepted.
#[test]
fn check_error_memory_balance_exceeded_cdeploy() {
    contract_deploy_consensus_test!(
        contract_name: "test-exceeds",
        contract_code: &{
            let define_data_var = "(define-constant buff-0 0x00)";

            let mut contract = define_data_var.to_string();
            for i in 0..20 {
                contract.push('\n');
                contract.push_str(&format!(
                    "(define-constant buff-{} (concat buff-{i} buff-{i}))",
                    i + 1,
                ));
            }

            contract.push('\n');
            contract.push_str("(is-eq ");

            for _i in 0..100 {
                let exploder = "buff-20 ";
                contract.push_str(exploder);
            }

            contract.push(')');
            contract
        },
    );
}

/// CheckErrorKind: [`CheckErrorKind::MemoryBalanceExceeded`]
/// Caused by: This test creates a contract that successfully passes analysis but fails during contract call.
///   The contract defines large buffer constants (buff-20 = 1MB) and then creates many references
///   to it in a top-level `is-eq` expression, which exhausts the 100MB memory limit during contract call.
/// Outcome: block accepted.
#[test]
fn check_error_memory_balance_exceeded_ccall() {
    contract_call_consensus_test!(
        contract_name: "memory-test-contract",
        contract_code: &{
            // Procedurally generate a contract with large buffer constants and a function
            // that creates many references to them, similar to argument_memory_test
            let mut contract = String::new();

            // Create buff-0 through buff-20 via repeated doubling: buff-20 = 1MB
            contract.push_str("(define-constant buff-0 0x00)\n");
            for i in 0..20 {
                contract.push_str(&format!(
                    "(define-constant buff-{} (concat buff-{i} buff-{i}))\n",
                    i + 1
                ));
            }

            // Create a public function that makes many references to buff-20
            contract.push_str("\n(define-public (create-many-references)\n");
            contract.push_str("    (ok (is-eq ");

            // Create 100 references to buff-20 (1MB each = ~100MB total)
            for _ in 0..100 {
                contract.push_str("buff-20 ");
            }

            contract.push_str(")))\n");
            contract
        },
        function_name: "create-many-references",
        function_args: &[],
        // we only test epochs 2.4 and later because the call takes ~200 milion runtime cost,
        // if we test all epochs, the tenure limit will be exceeded and the last 2 calls in
        // epoch 3.3 will cause a block rejection.
        deploy_epochs: &StacksEpochId::since(StacksEpochId::Epoch24),
    );
}

/// CheckErrorKind: [`CheckErrorKind::CostBalanceExceeded`]
/// Caused by: exceeding the cost analysis budget during contract initialization.
///   The contract repeatedly performs `var-get` lookups on a data variable,
///   forcing the type checker to fetch the variable enough times to exceed
///   the read-count limit in [`BLOCK_LIMIT_MAINNET_21`].
/// Outcome: block rejected.
#[test]
fn check_error_cost_balance_exceeded_ccall() {
    contract_call_consensus_test!(
        contract_name: "cost-balance-exceeded",
        contract_code: &format!("
        (define-data-var foo int 1)
        (define-public (trigger-error)
            (ok (begin
                {}
                u0)))",
            "(var-get foo)\n".repeat(BLOCK_LIMIT_MAINNET_21.read_count as usize + 1)
        ),
        function_name: "trigger-error",
        function_args: &[],
    );
}

/// CheckErrorKind: [`CheckErrorKind::NoSuchPublicFunction`]
/// Caused by: Attempted to invoke a private function from outside the contract.
/// Outcome: block accepted
#[test]
fn check_error_kind_no_such_public_function_ccall() {
    contract_call_consensus_test!(
        contract_name: "target-contract",
        contract_code: "(define-private (get-one) (ok u1))",
        function_name: "get-one",
        function_args: &[],
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

/// CheckErrorKind: [`CheckErrorKind::ValueTooLarge`]
/// Caused by: `(as-max-len? …)` wraps a buffer whose serialized size plus the optional wrapper
///   exceeds `MAX_VALUE_SIZE`. Static analysis allows this construction, but initialization fails
///   at runtime when `Value::some` detects the oversized payload.
/// Outcome: block accepted.
#[test]
fn check_error_kind_value_too_large_ccall() {
    contract_call_consensus_test!(
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

        (define-public (trigger-error)
            (ok (begin
                (unwrap-panic (as-max-len? (make-buff-1048576) u1048576))
                u0)))
    "#,
        function_name: "trigger-error",
        function_args: &[],
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

/// CheckErrorKind: [`CheckErrorKind::TypeSignatureTooDeep`]
/// Caused by: inserting into a map whose value type already has depth `MAX_TYPE_DEPTH`.
///   The runtime wraps stored entries in an optional, pushing the depth past the limit.
/// Outcome: block accepted.
#[test]
fn check_error_kind_type_signature_too_deep_ccall() {
    contract_call_consensus_test!(
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
            (define-public (trigger-error)
                (ok (begin
                    (map-insert deep (tuple (key u0)) (tuple (data deep-value)))
                    u0)))")
        },
        function_name: "trigger-error",
        function_args: &[],
    );
}

/// CheckErrorKind: [`CheckErrorKind::TypeError`]
/// Caused by: `(at-block … (ok (var-get zero)))` returns `none` when evaluated at
/// a block where the contract state doesn't exist yet. The code immediately feeds
/// that `OptionalType(NoType)` value into `is-eq` against `u0`, triggering the
/// runtime `TypeError(UIntType, OptionalType(NoType))`.
/// Outcome: block accepted.
#[test]
fn check_error_kind_type_error_cdeploy() {
    let contract_1 = SetupContract::new(
        "pool-trait",
        "
    (define-trait pool-trait
        ((get-shares-at (uint) (response uint uint))))",
    );

    let contract_2 = SetupContract::new(
        "pool",
        "
    ;; Pool - uses at-block with map access
    (impl-trait .pool-trait.pool-trait)

    (define-data-var zero uint u0)

    (define-read-only (get-shares-at (block uint))
        (let (
            (hash (unwrap-panic (get-block-info? id-header-hash block)))
            (total-amt (unwrap-panic (at-block hash (ok (var-get zero)))))
            (is-zero (is-eq total-amt u0))) ;; this is triggering the TypeError
        (ok u0)))",
    )
    .with_clarity_version(ClarityVersion::Clarity2); // Only works with clarity 1 or 2

    contract_deploy_consensus_test!(
        contract_name: "value-too-large",
        contract_code: "
    ;; Rewards - calls pool via trait
    (use-trait pool-trait .pool-trait.pool-trait)

    (define-map reward-info { id: uint } { share-block: uint })

    (define-read-only (get-reward-info (id uint))
        (default-to { share-block: u0 } (map-get? reward-info { id: id })))

    (define-public (get-shares (id uint) (pool <pool-trait>))
        (let (
            (info (get-reward-info id))
            (block (get share-block info))
            ;; the following line triggers the TypeError
            (shares (unwrap-panic (contract-call? pool get-shares-at block))))
        (ok shares)))

    (define-constant result (get-shares u999 .pool))",
        setup_contracts: &[contract_1, contract_2],
    );
}

/// CheckErrorKind: [`CheckErrorKind::TypeError`]
/// Caused by: `(at-block … (ok (var-get zero)))` returns `none` when evaluated at
/// a block where the contract state doesn't exist yet. The code immediately feeds
/// that `OptionalType(NoType)` value into `is-eq` against `u0`, triggering the
/// runtime `TypeError(UIntType, OptionalType(NoType))`.
/// Outcome: block accepted.
#[test]
fn check_error_kind_type_error_ccall() {
    let contract_1 = SetupContract::new(
        "pool-trait",
        "
    (define-trait pool-trait
        ((get-shares-at (uint) (response uint uint))))",
    );

    let contract_2 = SetupContract::new(
        "pool",
        "
    ;; Pool - uses at-block with map access
    (impl-trait .pool-trait.pool-trait)

    (define-data-var zero uint u0)

    (define-read-only (get-shares-at (block uint))
        (let (
            (hash (unwrap-panic (get-block-info? id-header-hash block)))
            (total-amt (unwrap-panic (at-block hash (ok (var-get zero)))))
            (is-zero (is-eq total-amt u0))) ;; this is triggering the TypeError
        (ok u0)))",
    )
    .with_clarity_version(ClarityVersion::Clarity1); // Only works with clarity 1 or 2

    contract_call_consensus_test!(
        contract_name: "value-too-large",
        contract_code: "
    (use-trait pool-trait .pool-trait.pool-trait)

    (define-map reward-info { id: uint } { share-block: uint })

    (define-read-only (get-reward-info (id uint))
        (default-to { share-block: u0 } (map-get? reward-info { id: id })))

    (define-public (get-shares (id uint) (pool <pool-trait>))
        (let (
            (info (get-reward-info id))
            (block (get share-block info))
            ;; the following line triggers the TypeError
            (shares (unwrap-panic (contract-call? pool get-shares-at block))))
        (ok shares)))

    (define-public (trigger-error)
        (get-shares u999 .pool))",
        function_name: "trigger-error",
        function_args: &[],
        setup_contracts: &[contract_1, contract_2],
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

/// CheckErrorKind: [`CheckErrorKind::UnionTypeValueError`]
/// Caused by: evaluating `to-ascii?` with a `(contract <trait-1>)` argument while the contract
///     is being initialized. The static analysis accepts the form, but the runtime encounters a
///     `CallableContract` value and the runtime rejects it with the union type error.
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

/// CheckErrorKind: [`CheckErrorKind::UnionTypeValueError`]
/// Caused by: executing `to-ascii?` inside a public function with a `(contract <trait-1>)`
///     argument. Deployment succeeds, but calling `trigger-runtime-error` binds a
///     `CallableContract` value and the runtime rejects it with the union type error.
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
        deploy_epochs: &StacksEpochId::since(StacksEpochId::Epoch33),
        exclude_clarity_versions: &[ClarityVersion::Clarity1, ClarityVersion::Clarity2, ClarityVersion::Clarity3],
        setup_contracts: &[contract_1],
    );
}

/// CheckErrorKind: [`CheckErrorKind::ListTypesMustMatch`]
/// Caused by: Contract initialization creates a constant list that mixes callable values
///     implementing different traits (`trait-a` vs `trait-b`). Runtime sanitization tries to
///     coerce that mixed list into a single entry type and fails with `ListTypesMustMatch`.
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
;; mixes callable references to two distinct traits. That at runtime triggers a
;; `ListTypesMustMatch` error.

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
        deploy_epochs: &StacksEpochId::since(StacksEpochId::Epoch33),
        exclude_clarity_versions: &[ClarityVersion::Clarity1, ClarityVersion::Clarity2, ClarityVersion::Clarity3],
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
        call_epochs: &StacksEpochId::since(StacksEpochId::Epoch24),
        exclude_clarity_versions: &[
            ClarityVersion::Clarity1,
            ClarityVersion::Clarity3,
            ClarityVersion::Clarity4,
            ClarityVersion::Clarity5
        ],
        setup_contracts: &[trait_contract, trait_impl],
    );
}

/// CheckErrorKind: [`CheckErrorKind::CircularReference`]
/// Caused by: circular reference forcing a contract calling itself using a contract call.
/// Outcome: block accepted
#[test]
fn check_error_kind_circular_reference_ccall() {
    let trait_contract = SetupContract::new(
        "trait-contract",
        "(define-trait trait-1 (
                (get-1 (uint) (response uint uint))))",
    );

    let dispatching_contract = SetupContract::new(
        "dispatch-contract",
        "(use-trait trait-1 .trait-contract.trait-1)
            (define-public (wrapped-get-1 (contract <trait-1>))
                (contract-call? contract get-1 u0))
            (define-public (get-1 (x uint)) (ok u1))",
    );

    let dispatch_principal =
        QualifiedContractIdentifier::parse(&format!("{}.dispatch-contract", *FAUCET_ADDRESS))
            .unwrap();

    // The main contract is required because `contract_call_consensus_test!` needs a deployed contract.
    // As a result, `dispatch-contract` cannot be used directly, because need to be passed as `function_args`,
    // and the consensus test mangles the `contract_name`.
    let main_contract = "(use-trait trait-1 .trait-contract.trait-1)
            (define-public (main-get-1 (contract <trait-1>))
            (contract-call? .dispatch-contract wrapped-get-1 contract))";

    contract_call_consensus_test!(
        contract_name: "main-contract",
        contract_code: main_contract,
        function_name: "main-get-1",
        function_args: &[ClarityValue::from(dispatch_principal)],
        setup_contracts: &[trait_contract, dispatching_contract],
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

/// Error: [`CheckErrorKind::BadTraitImplementation`]
/// Caused by: Dynamic trait dispatch to a concrete contract that has the function,
/// but with a mismatched argument type (int instead of uint)
/// Outcome: Block accepted
#[test]
fn bad_trait_implementation_mismatched_args() {
    let trait_definer = SetupContract::new(
        "traits",
        "
        (define-trait getter-trait
            ((get-1 (uint) (response uint uint))))
        ",
    );

    // Target contract has `get-1`, but it takes `int`, not `uint` → signature mismatch
    let target_contract = SetupContract::new(
        "target-contract",
        "
        (define-public (get-1 (x int))
            (ok u1))
        ",
    );

    contract_call_consensus_test!(
        contract_name: "dispatching-contract",
        contract_code: "
            (use-trait getter-trait .traits.getter-trait)

            (define-public (wrapped-get-1 (contract <getter-trait>))
                (contract-call? contract get-1 u0))
        ",
        function_name: "wrapped-get-1",
        function_args: &[ClarityValue::Principal(PrincipalData::Contract(
            QualifiedContractIdentifier::new(
                FAUCET_ADDRESS.clone().into(),
                "target-contract".into(),
            )
        ))],
        setup_contracts: &[trait_definer, target_contract],
    );
}

/// Error: [`CheckErrorKind::InvalidCharactersDetected`]
/// Caused by: deserializing an invalid ascii string using `from-consensus-buff?` which eventually calls [`ClarityValue::string_ascii_from_bytes`].
/// Outcome: Block accepted
/// Note: [`CheckErrorKind::InvalidCharactersDetected`] is converted to a serialization error in `inner_deserialize_read` which in turn is
/// converted to `None` in `conversions::from_consensus_buff` during its handling of the result of `try_deserialize_bytes_exact`.
#[test]
fn invalid_characters_detected_invalid_ascii() {
    contract_deploy_consensus_test!(
        contract_name: "invalid-ascii",
        contract_code: "
            (define-constant deserialized-invalid-ascii
                ;; This buffer represents: string-ascii with bytes [0x00, 0x01, 0x02]
                ;; (0x0d = string-ascii type, 0x00000003 = length 3, then invalid bytes)
                (from-consensus-buff? (string-ascii 3) 0x0d00000003000102))
        ",
        exclude_clarity_versions: &[ClarityVersion::Clarity1], // Clarity1 does not support from-consensus-buff?
    );
}

/// Error: [`CheckErrorKind::InvalidCharactersDetected`]
/// Caused by: deserializing an invalid utf8 string using `from-consensus-buff?` which eventually calls [`ClarityValue::string_utf8_from_bytes`].
/// Outcome: Block accepted
/// Note: [`CheckErrorKind::InvalidCharactersDetected`] is converted to a serialization error in `inner_deserialize_read` which in turn is
/// converted to `None` in `conversions::from_consensus_buff` during its handling of the result of `try_deserialize_bytes_exact`.
#[test]
fn invalid_characters_detected_invalid_utf8() {
    contract_deploy_consensus_test!(
        contract_name: "invalid-utf8",
        contract_code: "
            (define-constant deserialized-invalid-utf8
                ;; This buffer represents: string-utf8 with invalid UTF-8 bytes [0xff, 0xfe]
                ;; (0x0e = string-utf8 type, 0x00000002 = length 2, then invalid UTF-8)
                (from-consensus-buff? (string-utf8 2) 0x0e00000002fffe))
        ",
        exclude_clarity_versions: &[ClarityVersion::Clarity1], // Clarity1 does not support from-consensus-buff?
    );
}

/// Error (pre 3.4): [`CostErrors::CostComputationFailed`]
/// Caused by: passing an empty buffer to `from-consensus-buff?`
/// Outcome: block accepted.
/// After 3.4: Contract call executes successfully and returns `(ok none)`
#[test]
fn empty_consensus_buff() {
    contract_call_consensus_test!(
        contract_name: "check-error-kind",
        contract_code: "(define-public (deserialize-bool (b (buff 2))) (ok (from-consensus-buff? bool b)))",
        function_name: "deserialize-bool",
        function_args: &[ClarityValue::buff_from([].into()).expect("failed to build buffer")],
        deploy_epochs: StacksEpochId::since(clarity::types::StacksEpochId::Epoch21),
        exclude_clarity_versions: &[ClarityVersion::Clarity1], // Clarity1 does not support from-consensus-buff?
    );
}
