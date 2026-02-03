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

//! This module contains consensus tests related to Clarity StaticCheckErrorKind errors that happens during contract analysis.

use std::collections::HashMap;

use clarity::types::StacksEpochId;
use clarity::vm::analysis::type_checker::v2_1::{MAX_FUNCTION_PARAMETERS, MAX_TRAIT_METHODS};
#[allow(unused_imports)]
use clarity::vm::analysis::StaticCheckErrorKind;
use clarity::vm::types::MAX_TYPE_DEPTH;
use clarity::vm::ClarityVersion;

use crate::chainstate::tests::consensus::{
    clarity_versions_for_epoch, contract_deploy_consensus_test, ConsensusTest, ConsensusUtils,
    SetupContract, TestBlock, EPOCHS_TO_TEST,
};
use crate::core::BLOCK_LIMIT_MAINNET_21;
use crate::util_lib::boot::boot_code_test_addr;

/// Generates a coverage classification report for a specific [`StaticCheckErrorKind`] variant.
///
/// This method exists purely for **documentation and tracking purposes**.
/// It helps maintainers understand which error variants have been:
///
/// - ✅ **Tested** — verified through consensus tests.
/// - ⚙️ **Ignored** — not tested on purpose.
/// - 🚫 **Unreachable** — not testable from consensus test side for reasons.
#[allow(dead_code)]
fn variant_coverage_report(variant: StaticCheckErrorKind) {
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

    use StaticCheckErrorKind::*;
    use VariantCoverage::*;

    _ = match variant {
        CostOverflow => Unreachable_ExpectLike, // Should exceed u64
        CostBalanceExceeded(execution_cost, execution_cost1) => Tested(vec![static_check_error_cost_balance_exceeded]),
        MemoryBalanceExceeded(_, _) => Tested(vec![static_check_error_memory_balance_exceeded]),
        CostComputationFailed(_) => Unreachable_ExpectLike,
        ExecutionTimeExpired => Unreachable_Functionally("Can only be triggered at runtime."),
        ValueTooLarge => Tested(vec![static_check_error_value_too_large]),
        ValueOutOfBounds => Tested(vec![static_check_error_value_out_of_bounds]),
        TypeSignatureTooDeep => Tested(vec![static_check_error_type_signature_too_deep]),
        ExpectedName => Tested(vec![static_check_error_expected_name]),
        SupertypeTooLarge => Tested(vec![static_check_error_supertype_too_large]),
        ExpectsAcceptable(_) => Unreachable_ExpectLike,
        ExpectsRejectable(_) => Unreachable_ExpectLike,
        BadMatchOptionSyntax(static_check_error_kind) => {
            Tested(vec![static_check_error_bad_match_option_syntax])
        }
        BadMatchResponseSyntax(static_check_error_kind) => {
            Tested(vec![static_check_error_bad_match_response_syntax])
        }
        BadMatchInput(type_signature) => Tested(vec![static_check_error_bad_match_input]),
        ConstructedListTooLarge => Tested(vec![static_check_error_constructed_list_too_large]),
        TypeError(type_signature, type_signature1) => Tested(vec![static_check_error_type_error]),
        InvalidTypeDescription => Tested(vec![static_check_error_invalid_type_description]),
        UnknownTypeName(_) => Tested(vec![static_check_error_unknown_type_name]),
        UnionTypeError(type_signatures, type_signature) => {
            Tested(vec![static_check_error_union_type_error])
        }
        ExpectedOptionalType(type_signature) => {
            Tested(vec![static_check_error_expected_optional_type])
        }
        ExpectedResponseType(type_signature) => {
            Tested(vec![static_check_error_expected_response_type])
        }
        ExpectedOptionalOrResponseType(type_signature) => {
            Tested(vec![static_check_error_expected_optional_or_response_type])
        }
        CouldNotDetermineResponseOkType => Tested(vec![
            static_check_error_could_not_determine_response_ok_type,
        ]),
        CouldNotDetermineResponseErrType => Tested(vec![
            static_check_error_could_not_determine_response_err_type,
        ]),
        CouldNotDetermineSerializationType => Tested(vec![
            static_check_error_could_not_determine_serialization_type,
        ]),
        UncheckedIntermediaryResponses => Tested(vec![static_check_error_unchecked_intermediary_responses]),
        CouldNotDetermineMatchTypes => Tested(vec![static_check_error_could_not_determine_match_types]),
        CouldNotDetermineType => Tested(vec![static_check_error_could_not_determine_type]),
        TypeAlreadyAnnotatedFailure => Unreachable_Functionally("The AST assigner gives each node a unique `id`, and the type checker visits each node exactly once, so duplicate annotations cannot occur."),
        CheckerImplementationFailure => Unreachable_ExpectLike,
        BadTokenName => Tested(vec![static_check_error_bad_token_name]),
        DefineNFTBadSignature => Tested(vec![static_check_error_define_nft_bad_signature]),
        NoSuchNFT(_) => Tested(vec![static_check_error_no_such_nft]),
        NoSuchFT(_) => Tested(vec![static_check_error_no_such_ft]),
        BadTupleFieldName => Tested(vec![static_check_error_bad_tuple_field_name]),
        ExpectedTuple(type_signature) => Tested(vec![static_check_error_expected_tuple]),
        NoSuchTupleField(_, tuple_type_signature) => Tested(vec![static_check_error_no_such_tuple_field]),
        EmptyTuplesNotAllowed => Tested(vec![static_check_error_empty_tuples_not_allowed]),
        BadTupleConstruction(_) => Tested(vec![static_check_error_bad_tuple_construction]),
        NoSuchDataVariable(_) => Tested(vec![static_check_error_no_such_data_variable]),
        BadMapName => Tested(vec![static_check_error_bad_map_name]),
        NoSuchMap(_) => Tested(vec![static_check_error_no_such_map]),
        DefineFunctionBadSignature => Tested(vec![static_check_error_define_function_bad_signature]),
        BadFunctionName => Tested(vec![static_check_error_bad_function_name]),
        BadMapTypeDefinition => Tested(vec![static_check_error_bad_map_type_definition]),
        PublicFunctionMustReturnResponse(type_signature) => Tested(vec![static_check_error_public_function_must_return_response]),
        DefineVariableBadSignature => Tested(vec![static_check_error_define_variable_bad_signature]),
        ReturnTypesMustMatch(type_signature, type_signature1) => Tested(vec![static_check_error_return_types_must_match]),
        NoSuchContract(_) => Tested(vec![static_check_error_no_such_contract]),
        NoSuchPublicFunction(_, _) => Tested(vec![static_check_error_no_such_public_function]),
        ContractAlreadyExists(_) => Unreachable_Functionally("During normal operations, `StacksChainState::process_transaction_payload` will check if the contract exists already, invalidating the block before executing analysis. see `error_invalid_stacks_transaction_duplicate_contract`"),
        ContractCallExpectName => Tested(vec![static_check_error_contract_call_expect_name]),
        ExpectedCallableType(type_signature) => Tested(vec![static_check_error_expected_callable_type]),
        NoSuchBlockInfoProperty(_) => Tested(vec![static_check_error_no_such_block_info_property]),
        NoSuchStacksBlockInfoProperty(_) => Tested(vec![static_check_error_no_such_stacks_block_info_property]),
        NoSuchTenureInfoProperty(_) => Tested(vec![static_check_error_no_such_tenure_info_property]),
        GetBlockInfoExpectPropertyName => Tested(vec![static_check_error_get_block_info_expect_property_name]),
        GetBurnBlockInfoExpectPropertyName => Tested(vec![static_check_error_get_burn_block_info_expect_property_name]),
        GetStacksBlockInfoExpectPropertyName => Tested(vec![static_check_error_get_stacks_block_info_expect_property_name]),
        GetTenureInfoExpectPropertyName => Tested(vec![static_check_error_get_tenure_info_expect_property_name]),
        NameAlreadyUsed(_) => Tested(vec![static_check_error_name_already_used]),
        ReservedWord(_) => Tested(vec![static_check_error_reserved_word]),
        NonFunctionApplication => Tested(vec![static_check_error_non_function_application]),
        ExpectedListApplication => Tested(vec![static_check_error_expected_list_application]),
        ExpectedSequence(type_signature) => Tested(vec![static_check_error_expected_sequence]),
        MaxLengthOverflow => Unreachable_ExpectLike,  // Should exceed u32 elements in memory.
        BadLetSyntax => Tested(vec![static_check_error_bad_let_syntax]),
        BadSyntaxBinding(syntax_binding_error) => Tested(vec![static_check_error_bad_syntax_binding]),
        MaxContextDepthReached => Unreachable_Functionally("Before type checking runs, the parser enforces an AST nesting limit of (5 + 64). Any contract exceeding depth 69 fails with `ParseErrorKind::ExpressionStackDepthTooDeep`"),
        UndefinedVariable(_) => Tested(vec![static_check_error_undefined_variable]),
        RequiresAtLeastArguments(_, _) => Tested(vec![static_check_error_requires_at_least_arguments]),
        RequiresAtMostArguments(_, _) => Tested(vec![static_check_error_requires_at_most_arguments]),
        IncorrectArgumentCount(_, _) => Tested(vec![static_check_error_incorrect_argument_count]),
        IfArmsMustMatch(type_signature, type_signature1) => Tested(vec![static_check_error_if_arms_must_match]),
        MatchArmsMustMatch(type_signature, type_signature1) => Tested(vec![static_check_error_match_arms_must_match]),
        DefaultTypesMustMatch(type_signature, type_signature1) => Tested(vec![static_check_error_default_types_must_match]),
        IllegalOrUnknownFunctionApplication(_) => Tested(vec![static_check_error_illegal_or_unknown_function_application]),
        UnknownFunction(_) => Tested(vec![static_check_error_unknown_function]),
        TooManyFunctionParameters(_, _) => Tested(vec![static_check_error_too_many_function_parameters]),
        NoSuchTrait(_, _) => Unreachable_Functionally("Trait identifiers are validated by the parser and TraitsResolver before type checking; invalid or missing traits trigger TraitReferenceUnknown earlier, so this error is never returned."),
        TraitReferenceUnknown(_) => Tested(vec![static_check_error_trait_reference_unknown]),
        TraitMethodUnknown(_, _) => Tested(vec![static_check_error_trait_method_unknown]),
        ExpectedTraitIdentifier => Unreachable_Functionally("`use-trait` or `impl-trait` with an invalid second argument fails in the AST stage, raising ParseErrorKind::ImportTraitBadSignature/ImplTraitBadSignature before static checks run."),
        BadTraitImplementation(_, _) => Tested(vec![static_check_error_bad_trait_implementation]),
        DefineTraitBadSignature => Tested(vec![static_check_error_define_trait_bad_signature]),
        DefineTraitDuplicateMethod(_) => Tested(vec![static_check_error_define_trait_duplicate_method]),
        UnexpectedTraitOrFieldReference => Tested(vec![static_check_error_unexpected_trait_or_field_reference]),
        ContractOfExpectsTrait => Tested(vec![static_check_error_contract_of_expects_trait]),
        IncompatibleTrait(trait_identifier, trait_identifier1) => Tested(vec![static_check_error_incompatible_trait]),
        TraitTooManyMethods(_, _) => Tested(vec![static_check_error_trait_too_many_methods]),
        WriteAttemptedInReadOnly => Tested(vec![static_check_error_write_attempted_in_read_only]),
        AtBlockClosureMustBeReadOnly => Tested(vec![static_check_error_at_block_closure_must_be_read_only]),
        ExpectedListOfAllowances(_, _) => Tested(vec![static_check_error_expected_list_of_allowances]),
        AllowanceExprNotAllowed => Tested(vec![static_check_error_allowance_expr_not_allowed]),
        ExpectedAllowanceExpr(_) => Tested(vec![static_check_error_expected_allowance_expr]),
        WithAllAllowanceNotAllowed => Tested(vec![static_check_error_with_all_allowance_not_allowed]),
        WithAllAllowanceNotAlone => Tested(vec![static_check_error_with_all_allowance_not_alone]),
        WithNftExpectedListOfIdentifiers => Tested(vec![static_check_error_with_nft_expected_list_of_identifiers]),
        MaxIdentifierLengthExceeded(_, _) => Tested(vec![static_check_error_max_identifier_length_exceeded]),
        TooManyAllowances(_, _) => Tested(vec![static_check_error_too_many_allowances]),
    }
}

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

/// StaticCheckErrorKind: [`StaticCheckErrorKind::MemoryBalanceExceeded`]
/// Caused by: This test creates a contract that fails during analysis phase.
///   The contract defines large nested tuple constants that exhaust
///   the 100MB memory limit during analysis.
/// Outcome: block rejected.
#[test]
fn static_check_error_memory_balance_exceeded() {
    contract_deploy_consensus_test!(
        contract_name: "analysis-memory-test",
        contract_code: &{
            let mut contract = String::new();
            // size: t0: 36 bytes
            contract.push_str("(define-constant t0 (tuple (f0 0x00) (f1 0x00) (f2 0x00) (f3 0x00)))");
            // size: t1: 160 bytes
            contract.push_str("(define-constant t1 (tuple (f0 t0) (f1 t0) (f2 t0) (f3 t0)))");
            // size: t2: 656 bytes
            contract.push_str("(define-constant t2 (tuple (f0 t1) (f1 t1) (f2 t1) (f3 t1)))");
            // size: t3: 2640 bytes
            contract.push_str("(define-constant t3 (tuple (f0 t2) (f1 t2) (f2 t2) (f3 t2)))");
            // size: t4: 10576 bytes
            contract.push_str("(define-constant t4 (tuple (f0 t3) (f1 t3) (f2 t3) (f3 t3)))");
            // size: t5: 42320 bytes
            contract.push_str("(define-constant t5 (tuple (f0 t4) (f1 t4) (f2 t4) (f3 t4)))");
            // size: t6: 126972 bytes
            contract.push_str("(define-constant t6 (tuple (f0 t5) (f1 t5) (f2 t5)))");
            // 126972 bytes * 800 ~= 101577600. Triggers MemoryBalanceExceeded during analysis.
            for i in 0..800 {
                contract.push_str(&format!("(define-constant l{} t6)", i + 1));
            }
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
/// Caused by: option `match` expecting 4 arguments, got 3.
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

/// StaticCheckErrorKind: [`StaticCheckErrorKind::NameAlreadyUsed`]
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

/// StaticCheckErrorKind: [`StaticCheckErrorKind::ReturnTypesMustMatch`]
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

/// StaticCheckErrorKind: [`StaticCheckErrorKind::TypeError`]
/// Caused by: initializing `define-data-var cursor int` with the boolean `true`.
/// Outcome: block accepted.
#[test]
fn static_check_error_type_error() {
    contract_deploy_consensus_test!(
        contract_name: "type-error",
        contract_code: "(define-data-var cursor int true)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::DefineVariableBadSignature`]
/// Caused by: `define-data-var` is provided only a name and value, missing the required type.
/// Outcome: block accepted.
#[test]
fn static_check_error_define_variable_bad_signature() {
    contract_deploy_consensus_test!(
        contract_name: "define-variable-bad",
        contract_code: "(define-data-var cursor 0x00)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::InvalidTypeDescription`]
/// Caused by: `define-data-var` uses `0x00` where a valid type description is required.
/// Outcome: block accepted.
#[test]
fn static_check_error_invalid_type_description() {
    contract_deploy_consensus_test!(
        contract_name: "invalid-type-desc",
        contract_code: "(define-data-var cursor 0x00 true)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::TypeSignatureTooDeep`]
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

/// StaticCheckErrorKind: [`StaticCheckErrorKind::SupertypeTooLarge`]
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

/// StaticCheckErrorKind: [`StaticCheckErrorKind::ConstructedListTooLarge`]
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

/// StaticCheckErrorKind: [`StaticCheckErrorKind::UnknownTypeName`]
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
        exclude_clarity_versions: &[ClarityVersion::Clarity1],
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::PublicFunctionMustReturnResponse`]
/// Caused by: defining a public function that does not return a response (ok or err).
/// Outcome: block accepted.
#[test]
fn static_check_error_public_function_must_return_response() {
    contract_deploy_consensus_test!(
        contract_name: "non-response",
        contract_code: "(define-public (non-response) true)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::UnionTypeError`]
/// Caused by: `map` applies subtraction to booleans.
/// Outcome: block accepted.
#[test]
fn static_check_error_union_type_error() {
    contract_deploy_consensus_test!(
        contract_name: "union-type-error",
        contract_code: "(map - (list true false true false))",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::UndefinedVariable`]
/// Caused by: `x`, `y`, and `z` are referenced without being defined.
/// Outcome: block accepted.
#[test]
fn static_check_error_undefined_variable() {
    contract_deploy_consensus_test!(
        contract_name: "undefined-variable",
        contract_code: "(+ x y z)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::BadMapTypeDefinition`]
/// Caused by: Invalid map type definition in a `(define-map ...)` expression.
/// Outcome: block accepted.
#[test]
fn static_check_error_bad_map_type_definition() {
    contract_deploy_consensus_test!(
        contract_name: "bad-map-type",
        contract_code: "(define-map lists { name: int } contents)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::CouldNotDetermineType`]
/// Caused by: `(index-of (list) none)` supplies no concrete element types.
/// Outcome: block accepted.
#[test]
fn static_check_error_could_not_determine_type() {
    contract_deploy_consensus_test!(
        contract_name: "could-not-determine",
        contract_code: "(index-of (list) none)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::ExpectedSequence`]
/// Caused by: passing integer `3` as the sequence argument to `index-of` instead of a list or string.
/// Outcome: block accepted.
#[test]
fn static_check_error_expected_sequence() {
    contract_deploy_consensus_test!(
        contract_name: "expected-sequence",
        contract_code: r#"(index-of 3 "a")"#,
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::CouldNotDetermineSerializationType`]
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
        exclude_clarity_versions: &[ClarityVersion::Clarity1],
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::IllegalOrUnknownFunctionApplication`]
/// Caused by: calling `map` with `if` (a non-function) as its function argument.
/// Outcome: block accepted.
#[test]
fn static_check_error_illegal_or_unknown_function_application() {
    contract_deploy_consensus_test!(
        contract_name: "illegal-or-unknown",
        contract_code: "(map if (list 1 2 3 4 5))",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::UnknownFunction`]
/// Caused by: invoking the undefined function `ynot`.
/// Outcome: block accepted.
#[test]
fn static_check_error_unknown_function() {
    contract_deploy_consensus_test!(
        contract_name: "unknown-function",
        contract_code: "(ynot 1 2)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::IncorrectArgumentCount`]
/// Caused by: `len` receives two arguments even though it expects exactly one.
/// Outcome: block accepted.
#[test]
fn static_check_error_incorrect_argument_count() {
    contract_deploy_consensus_test!(
        contract_name: "incorrect-arg-count",
        contract_code: "(len (list 1) (list 1))",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::BadLetSyntax`]
/// Caused by: `let` is used without a binding list.
/// Outcome: block accepted.
#[test]
fn static_check_error_bad_let_syntax() {
    contract_deploy_consensus_test!(
        contract_name: "bad-let-syntax",
        contract_code: "(let 1 2)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::BadSyntaxBinding`]
/// Caused by: `let` binding `((1))` is not a two-element list.
/// Outcome: block accepted.
#[test]
fn static_check_error_bad_syntax_binding() {
    contract_deploy_consensus_test!(
        contract_name: "bad-syntax-binding",
        contract_code: "(let ((1)) (+ 1 2))",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::ExpectedOptionalOrResponseType`]
/// Caused by: expected an optional or response type, but got a value
/// Outcome: block accepted.
#[test]
fn static_check_error_expected_optional_or_response_type() {
    contract_deploy_consensus_test!(
        contract_name: "exp-opt-or-res",
        contract_code: "(try! 3)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::DefineTraitBadSignature`]
/// Caused by: calling `define-trait` with a method signature that is not valid.
/// Outcome: block accepted.
#[test]
fn static_check_error_define_trait_bad_signature() {
    contract_deploy_consensus_test!(
        contract_name: "def-trait-bad-sign",
        contract_code: "(define-trait trait-1 ((get-1 uint uint)))",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::DefineTraitDuplicateMethod`]
/// Caused by: trait definition contains duplicate method names
/// Outcome: block accepted.
/// Note: This error was added in Clarity 2. Clarity 1 will accept the contract.
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

/// StaticCheckErrorKind: [`StaticCheckErrorKind::UnexpectedTraitOrFieldReference`]
/// Caused by: unexpected use of trait reference or field
/// Outcome: block accepted.
#[test]
fn static_check_error_unexpected_trait_or_field_reference() {
    contract_deploy_consensus_test!(
        contract_name: "trait-or-field-ref",
        contract_code: "(+ 1 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR.contract.field)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::IncompatibleTrait`]
/// Caused by: pass a trait to a trait parameter which is not compatible.
/// Outcome: block accepted.
/// Note: Added in Clarity 2. Clarity 1 will trigger a [`RuntimeCheckErrorKind::TypeError`].
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

/// StaticCheckErrorKind: [`StaticCheckErrorKind::TraitTooManyMethods`]
/// Caused by: a trait has too many methods.
/// Outcome: block accepted.
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

/// StaticCheckErrorKind: [`StaticCheckErrorKind::TooManyFunctionParameters`]
/// Caused by: a function has too many parameters.
/// Outcome: block accepted.
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

/// StaticCheckErrorKind: [`StaticCheckErrorKind::ReservedWord`]
/// Caused by: name is a reserved word
/// Outcome: block accepted.
/// Note: This error was added in Clarity 3. Clarity 1 and 2
///       will trigger a [`RuntimeCheckErrorKind::NameAlreadyUsed`].
#[test]
fn static_check_error_reserved_word() {
    contract_deploy_consensus_test!(
        contract_name: "reserved-word",
        contract_code: "(define-private (block-height) true)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::NoSuchBlockInfoProperty`]
/// Caused by: referenced an unknown property of a burn block
/// Outcome: block accepted.
#[test]
fn static_check_error_no_such_block_info_property() {
    contract_deploy_consensus_test!(
        contract_name: "no-such-block-info",
        contract_code: "(get-burn-block-info? none u1)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::NoSuchStacksBlockInfoProperty`]
/// Caused by: referenced an unknown property of a stacks block
/// Outcome: block accepted.
/// Note: This error was added in Clarity 3. Clarity 1, and 2
///       will trigger a [`RuntimeCheckErrorKind::UnknownFunction`].
#[test]
fn static_check_error_no_such_stacks_block_info_property() {
    contract_deploy_consensus_test!(
        contract_name: "no-such-stacks-info",
        contract_code: "(get-stacks-block-info? none u1)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::UncheckedIntermediaryResponses`]
/// Caused by: Intermediate `(ok ...)` expressions inside a `begin` block that are not unwrapped.
/// Outcome: block accepted.
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

/// StaticCheckErrorKind: [`StaticCheckErrorKind::NoSuchFT`]
/// Caused by: calling `ft-get-balance` with a non-existent FT name.
/// Outcome: block accepted.
#[test]
fn static_check_error_no_such_ft() {
    contract_deploy_consensus_test!(
        contract_name: "no-such-ft",
        contract_code: "(ft-get-balance stackoos tx-sender)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::NoSuchNFT`]
/// Caused by: calling `nft-get-owner?` with a non-existent NFT name.
/// Outcome: block accepted.
#[test]
fn static_check_error_no_such_nft() {
    contract_deploy_consensus_test!(
        contract_name: "no-such-nft",
        contract_code: r#"(nft-get-owner? stackoos "abc")"#,
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::DefineNFTBadSignature`]
/// Caused by: malformed signature in a `(define-non-fungible-token ...)` expression
/// Outcome: block accepted.
#[test]
fn static_check_error_define_nft_bad_signature() {
    contract_deploy_consensus_test!(
        contract_name: "nft-bad-signature",
        contract_code: "(define-non-fungible-token stackaroos integer)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::BadTokenName`]
/// Caused by: calling `ft-get-balance` with a non-valid token name.
/// Outcome: block accepted.
#[test]
fn static_check_error_bad_token_name() {
    contract_deploy_consensus_test!(
        contract_name: "bad-token-name",
        contract_code: "(ft-get-balance u1234 tx-sender)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::EmptyTuplesNotAllowed`]
/// Caused by: calling `set-cursor` with an empty tuple.
/// Outcome: block accepted.
#[test]
fn static_check_error_empty_tuples_not_allowed() {
    contract_deploy_consensus_test!(
        contract_name: "empty-tuples-not",
        contract_code: "
            (define-private (set-cursor (value (tuple)))
                value)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::NoSuchDataVariable`]
/// Caused by: calling var-get with a non-existent variable.
/// Outcome: block accepted.
#[test]
fn static_check_error_no_such_data_variable() {
    contract_deploy_consensus_test!(
        contract_name: "no-such-data-var",
        contract_code: "
            (define-private (get-cursor)
            (unwrap! (var-get cursor) 0))",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::NonFunctionApplication`]
/// Caused by: attempt to apply a non-function value as a function.
/// Outcome: block accepted.
#[test]
fn static_check_error_non_function_application() {
    contract_deploy_consensus_test!(
        contract_name: "non-function-appl",
        contract_code: "((lambda (x y) 1) 2 1)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::ExpectedListApplication`]
/// Caused by: calling append with lhs that is not a list.
/// Outcome: block accepted.
#[test]
fn static_check_error_expected_list_application() {
    contract_deploy_consensus_test!(
        contract_name: "expected-list-appl",
        contract_code: "(append 2 3)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::NoSuchContract`]
/// Caused by: calling contract-call? with a non-existent contract name.
/// Outcome: block accepted.
#[test]
fn static_check_error_no_such_contract() {
    contract_deploy_consensus_test!(
        contract_name: "no-such-contract",
        contract_code: "(contract-call? 'S1G2081040G2081040G2081040G208105NK8PE5.contract-name test! u1)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::ContractCallExpectName`]
/// Caused by: calling contract-call? without a contract function name.
/// Outcome: block accepted.
#[test]
fn static_check_error_contract_call_expect_name() {
    contract_deploy_consensus_test!(
        contract_name: "ccall-expect-name",
        contract_code: "(contract-call? 'S1G2081040G2081040G2081040G208105NK8PE5.contract-name u1)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::ExpectedCallableType`]
/// Caused by: passing a non-callable constant as the contract principal in `contract-call?`.
/// Outcome: block accepted.
/// Note: This error was added in Clarity 2. Clarity 1 will trigger a [`RuntimeCheckErrorKind::TraitReferenceUnknown`]
#[test]
fn static_check_error_expected_callable_type() {
    contract_deploy_consensus_test!(
        contract_name: "exp-callable-type",
        contract_code: "
            (define-constant bad-contract u1)
            (contract-call? bad-contract call-me)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::NoSuchPublicFunction`]
/// Caused by: calling a non-existent public or read-only function on a contract literal.
/// Outcome: block accepted.
#[test]
fn static_check_error_no_such_public_function() {
    contract_deploy_consensus_test!(
        contract_name: "no-such-pub-func-lit",
        // using the pox-4 contract as we know it exists!
        contract_code: &format!("(contract-call? '{}.pox-4 missing-func)", boot_code_test_addr()),
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::DefaultTypesMustMatch`]
/// Caused by: calling `default-to` with a default value that does not match the expected type.
/// Outcome: block accepted.
#[test]
fn static_check_error_default_types_must_match() {
    contract_deploy_consensus_test!(
        contract_name: "default-types-must",
        contract_code: "
        (define-map tokens { id: int } { balance: int })
        (default-to false (get balance (map-get? tokens (tuple (id 0)))))",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::IfArmsMustMatch`]
/// Caused by: calling `if` with arms that do not match the same type.
/// Outcome: block accepted.
#[test]
fn static_check_error_if_arms_must_match() {
    contract_deploy_consensus_test!(
        contract_name: "if-arms-must-match",
        contract_code: "(if true true 1)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::ExpectedTuple`]
/// Caused by: `(get ...)` is given `(some 1)` instead of a tuple value.
/// Outcome: block accepted.
#[test]
fn static_check_error_expected_tuple() {
    contract_deploy_consensus_test!(
        contract_name: "expected-tuple",
        contract_code: "(get field-0 (some 1))",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::NoSuchTupleField`]
/// Caused by: tuple argument only contains `name`, so requesting `value` fails.
/// Outcome: block accepted.
#[test]
fn static_check_error_no_such_tuple_field() {
    contract_deploy_consensus_test!(
        contract_name: "no-such-tuple-f",
        contract_code: "(get value (tuple (name 1)))",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::NoSuchMap`]
/// Caused by: `map-get?` refers to map `non-existent`, which is never defined.
/// Outcome: block accepted.
#[test]
fn static_check_error_no_such_map() {
    contract_deploy_consensus_test!(
        contract_name: "no-such-map",
        contract_code: "(map-get? non-existent (tuple (name 1)))",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::BadFunctionName`]
/// Caused by: defining a function whose signature does not start with an atom name.
/// Outcome: block accepted.
#[test]
fn static_check_error_bad_function_name() {
    contract_deploy_consensus_test!(
        contract_name: "bad-func-name",
        contract_code: "(define-private (u1) u0)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::DefineFunctionBadSignature`]
/// Caused by: defining a function with an empty signature list.
/// Outcome: block accepted.
#[test]
fn static_check_error_define_function_bad_signature() {
    contract_deploy_consensus_test!(
        contract_name: "def-func-bad-sign",
        contract_code: "(define-private () 1)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::BadTupleFieldName`]
/// Caused by: using `(get ...)` with a tuple field argument that is not an atom.
/// Outcome: block accepted.
#[test]
fn static_check_error_bad_tuple_field_name() {
    contract_deploy_consensus_test!(
        contract_name: "bad-tuple-field-name",
        contract_code: "(get u1 (tuple (foo u0)))",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::BadMapName`]
/// Caused by: passing a literal instead of a map identifier to `map-get?`.
/// Outcome: block accepted.
#[test]
fn static_check_error_bad_map_name() {
    contract_deploy_consensus_test!(
        contract_name: "bad-map-name",
        contract_code: "(map-get? u1 (tuple (id u0)))",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::GetBlockInfoExpectPropertyName`]
/// Caused by: calling `get-block-info` with a non-atom property argument.
/// Outcome: block accepted.
/// Note: Only Clarity 1 and 2 will trigger this error. Clarity 3 and 4
///       will trigger a [`RuntimeCheckErrorKind::UnknownFunction`].
#[test]
fn static_check_error_get_block_info_expect_property_name() {
    contract_deploy_consensus_test!(
        contract_name: "info-exp-prop-name",
        contract_code: "(get-block-info? u1 u0)",
        exclude_clarity_versions: &[
            ClarityVersion::Clarity3,
            ClarityVersion::Clarity4,
            ClarityVersion::Clarity5
        ],
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::GetBurnBlockInfoExpectPropertyName`]
/// Caused by: calling `get-burn-block-info` with a non-atom property argument.
/// Outcome: block accepted.
/// Note: This error was added in Clarity 2. Clarity 1 will trigger
///       a [`RuntimeCheckErrorKind::UnknownFunction`].
#[test]
fn static_check_error_get_burn_block_info_expect_property_name() {
    contract_deploy_consensus_test!(
        contract_name: "burn-exp-prop-name",
        contract_code: "(get-burn-block-info? u1 u0)",
        exclude_clarity_versions: &[ClarityVersion::Clarity1],
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::GetStacksBlockInfoExpectPropertyName`]
/// Caused by: calling `get-stacks-block-info` with a non-atom property argument.
/// Outcome: block accepted.
/// Note: This error was added in Clarity 3. Clarity 1 and 2 will trigger
///       a [`RuntimeCheckErrorKind::UnknownFunction`].
#[test]
fn static_check_error_get_stacks_block_info_expect_property_name() {
    contract_deploy_consensus_test!(
        contract_name: "stacks-exp-prop-name",
        contract_code: "(get-stacks-block-info? u1 u0)",
        exclude_clarity_versions: &[ClarityVersion::Clarity1, ClarityVersion::Clarity2],
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::GetTenureInfoExpectPropertyName`]
/// Caused by: calling `get-tenure-info` with a non-atom property argument.
/// Outcome: block accepted.
/// Note: This error was added in Clarity 3. Clarity 1 and 2 will trigger
///       a [`RuntimeCheckErrorKind::UnknownFunction`].
#[test]
fn static_check_error_get_tenure_info_expect_property_name() {
    contract_deploy_consensus_test!(
        contract_name: "tenure-exp-prop-name",
        contract_code: "(get-tenure-info? u1 u0)",
        exclude_clarity_versions: &[ClarityVersion::Clarity1, ClarityVersion::Clarity2],
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::NoSuchTenureInfoProperty`]
/// Caused by: referenced an unknown property of a tenure
/// Outcome: block accepted.
/// Note: This error was added in Clarity 3. Clarity 1, and 2
///       will trigger a [`RuntimeCheckErrorKind::UnknownFunction`].
#[test]
fn static_check_error_no_such_tenure_info_property() {
    contract_deploy_consensus_test!(
        contract_name: "no-such-tenure-info",
        contract_code: "(get-tenure-info? none u1)",
        exclude_clarity_versions: &[ClarityVersion::Clarity1, ClarityVersion::Clarity2],
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::TraitReferenceUnknown`]
/// Caused by: referenced trait is unknown
/// Outcome: block accepted.
#[test]
fn static_check_error_trait_reference_unknown() {
    contract_deploy_consensus_test!(
        contract_name: "trait-ref-unknown",
        contract_code: "(+ 1 <kvstore>)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::ContractOfExpectsTrait`]
/// Caused by: calling `contract-of` with a non-trait argument.
/// Outcome: block accepted.
#[test]
fn static_check_error_contract_of_expects_trait() {
    contract_deploy_consensus_test!(
        contract_name: "expect-trait",
        contract_code: "(contract-of u1)",
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::TraitMethodUnknown`]
/// Caused by: defining a method that is not declared in the trait
/// Outcome: block accepted.
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

/// StaticCheckErrorKind: [`StaticCheckErrorKind::WriteAttemptedInReadOnly`]
/// Caused by: read-only function `silly` invoking `map-delete`, which performs a write.
/// Outcome: block accepted.
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

/// StaticCheckErrorKind: [`StaticCheckErrorKind::AtBlockClosureMustBeReadOnly`]
/// Caused by: `at-block` closure must be read-only but contains write operations.
/// Outcome: block accepted.
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

/// StaticCheckErrorKind: [`StaticCheckErrorKind::AllowanceExprNotAllowed`]
/// Caused by: using an allowance expression outside of `restrict-assets?` or `as-contract?`.
/// Outcome: block accepted.
/// Note: This error was added in Clarity 4. Clarity 1, 2, and 3
///       will trigger a [`RuntimeCheckErrorKind::UnknownFunction`].
#[test]
fn static_check_error_allowance_expr_not_allowed() {
    contract_deploy_consensus_test!(
        contract_name: "allow-expr-not-allo",
        contract_code: "(with-stx u1)",
        exclude_clarity_versions: &[ClarityVersion::Clarity1, ClarityVersion::Clarity2, ClarityVersion::Clarity3],
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::ExpectedListOfAllowances`]
/// Caused by: post-condition expects a list of asset allowances but received invalid input.
/// Outcome: block accepted.
/// Note: This error was added in Clarity 4. Clarity 1, 2, and 3
///       will trigger a [`RuntimeCheckErrorKind::UnknownFunction`].
#[test]
fn static_check_error_expected_list_of_allowances() {
    contract_deploy_consensus_test!(
        contract_name: "exp-list-of-allowances",
        contract_code: "(restrict-assets? tx-sender u1 true)",
        exclude_clarity_versions: &[ClarityVersion::Clarity1, ClarityVersion::Clarity2, ClarityVersion::Clarity3],
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::ExpectedAllowanceExpr`]
/// Caused by: allowance list contains a non-allowance expression.
/// Outcome: block accepted.
/// Note: This error was added in Clarity 4. Clarity 1, 2, and 3
///       will trigger a [`RuntimeCheckErrorKind::UnknownFunction`].
#[test]
fn static_check_error_expected_allowance_expr() {
    contract_deploy_consensus_test!(
        contract_name: "exp-allowa-expr",
        contract_code: "(restrict-assets? tx-sender ((not true)) true)",
        exclude_clarity_versions: &[ClarityVersion::Clarity1, ClarityVersion::Clarity2, ClarityVersion::Clarity3],
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::WithAllAllowanceNotAllowed`]
/// Caused by: `restrict-assets?` allowance list contains `with-all-assets-unsafe`, which is forbidden.
/// Outcome: block accepted.
/// Note: This error was added in Clarity 4. Clarity 1, 2, and 3
///       will trigger a [`RuntimeCheckErrorKind::UnknownFunction`].
#[test]
fn static_check_error_with_all_allowance_not_allowed() {
    contract_deploy_consensus_test!(
        contract_name: "all-allow-not-allowed",
        contract_code: "(restrict-assets? tx-sender ((with-all-assets-unsafe)) true)",
        exclude_clarity_versions: &[ClarityVersion::Clarity1, ClarityVersion::Clarity2, ClarityVersion::Clarity3],
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::WithAllAllowanceNotAlone`]
/// Caused by: combining `with-all-assets-unsafe` with another allowance inside `as-contract?`.
/// Outcome: block accepted.
/// Note: This error was added in Clarity 4. Clarity 1, 2, and 3
///       will trigger a [`RuntimeCheckErrorKind::UnknownFunction`].
#[test]
fn static_check_error_with_all_allowance_not_alone() {
    contract_deploy_consensus_test!(
        contract_name: "all-allow-not-alone",
        contract_code: "(as-contract? ((with-all-assets-unsafe) (with-stx u1000)) true)",
        exclude_clarity_versions: &[ClarityVersion::Clarity1, ClarityVersion::Clarity2, ClarityVersion::Clarity3],
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::WithNftExpectedListOfIdentifiers`]
/// Caused by: the third argument to `with-nft` is not a list of identifiers.
/// Outcome: block accepted.
/// Note: This error was added in Clarity 4. Clarity 1, 2, and 3
///       will trigger a [`RuntimeCheckErrorKind::UnknownFunction`].
#[test]
fn static_check_error_with_nft_expected_list_of_identifiers() {
    contract_deploy_consensus_test!(
        contract_name: "with-nft-exp-ident",
        contract_code: r#"(restrict-assets? tx-sender ((with-nft tx-sender "token-name" tx-sender)) true)"#,
        exclude_clarity_versions: &[ClarityVersion::Clarity1, ClarityVersion::Clarity2, ClarityVersion::Clarity3],
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::MaxIdentifierLengthExceeded`]
/// Caused by: `with-nft` lists 130 identifiers, surpassing [`MAX_NFT_IDENTIFIERS`] (128).
/// Outcome: block accepted.
/// Note: This error was added in Clarity 4. Clarity 1, 2, and 3
///       will trigger a [`RuntimeCheckErrorKind::UnknownFunction`].
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
        exclude_clarity_versions: &[ClarityVersion::Clarity1, ClarityVersion::Clarity2, ClarityVersion::Clarity3],
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::TooManyAllowances`]
/// Caused by: allowance list supplies 130 entries, exceeding [`MAX_ALLOWANCES`] (128).
/// Outcome: block accepted.
/// Note: This error was added in Clarity 4. Clarity 1, 2, and 3
///       will trigger a [`RuntimeCheckErrorKind::UnknownFunction`].
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
        exclude_clarity_versions: &[ClarityVersion::Clarity1, ClarityVersion::Clarity2, ClarityVersion::Clarity3],
    );
}

/// StaticCheckErrorKind: [`StaticCheckErrorKind::BadTupleConstruction`]
/// Caused by: tuple literal repeats the `name` field twice.
/// Outcome: block accepted.
#[test]
fn static_check_error_bad_tuple_construction() {
    contract_deploy_consensus_test!(
        contract_name: "bad-tuple-constr",
        contract_code: "(tuple (name 1) (name 2))",
    );
}

/// Error: [`Error::InvalidStacksTransaction("Duplicate contract")`]
/// Caused by: trying to deploy a contract that already exists.
/// Outcome: block rejected.
#[test]
fn error_invalid_stacks_transaction_duplicate_contract() {
    let contract_code = "(define-constant buff-0 0x00)";
    let mut nonce = 0;

    let tx_fee = (contract_code.len() * 100) as u64;
    let mut epochs_blocks: HashMap<StacksEpochId, Vec<TestBlock>> = HashMap::new();
    let contract_name = "contract-name";
    let deploy_tx = ConsensusUtils::new_deploy_tx(nonce, contract_name, contract_code, None);
    nonce += 1;
    epochs_blocks
        .entry(*EPOCHS_TO_TEST.first().unwrap())
        .or_insert(vec![])
        .push(TestBlock {
            transactions: vec![deploy_tx],
        });

    for epoch in EPOCHS_TO_TEST {
        for version in clarity_versions_for_epoch(*epoch) {
            let deploy_tx =
                ConsensusUtils::new_deploy_tx(nonce, contract_name, contract_code, Some(*version));

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
