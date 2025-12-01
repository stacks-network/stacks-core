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

//! This module contains consensus tests related to Clarity CheckErrorKind errors that happens during runtime analysis.

#[allow(unused_imports)]
use clarity::vm::analysis::CheckErrorKind;
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use clarity::vm::Value as ClarityValue;

use crate::chainstate::tests::consensus::{
    contract_call_consensus_test, SetupContract, FAUCET_ADDRESS,
};

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
        CostOverflow
        | CostBalanceExceeded(_, _)
        | MemoryBalanceExceeded(_, _)
        | CostComputationFailed(_)
        | ExecutionTimeExpired
        | ValueTooLarge
        | ValueOutOfBounds
        | TypeSignatureTooDeep
        | ExpectedName
        | SupertypeTooLarge
        | Expects(_)
        | BadMatchOptionSyntax(_)
        | BadMatchResponseSyntax(_)
        | BadMatchInput(_)
        | ListTypesMustMatch
        | ConstructedListTooLarge
        | TypeError(_, _)
        | TypeValueError(_, _)
        | InvalidTypeDescription
        | UnknownTypeName(_)
        | UnionTypeError(_, _)
        | UnionTypeValueError(_, _)
        | ExpectedOptionalType(_)
        | ExpectedResponseType(_)
        | ExpectedOptionalOrResponseType(_)
        | ExpectedOptionalValue(_)
        | ExpectedResponseValue(_)
        | ExpectedOptionalOrResponseValue(_)
        | CouldNotDetermineResponseOkType
        | CouldNotDetermineResponseErrType
        | CouldNotDetermineSerializationType
        | UncheckedIntermediaryResponses
        | ExpectedContractPrincipalValue(_)
        | CouldNotDetermineMatchTypes
        | CouldNotDetermineType
        | TypeAlreadyAnnotatedFailure
        | CheckerImplementationFailure
        | BadTokenName
        | DefineNFTBadSignature
        | NoSuchNFT(_)
        | NoSuchFT(_)
        | BadTransferSTXArguments
        | BadTransferFTArguments
        | BadTransferNFTArguments
        | BadMintFTArguments
        | BadBurnFTArguments
        | BadTupleFieldName
        | ExpectedTuple(_) => todo!(),
        NoSuchTupleField(_, _) | DefineFunctionBadSignature | BadFunctionName | PublicFunctionMustReturnResponse(_) => Unreachable_Functionally("On contract deploy checked during static analysis."),
        EmptyTuplesNotAllowed | NoSuchMap(_) => Unreachable_Functionally("On contract deploy checked during static analysis. (At runtime, just used for loading cost functions on block begin)"),
        BadTupleConstruction(_) => todo!(),
        NoSuchDataVariable(_) => Unreachable_Functionally("On contract deploy checked during static analysis. (At runtime, just used for loading cost functions on block begin and for handle prepare phase)"),
        BadMapName => todo!(),
        BadMapTypeDefinition => todo!(),
        DefineVariableBadSignature
        | ReturnTypesMustMatch(_, _) => todo!(),
        CircularReference(_) => Tested(vec![check_error_kind_circular_reference_ccall]),
        NoSuchContract(_) => todo!(),
        NoSuchPublicFunction(_, _) => Tested(vec![check_error_kind_no_such_public_function_ccall]),
        PublicFunctionNotReadOnly(_, _) => Unreachable_Functionally("Environment::inner_execute_contract is invoked with read_only = false on the relevant code path, causing PublicFunctionNotReadOnly check to be skipped."),
        ContractAlreadyExists(_) => Unreachable_Functionally(
            "Contracts can only be created via SmartContract deployment transactions. \
             The runtime never performs contract installation or replacement.",
        ),
        ContractCallExpectName => todo!(),
        NoSuchBurnBlockInfoProperty(_) => Unreachable_Functionally(
            "Burn block info property names are validated during static analysis; \
             unknown properties are rejected at deploy time.",
        ),
        NoSuchStacksBlockInfoProperty(_) => Unreachable_Functionally(
            "Stacks block info property names are validated during static analysis; \
             unknown properties are rejected at deploy time.",
        ),
        NoSuchTenureInfoProperty(_) => Unreachable_Functionally(
            "Tenure info property names are validated during static analysis; \
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
        GetBurnBlockInfoExpectPropertyName => Unreachable_Functionally(
            "`get-burn-block-info?` requires a literal property name; \
             non-atom arguments are rejected during static analysis.",
        ),
        NameAlreadyUsed(_) => todo!(),
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
        UndefinedFunction(_) => todo!(),
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
        NoSuchTrait(_, _) => Unreachable_Functionally(
            "All trait references are fully resolved during static analysis via `use-trait`; \
            a missing or unknown trait prevents contract deployment and cannot reach runtime.",
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
        TraitReferenceNotAllowed => Unreachable_NotUsed, // Fuzz-only; never emitted by real Clarity execution
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
        ExpectedCallableType(_)
        | NoSuchBlockInfoProperty(_)
        | IfArmsMustMatch(_, _)
        | MatchArmsMustMatch(_, _)
        | ReservedWord(_)
        | MaxLengthOverflow
        | MaxContextDepthReached
        | DefaultTypesMustMatch(_, _)
        | IllegalOrUnknownFunctionApplication(_)
        | UnknownFunction(_)
        | UnexpectedTraitOrFieldReference
        | IncompatibleTrait(_, _)
        | WithAllAllowanceNotAllowed
        | WithAllAllowanceNotAlone
        | WithNftExpectedListOfIdentifiers
        | MaxIdentifierLengthExceeded(_, _) => Unreachable_NotUsed, // Static-only; cannot arise at runtime
        TraitTooManyMethods(_, _) => Unreachable_Functionally(
            "Trait method count limits are enforced during deployment; \
             oversized traits cannot appear at runtime.",
        ),
        InvalidCharactersDetected | InvalidUTF8Encoding => {
            Ignored("Only reachable via legacy v1 parsing paths")
        }
        WriteAttemptedInReadOnly | AtBlockClosureMustBeReadOnly => Unreachable_Functionally(
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
