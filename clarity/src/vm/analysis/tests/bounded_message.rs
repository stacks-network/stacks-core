// Copyright (C) 2026 Stacks Open Internet Foundation
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

use clarity_types::ClarityName;
use clarity_types::types::{MAX_ERROR_MESSAGE_LEN, TupleTypeSignature, TypeSignature};

use crate::vm::analysis::errors::{StaticCheckError, StaticCheckErrorKind};
use crate::vm::diagnostic::DiagnosableError;

/// The whole message renders through one byte-budgeted sink, so this is
/// the ceiling regardless of how many types a variant carries.
const CEILING: usize = MAX_ERROR_MESSAGE_LEN;

/// A tuple type whose rendering dwarfs any sane budget: 400 fields with
/// long names, so `Display` produces tens of kilobytes.
fn oversized_tuple_type() -> TupleTypeSignature {
    let fields: Vec<(ClarityName, TypeSignature)> = (0..400)
        .map(|i| {
            let name = ClarityName::try_from(format!("field_with_a_long_name_{i:040}"))
                .expect("field name should be valid");
            (name, TypeSignature::UIntType)
        })
        .collect();
    TupleTypeSignature::try_from(fields).expect("tuple should be constructible")
}

fn oversized_type() -> TypeSignature {
    TypeSignature::TupleType(oversized_tuple_type())
}

#[test]
fn oversized_type_is_actually_oversized() {
    // Guards the guard: if this stops holding, the assertions below pass
    // trivially and stop testing anything.
    assert!(oversized_type().to_string().len() > 2 * CEILING);
}

/// Each type-bearing variant, built with the oversized type in every
/// type-shaped position.
fn variants_with_type() -> Vec<StaticCheckErrorKind> {
    let big = || Box::new(oversized_type());
    vec![
        StaticCheckErrorKind::BadMatchInput(big()),
        StaticCheckErrorKind::TypeError(big(), big()),
        StaticCheckErrorKind::UnionTypeError(
            vec![oversized_type(), oversized_type(), oversized_type()],
            big(),
        ),
        StaticCheckErrorKind::ExpectedOptionalType(big()),
        StaticCheckErrorKind::ExpectedOptionalOrResponseType(big()),
        StaticCheckErrorKind::ExpectedResponseType(big()),
        StaticCheckErrorKind::ExpectedTuple(big()),
        StaticCheckErrorKind::NoSuchTupleField("field".into(), oversized_tuple_type()),
        StaticCheckErrorKind::PublicFunctionMustReturnResponse(big()),
        StaticCheckErrorKind::ReturnTypesMustMatch(big(), big()),
        StaticCheckErrorKind::ExpectedCallableType(big()),
        StaticCheckErrorKind::ExpectedSequence(big()),
        StaticCheckErrorKind::IfArmsMustMatch(big(), big()),
        StaticCheckErrorKind::MatchArmsMustMatch(big(), big()),
        StaticCheckErrorKind::DefaultTypesMustMatch(big(), big()),
    ]
}

/// Compile-time guard for [`variants_with_type`]: that is a
/// hand-maintained list, so without this a new type-bearing variant would
/// silently go untested. Adding a variant makes this match non-exhaustive
/// and the compiler sends you here — if the new variant carries a
/// `TypeSignature`, add it to [`variants_with_type`]. Never add a
/// wildcard arm.
#[allow(dead_code)]
fn every_variant_was_considered_for_the_list(kind: &StaticCheckErrorKind) {
    use StaticCheckErrorKind as E;
    match kind {
        E::CostOverflow
        | E::CostBalanceExceeded(..)
        | E::MemoryBalanceExceeded(..)
        | E::CostComputationFailed(..)
        | E::AnalysisResourceBudgetExceeded(..)
        | E::ReadOnlyCheckerRecursionLimitExceeded
        | E::ValueTooLarge
        | E::ValueOutOfBounds
        | E::TypeSignatureTooDeep
        | E::TraitReferenceChainTooDeep
        | E::ExpectedName
        | E::SupertypeTooLarge
        | E::Unreachable(..)
        | E::BadMatchOptionSyntax(..)
        | E::BadMatchResponseSyntax(..)
        | E::BadMatchInput(..)
        | E::ConstructedListTooLarge
        | E::TypeError(..)
        | E::InvalidTypeDescription
        | E::UnknownTypeName(..)
        | E::UnionTypeError(..)
        | E::ExpectedOptionalType(..)
        | E::ExpectedResponseType(..)
        | E::ExpectedOptionalOrResponseType(..)
        | E::CouldNotDetermineResponseOkType
        | E::CouldNotDetermineResponseErrType
        | E::CouldNotDetermineSerializationType
        | E::UncheckedIntermediaryResponses
        | E::CouldNotDetermineMatchTypes
        | E::CouldNotDetermineType
        | E::TypeAlreadyAnnotatedFailure
        | E::CheckerImplementationFailure
        | E::BadTokenName
        | E::DefineNFTBadSignature
        | E::NoSuchNFT(..)
        | E::NoSuchFT(..)
        | E::BadTupleFieldName
        | E::ExpectedTuple(..)
        | E::NoSuchTupleField(..)
        | E::EmptyTuplesNotAllowed
        | E::BadTupleConstruction(..)
        | E::NoSuchDataVariable(..)
        | E::BadMapName
        | E::NoSuchMap(..)
        | E::DefineFunctionBadSignature
        | E::BadFunctionName
        | E::BadMapTypeDefinition
        | E::PublicFunctionMustReturnResponse(..)
        | E::DefineVariableBadSignature
        | E::ReturnTypesMustMatch(..)
        | E::NoSuchContract(..)
        | E::NoSuchPublicFunction(..)
        | E::ContractAlreadyExists(..)
        | E::ContractCallExpectName
        | E::ExpectedCallableType(..)
        | E::NoSuchBlockInfoProperty(..)
        | E::NoSuchStacksBlockInfoProperty(..)
        | E::NoSuchTenureInfoProperty(..)
        | E::GetBlockInfoExpectPropertyName
        | E::GetBurnBlockInfoExpectPropertyName
        | E::GetStacksBlockInfoExpectPropertyName
        | E::GetTenureInfoExpectPropertyName
        | E::NameAlreadyUsed(..)
        | E::ReservedWord(..)
        | E::NonFunctionApplication
        | E::ExpectedListApplication
        | E::ExpectedSequence(..)
        | E::MaxLengthOverflow
        | E::BadLetSyntax
        | E::BadSyntaxBinding(..)
        | E::MaxContextDepthReached
        | E::UndefinedVariable(..)
        | E::RequiresAtLeastArguments(..)
        | E::RequiresAtMostArguments(..)
        | E::IncorrectArgumentCount(..)
        | E::IfArmsMustMatch(..)
        | E::MatchArmsMustMatch(..)
        | E::DefaultTypesMustMatch(..)
        | E::IllegalOrUnknownFunctionApplication(..)
        | E::UnknownFunction(..)
        | E::TooManyFunctionParameters(..)
        | E::NoSuchTrait(..)
        | E::TraitReferenceUnknown(..)
        | E::TraitMethodUnknown(..)
        | E::ExpectedTraitIdentifier
        | E::BadTraitImplementation(..)
        | E::DefineTraitBadSignature
        | E::DefineTraitDuplicateMethod(..)
        | E::UnexpectedTraitOrFieldReference
        | E::ContractOfExpectsTrait
        | E::IncompatibleTrait(..)
        | E::TraitTooManyMethods(..)
        | E::WriteAttemptedInReadOnly
        | E::AtBlockClosureMustBeReadOnly
        | E::AtBlockUnavailable
        | E::ExpectedListOfAllowances(..)
        | E::AllowanceExprNotAllowed
        | E::ExpectedAllowanceExpr(..)
        | E::WithAllAllowanceNotAllowed
        | E::WithAllAllowanceNotAlone
        | E::WithNftExpectedListOfIdentifiers
        | E::MaxIdentifierLengthExceeded(..)
        | E::TooManyAllowances(..) => (),
    }
}

#[test]
fn message_stays_bounded_for_variants_with_type() {
    for err in variants_with_type() {
        let message = err.message();
        assert!(
            message.len() <= CEILING,
            "unbounded diagnostic ({} bytes) -- arms must stream into the \
             formatter, never build a String",
            message.len(),
        );
    }
}

#[test]
fn constructing_the_error_stays_bounded() {
    // `message()` is rendered eagerly here, so this covers the real path.
    for kind in variants_with_type() {
        let err = StaticCheckError::new(kind);
        assert!(err.diagnostic.message.len() <= CEILING);
    }
}
