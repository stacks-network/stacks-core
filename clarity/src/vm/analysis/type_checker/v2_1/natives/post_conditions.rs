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

use clarity_types::errors::analysis::{check_argument_count, check_arguments_at_least};
use clarity_types::errors::{CheckError, CheckErrors};
use clarity_types::representations::SymbolicExpression;
use clarity_types::types::signatures::ASCII_128;
use clarity_types::types::{SequenceSubtype, TypeSignature};

use crate::vm::analysis::type_checker::contexts::TypingContext;
use crate::vm::analysis::type_checker::v2_1::TypeChecker;
use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::costs::runtime_cost;
use crate::vm::functions::NativeFunctions;

/// Maximum number of allowances allowed in a `restrict-assets?` or
/// `as-contract?` expression. This value is also used to indicate an allowance
/// violation for an asset with no allowances.
pub(crate) const MAX_ALLOWANCES: usize = 128;
/// Maximum number of asset identifiers allowed in a `with-nft` allowance expression.
pub(crate) const MAX_NFT_IDENTIFIERS: u32 = 128;

pub fn check_restrict_assets(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> Result<TypeSignature, CheckError> {
    check_arguments_at_least(3, args)?;

    let asset_owner = args
        .first()
        .ok_or(CheckErrors::CheckerImplementationFailure)?;
    let allowance_list = args
        .get(1)
        .ok_or(CheckErrors::CheckerImplementationFailure)?
        .match_list()
        .ok_or(CheckErrors::ExpectedListOfAllowances(
            "restrict-assets?".into(),
            2,
        ))?;
    let body_exprs = args
        .get(2..)
        .ok_or(CheckErrors::CheckerImplementationFailure)?;

    if allowance_list.len() > MAX_ALLOWANCES {
        return Err(CheckErrors::TooManyAllowances(MAX_ALLOWANCES, allowance_list.len()).into());
    }

    runtime_cost(
        ClarityCostFunction::AnalysisListItemsCheck,
        checker,
        allowance_list.len() + body_exprs.len(),
    )?;

    checker.type_check_expects(asset_owner, context, &TypeSignature::PrincipalType)?;

    for allowance in allowance_list {
        if check_allowance(checker, allowance, context)? {
            return Err(CheckErrors::WithAllAllowanceNotAllowed.into());
        }
    }

    // Check the body expressions, ensuring any intermediate responses are handled
    let mut last_return = None;
    for expr in body_exprs {
        let type_return = checker.type_check(expr, context)?;
        if type_return.is_response_type() {
            return Err(CheckErrors::UncheckedIntermediaryResponses.into());
        }
        last_return = Some(type_return);
    }

    let ok_type = last_return.ok_or_else(|| CheckErrors::CheckerImplementationFailure)?;
    Ok(TypeSignature::new_response(
        ok_type,
        TypeSignature::UIntType,
    )?)
}

pub fn check_as_contract(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> Result<TypeSignature, CheckError> {
    check_arguments_at_least(2, args)?;

    let allowance_list = args
        .first()
        .ok_or(CheckErrors::CheckerImplementationFailure)?
        .match_list()
        .ok_or(CheckErrors::ExpectedListOfAllowances(
            "as-contract?".into(),
            1,
        ))?;
    let body_exprs = args
        .get(1..)
        .ok_or(CheckErrors::CheckerImplementationFailure)?;

    if allowance_list.len() > MAX_ALLOWANCES {
        return Err(CheckErrors::TooManyAllowances(MAX_ALLOWANCES, allowance_list.len()).into());
    }

    runtime_cost(
        ClarityCostFunction::AnalysisListItemsCheck,
        checker,
        allowance_list.len() + body_exprs.len(),
    )?;

    for allowance in allowance_list {
        if check_allowance(checker, allowance, context)? && allowance_list.len() > 1 {
            return Err(CheckErrors::WithAllAllowanceNotAlone.into());
        }
    }

    // Check the body expressions, ensuring any intermediate responses are handled
    let mut last_return = None;
    for expr in body_exprs {
        let type_return = checker.type_check(expr, context)?;
        if type_return.is_response_type() {
            return Err(CheckErrors::UncheckedIntermediaryResponses.into());
        }
        last_return = Some(type_return);
    }

    let ok_type = last_return.ok_or_else(|| CheckErrors::CheckerImplementationFailure)?;
    Ok(TypeSignature::new_response(
        ok_type,
        TypeSignature::UIntType,
    )?)
}

/// Type-checking for allowance expressions. These are only allowed within the
/// context of an `restrict-assets?` or `as-contract?` expression. All other
/// uses will reach this function and return an error.
pub fn check_allowance_err(
    _checker: &mut TypeChecker,
    _args: &[SymbolicExpression],
    _context: &TypingContext,
) -> Result<TypeSignature, CheckError> {
    Err(CheckErrors::AllowanceExprNotAllowed.into())
}

/// Type check an allowance expression, returning whether it is a
/// `with-all-assets-unsafe` allowance (which has special rules).
pub fn check_allowance(
    checker: &mut TypeChecker,
    allowance: &SymbolicExpression,
    context: &TypingContext,
) -> Result<bool, CheckError> {
    let list = allowance
        .match_list()
        .ok_or(CheckErrors::ExpectedListApplication)?;
    let (allowance_fn, args) = list
        .split_first()
        .ok_or(CheckErrors::ExpectedListApplication)?;
    let function_name = allowance_fn
        .match_atom()
        .ok_or(CheckErrors::NonFunctionApplication)?;
    let Some(ref native_function) =
        NativeFunctions::lookup_by_name_at_version(function_name, &checker.clarity_version)
    else {
        return Err(CheckErrors::ExpectedAllowanceExpr(function_name.to_string()).into());
    };

    match native_function {
        NativeFunctions::AllowanceWithStx => check_allowance_with_stx(checker, args, context),
        NativeFunctions::AllowanceWithFt => check_allowance_with_ft(checker, args, context),
        NativeFunctions::AllowanceWithNft => check_allowance_with_nft(checker, args, context),
        NativeFunctions::AllowanceWithStacking => {
            check_allowance_with_stacking(checker, args, context)
        }
        NativeFunctions::AllowanceAll => check_allowance_all(checker, args, context),
        _ => Err(CheckErrors::ExpectedAllowanceExpr(function_name.to_string()).into()),
    }
}

/// Type check a `with-stx` allowance expression.
/// `(with-stx amount:uint)`
fn check_allowance_with_stx(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> Result<bool, CheckError> {
    check_argument_count(1, args)?;

    checker.type_check_expects(
        args.first()
            .ok_or(CheckErrors::CheckerImplementationFailure)?,
        context,
        &TypeSignature::UIntType,
    )?;

    Ok(false)
}

/// Type check a `with-ft` allowance expression.
/// `(with-ft contract-id:principal token-name:(string-ascii 128) amount:uint)`
fn check_allowance_with_ft(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> Result<bool, CheckError> {
    check_argument_count(3, args)?;

    checker.type_check_expects(
        args.first()
            .ok_or(CheckErrors::CheckerImplementationFailure)?,
        context,
        &TypeSignature::PrincipalType,
    )?;
    checker.type_check_expects(
        args.get(1)
            .ok_or(CheckErrors::CheckerImplementationFailure)?,
        context,
        &ASCII_128,
    )?;
    checker.type_check_expects(
        args.get(2)
            .ok_or(CheckErrors::CheckerImplementationFailure)?,
        context,
        &TypeSignature::UIntType,
    )?;

    Ok(false)
}

/// Type check a `with-nft` allowance expression.
/// `(with-nft contract-id:principal token-name:(string-ascii 128) asset-id:any)`
fn check_allowance_with_nft(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> Result<bool, CheckError> {
    check_argument_count(3, args)?;

    checker.type_check_expects(
        args.first()
            .ok_or(CheckErrors::CheckerImplementationFailure)?,
        context,
        &TypeSignature::PrincipalType,
    )?;
    checker.type_check_expects(
        args.get(1)
            .ok_or(CheckErrors::CheckerImplementationFailure)?,
        context,
        &ASCII_128,
    )?;

    // Asset identifiers must be a Clarity list with any type of elements
    let id_list_ty = checker.type_check(
        args.get(2)
            .ok_or(CheckErrors::CheckerImplementationFailure)?,
        context,
    )?;
    let TypeSignature::SequenceType(SequenceSubtype::ListType(list_data)) = id_list_ty else {
        return Err(CheckErrors::WithNftExpectedListOfIdentifiers.into());
    };
    if list_data.get_max_len() > MAX_NFT_IDENTIFIERS {
        return Err(CheckErrors::MaxIdentifierLengthExceeded(
            MAX_NFT_IDENTIFIERS,
            list_data.get_max_len(),
        )
        .into());
    }

    Ok(false)
}

/// Type check a `with-stacking` allowance expression.
/// `(with-stacking amount:uint)`
fn check_allowance_with_stacking(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> Result<bool, CheckError> {
    check_argument_count(1, args)?;

    checker.type_check_expects(
        args.first()
            .ok_or(CheckErrors::CheckerImplementationFailure)?,
        context,
        &TypeSignature::UIntType,
    )?;

    Ok(false)
}

/// Type check an `with-all-assets-unsafe` allowance expression.
/// `(with-all-assets-unsafe)`
fn check_allowance_all(
    _checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    _context: &TypingContext,
) -> Result<bool, CheckError> {
    check_argument_count(0, args)?;

    Ok(true)
}
