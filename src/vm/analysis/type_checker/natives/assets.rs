use super::{no_type, FunctionType, TypeChecker, TypeResult, TypingContext};
use vm::analysis::errors::{check_argument_count, CheckError, CheckErrors, CheckResult};
use vm::costs::cost_functions;
use vm::representations::SymbolicExpression;
use vm::types::{BlockInfoProperty, TupleTypeSignature, TypeSignature, MAX_VALUE_SIZE};

pub fn check_special_get_owner(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_argument_count(2, args)?;

    let asset_name = args[0].match_atom().ok_or(CheckErrors::BadTokenName)?;

    let expected_asset_type = checker
        .contract_context
        .get_nft_type(asset_name)
        .cloned()
        .ok_or_else(|| CheckErrors::NoSuchNFT(asset_name.to_string()))?;

    runtime_cost!(
        cost_functions::ANALYSIS_TYPE_LOOKUP,
        checker,
        expected_asset_type.type_size()?
    )?;

    checker.type_check_expects(&args[1], context, &expected_asset_type)?;

    Ok(TypeSignature::OptionalType(Box::new(TypeSignature::PrincipalType)).into())
}

pub fn check_special_get_balance(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_argument_count(2, args)?;

    let asset_name = args[0].match_atom().ok_or(CheckErrors::BadTokenName)?;

    if !checker.contract_context.ft_exists(asset_name) {
        return Err(CheckErrors::NoSuchFT(asset_name.to_string()).into());
    }

    runtime_cost!(cost_functions::ANALYSIS_TYPE_LOOKUP, checker, 1)?;

    let expected_owner_type: TypeSignature = TypeSignature::PrincipalType;
    checker.type_check_expects(&args[1], context, &expected_owner_type)?;

    Ok(TypeSignature::UIntType)
}

pub fn check_special_mint_asset(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_argument_count(3, args)?;

    let asset_name = args[0].match_atom().ok_or(CheckErrors::BadTokenName)?;

    let expected_owner_type: TypeSignature = TypeSignature::PrincipalType;
    let expected_asset_type = checker
        .contract_context
        .get_nft_type(asset_name)
        .ok_or(CheckErrors::NoSuchNFT(asset_name.to_string()))?
        .clone(); // this clone shouldn't be strictly necessary, but to use `type_check_expects` with this, it would have to be.

    runtime_cost!(
        cost_functions::ANALYSIS_TYPE_LOOKUP,
        checker,
        expected_asset_type.type_size()?
    )?;

    checker.type_check_expects(&args[1], context, &expected_asset_type)?;
    checker.type_check_expects(&args[2], context, &expected_owner_type)?;

    Ok(
        TypeSignature::ResponseType(Box::new((TypeSignature::BoolType, TypeSignature::UIntType)))
            .into(),
    )
}

pub fn check_special_mint_token(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_argument_count(3, args)?;

    let asset_name = args[0].match_atom().ok_or(CheckErrors::BadTokenName)?;

    let expected_amount: TypeSignature = TypeSignature::UIntType;
    let expected_owner_type: TypeSignature = TypeSignature::PrincipalType;

    runtime_cost!(cost_functions::ANALYSIS_TYPE_LOOKUP, checker, 1)?;

    checker.type_check_expects(&args[1], context, &expected_amount)?;
    checker.type_check_expects(&args[2], context, &expected_owner_type)?;

    if !checker.contract_context.ft_exists(asset_name) {
        return Err(CheckErrors::NoSuchFT(asset_name.to_string()).into());
    }

    Ok(
        TypeSignature::ResponseType(Box::new((TypeSignature::BoolType, TypeSignature::UIntType)))
            .into(),
    )
}

pub fn check_special_transfer_asset(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_argument_count(4, args)?;

    let token_name = args[0].match_atom().ok_or(CheckErrors::BadTokenName)?;

    let expected_owner_type: TypeSignature = TypeSignature::PrincipalType;
    let expected_asset_type = checker
        .contract_context
        .get_nft_type(token_name)
        .ok_or(CheckErrors::NoSuchNFT(token_name.to_string()))?
        .clone();

    runtime_cost!(
        cost_functions::ANALYSIS_TYPE_LOOKUP,
        checker,
        expected_asset_type.type_size()?
    )?;

    checker.type_check_expects(&args[1], context, &expected_asset_type)?;
    checker.type_check_expects(&args[2], context, &expected_owner_type)?; // owner
    checker.type_check_expects(&args[3], context, &expected_owner_type)?; // recipient

    Ok(
        TypeSignature::ResponseType(Box::new((TypeSignature::BoolType, TypeSignature::UIntType)))
            .into(),
    )
}

pub fn check_special_transfer_token(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_argument_count(4, args)?;

    let token_name = args[0].match_atom().ok_or(CheckErrors::BadTokenName)?;

    let expected_amount: TypeSignature = TypeSignature::UIntType;
    let expected_owner_type: TypeSignature = TypeSignature::PrincipalType;

    runtime_cost!(cost_functions::ANALYSIS_TYPE_LOOKUP, checker, 1)?;

    checker.type_check_expects(&args[1], context, &expected_amount)?;
    checker.type_check_expects(&args[2], context, &expected_owner_type)?; // owner
    checker.type_check_expects(&args[3], context, &expected_owner_type)?; // recipient

    if !checker.contract_context.ft_exists(token_name) {
        return Err(CheckErrors::NoSuchFT(token_name.to_string()).into());
    }

    Ok(
        TypeSignature::ResponseType(Box::new((TypeSignature::BoolType, TypeSignature::UIntType)))
            .into(),
    )
}
